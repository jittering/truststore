// Copyright 2018 The mkcert Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package truststore

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path"
	"path/filepath"
	"runtime"
	"strings"
)

var (
	hasNSS       bool
	hasCertutil  bool
	certutilPath string
	nssDBs       = []string{
		filepath.Join(os.Getenv("HOME"), ".pki/nssdb"),
		filepath.Join(os.Getenv("HOME"), "snap/chromium/current/.pki/nssdb"), // Snapcraft
		"/etc/pki/nssdb", // CentOS 7
	}
	firefoxPaths = []string{
		"/usr/bin/firefox",
		"/usr/bin/firefox-nightly",
		"/usr/bin/firefox-developer-edition",
		"/snap/firefox",
		"/Applications/Firefox.app",
		"/Applications/FirefoxDeveloperEdition.app",
		"/Applications/Firefox Developer Edition.app",
		"/Applications/Firefox Nightly.app",
		"C:\\Program Files\\Mozilla Firefox",
	}
)

func init() {
	allPaths := append(append([]string{}, nssDBs...), firefoxPaths...)
	for _, path := range allPaths {
		if pathExists(path) {
			hasNSS = true
			break
		}
	}

	switch runtime.GOOS {
	case "darwin":
		switch {
		case binaryExists("certutil"):
			certutilPath, _ = exec.LookPath("certutil")
			hasCertutil = true
		case binaryExists("/usr/local/opt/nss/bin/certutil"):
			// Check the default Homebrew path, to save executing Ruby. #135
			certutilPath = "/usr/local/opt/nss/bin/certutil"
			hasCertutil = true
		default:
			out, err := exec.Command("brew", "--prefix", "nss").Output()
			if err == nil {
				certutilPath = filepath.Join(strings.TrimSpace(string(out)), "bin", "certutil")
				hasCertutil = pathExists(certutilPath)
			}
		}

	case "linux":
		if hasCertutil = binaryExists("certutil"); hasCertutil {
			certutilPath, _ = exec.LookPath("certutil")
		}
	}
}

func (m *mkcert) checkNSS() bool {
	// bundled certutil/nss support
	err := setupCertutil()
	if err != nil {
		logFatalln(err)
	}
	if !hasCertutil {
		return false
	}
	success := true
	if m.forEachNSSProfile(func(profile string) {
		err := exec.Command(certutilPath, "-V", "-d", profile, "-u", "L", "-n", m.caUniqueName()).Run()
		if err != nil {
			success = false
		}
	}) == 0 {
		success = false
	}
	return success
}

func (m *mkcert) installNSS() bool {
	if m.forEachNSSProfile(func(profile string) {
		cmd := exec.Command(certutilPath, "-A", "-d", profile, "-t", "C,,", "-n", m.caUniqueName(), "-i", filepath.Join(m.CAROOT, rootName))
		out, err := execCertutil(cmd)
		fatalIfCmdErr(err, "certutil -A -d "+profile, out)
	}) == 0 {
		logPrintf("ERROR: no %s security databases found", NSSBrowsers)
		return false
	}
	if !m.checkNSS() {
		logPrintf("Installing in %s failed. Please report the issue with details about your environment at https://github.com/FiloSottile/mkcert/issues/new 👎", NSSBrowsers)
		logPrintf("Note that if you never started %s, you need to do that at least once.", NSSBrowsers)
		return false
	}
	return true
}

func (m *mkcert) uninstallNSS() {
	m.forEachNSSProfile(func(profile string) {
		err := exec.Command(certutilPath, "-V", "-d", profile, "-u", "L", "-n", m.caUniqueName()).Run()
		if err != nil {
			return
		}
		cmd := exec.Command(certutilPath, "-D", "-d", profile, "-n", m.caUniqueName())
		out, err := execCertutil(cmd)
		fatalIfCmdErr(err, "certutil -D -d "+profile, out)
	})
}

// execCertutil will execute a "certutil" command and if needed re-execute
// the command with commandWithSudo to work around file permissions.
func execCertutil(cmd *exec.Cmd) ([]byte, error) {
	out, err := cmd.CombinedOutput()
	if err != nil && bytes.Contains(out, []byte("SEC_ERROR_READ_ONLY")) && runtime.GOOS != "windows" {
		origArgs := cmd.Args[1:]
		cmd = commandWithSudo(cmd.Path)
		cmd.Args = append(cmd.Args, origArgs...)
		out, err = cmd.CombinedOutput()
	}
	return out, err
}

func (m *mkcert) forEachNSSProfile(f func(profile string)) (found int) {
	var profiles []string
	profiles = append(profiles, nssDBs...)
	for _, ff := range FirefoxProfiles {
		pp, _ := filepath.Glob(ff)
		profiles = append(profiles, pp...)
	}
	for _, profile := range profiles {
		if stat, err := os.Stat(profile); err != nil || !stat.IsDir() {
			continue
		}
		if pathExists(filepath.Join(profile, "cert9.db")) {
			f("sql:" + profile)
			found++
		} else if pathExists(filepath.Join(profile, "cert8.db")) {
			f("dbm:" + profile)
			found++
		}
	}
	return
}

func setupCertutil() error {
	certutilDir = path.Join(os.TempDir(), "truststore-certutil")
	err := os.MkdirAll(certutilDir, 0755)
	if err != nil {
		return fmt.Errorf("error setting up certutil: %s", err)
	}
	for _, filename := range certutilFiles {
		// gunzip file and write to temp dir
		f, err := embedded.Open(filename)
		if err != nil {
			return fmt.Errorf("error setting up certutil: %s", err)
		}
		defer f.Close()
		gr, err := gzip.NewReader(f)
		if err != nil {
			return fmt.Errorf("error setting up certutil: %s", err)
		}
		defer gr.Close()
		out, err := os.OpenFile(path.Join(certutilDir, strings.TrimSuffix(path.Base(filename), ".gz")), os.O_CREATE|os.O_RDWR, 0755)
		if err != nil {
			return fmt.Errorf("error: failed to open file for writing: %s", err)
		}
		defer out.Close()
		_, err = io.Copy(out, gr)
		if err != nil {
			return fmt.Errorf("error: failed to write certutil binary: %s", err)
		}
	}

	// cleanup temp dir if interrupted
	stop := make(chan os.Signal)
	signal.Notify(stop, os.Interrupt)
	go func() {
		<-stop
		err = os.RemoveAll(certutilDir)
		if err != nil {
			fmt.Printf("failed to remove bundled certutil at %s: %s", certutilDir, err.Error())
		}
	}()

	// set flags so nss sees it
	certutilPath = path.Join(certutilDir, "certutil")
	hasCertutil = true

	return nil
}

func cleanupCertutil() error {
	if certutilDir == "" {
		return nil
	}
	err := os.RemoveAll(certutilDir)
	if err != nil {
		return fmt.Errorf("failed to remove bundled certutil at %s: %s", certutilDir, err.Error())
	}
	return nil

}
