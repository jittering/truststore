package truststore

import (
	"errors"
	"fmt"
	"log"
	"net"
	"net/mail"
	"net/url"
	"regexp"

	"golang.org/x/net/idna"
)

var hostnameRegexp = regexp.MustCompile(`(?i)^(\*\.)?[0-9a-z_-]([0-9a-z._-]*[0-9a-z_-])?$`)

// Print controls whether or not log messages should be printed.
//
// As `mkcert` is originally a cli-based tool, there are verbose print
// statements littered throughout. For library usage, we want to silence them
// by default, but it may be useful to re-enable under some conditions.
var Print = false

type MkcertLib struct {
	m *mkcert
}

type Cert struct {
	CertFile string
	KeyFile  string
}

// GetCAROOT returns the computed CAROOT path. See `getCAROOT` for search order.
func GetCAROOT() string {
	return getCAROOT()
}

// NewLib initializes a new instance of MkcertLib. It will automatically
// initialize a new CA, as needed.
//
// Since output is silenced by default, in order to troubleshoot errors while
// creating a new CA or loading an existing one, it may be useful to run twice
// if an error is returned, like so:
//
// ml, err := truststore.NewLib()
// if err != nil {
// 	truststore.Print = true
// 	truststore.NewLib()
// 	// handle err...
// }
func NewLib() (mlib *MkcertLib, err error) {
	ml := &MkcertLib{
		m: &mkcert{
			CAROOT: GetCAROOT(),
		},
	}

	err = trap(func() {
		ml.m.loadCA()
	})
	if err != nil {
		return nil, err
	}

	return ml, nil
}

// CertFile generates the output filenames for the given host(s)
func (ml *MkcertLib) CertFile(hosts []string, targetOutputPath string) (cert Cert, err error) {
	err = validateHosts(hosts)
	if err != nil {
		return Cert{}, err
	}

	certFile, keyFile, _ := ml.m.fileNames(hosts, targetOutputPath)
	cert = Cert{certFile, keyFile}
	return cert, nil
}

// MakeCert with the given host names.
//
// All names must be valid hostnames or IP addresses. See `validateHosts`.
//
// *NOTE* A single cert will be created which is valid for all given hosts. To
//        create multiple files, call this method once per host.
func (ml *MkcertLib) MakeCert(hosts []string, targetOutputPath string) (cert Cert, err error) {
	cert, err = ml.CertFile(hosts, targetOutputPath)
	if err != nil {
		return
	}

	err = trap(func() {
		ml.m.makeCert(hosts, targetOutputPath)
	})
	if err != nil {
		return Cert{}, err
	}

	return
}

// validateHosts method extracted from cli program's `run` method.
func validateHosts(hosts []string) error {
	for i, name := range hosts {
		if ip := net.ParseIP(name); ip != nil {
			continue
		}
		if email, err := mail.ParseAddress(name); err == nil && email.Address == name {
			continue
		}
		if uriName, err := url.Parse(name); err == nil && uriName.Scheme != "" && uriName.Host != "" {
			continue
		}
		punycode, err := idna.ToASCII(name)
		if err != nil {
			return fmt.Errorf("ERROR: %q is not a valid hostname, IP, URL or email: %s", name, err)
		}
		hosts[i] = punycode
		if !hostnameRegexp.MatchString(punycode) {
			return fmt.Errorf("ERROR: %q is not a valid hostname, IP, URL or email", name)
		}
	}
	return nil
}

// trap panic raised by the given function.
//
// This ugly hack allows us to make the smallest change possible to the existing
// codebase. Rather than convert each method so that errors are bubbled up, this
// lets us get away with a smaller change and will make it easier to pull
// new changes in the future.
func trap(f func()) (err error) {
	defer func() {
		x := recover()
		if x != nil {
			if a, ok := x.(error); ok {
				err = a
			} else if a, ok := x.(string); ok {
				err = errors.New(a)
			} else {
				err = fmt.Errorf("caught panic: %v", x)
			}
		}
	}()
	f()
	return
}

// Simple stub for log.Fatalln which is used throughout the codebase. Instead of
// exiting, raise a panic which we can catch with `trap` above.
func logFatalln(v ...interface{}) {
	panic(errors.New(fmt.Sprintln(v...)))
}

func logPrint(v ...interface{}) {
	if Print {
		log.Print(v...)
	}
}

func logPrintf(format string, v ...interface{}) {
	if Print {
		log.Printf(format, v...)
	}
}

func logPrintln(v ...interface{}) {
	if Print {
		log.Println(v...)
	}

}
