package truststore

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var tempDir string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp(os.TempDir(), "truststore-test-")
	if err != nil {
		panic(fmt.Errorf("failed to create temp dir: %v", err))
	}
	os.Setenv("CAROOT", dir)
	tempDir = dir + string(filepath.Separator)
	ret := m.Run()

	err = os.RemoveAll(dir)
	if err != nil {
		fmt.Printf("ERROR: failed to cleanup temp dir '%s': %v\n", dir, err)
	}
	os.Exit(ret)
}

func TestCARootPath(t *testing.T) {
	if got := GetCAROOT(); got == "" {
		t.Errorf("GetCAROOT() = %v, expected non-empty string", got)
	}
}

func TestNew(t *testing.T) {
	m, err := NewLib()
	if err != nil {
		t.Errorf("got unexpected error: %v", err)
	}
	if m == nil {
		t.Errorf("m was nil")
	}
}

func TestMakeCertDontPanic(t *testing.T) {
	ml := MkcertLib{m: &mkcert{}}

	_, err := ml.MakeCert([]string{"foo.baz.com"}, tempDir)
	t.Logf("got error: %v\n", err)
	if err == nil {
		t.Errorf("expected an error, got nil")
		t.FailNow()
	}

	if !strings.Contains(err.Error(), "can't create new certificates") {
		t.Errorf("got unexpected error: %v", err)
		t.FailNow()
	}
}

func TestMakeCert(t *testing.T) {
	ml, _ := NewLib()

	cert, err := ml.MakeCert([]string{"foo.baz.com"}, tempDir)
	t.Logf("got error: %v\n", err)
	if err != nil {
		t.Errorf("got unexpected error: %v", err)
		t.FailNow()
	}

	// ensure files were generated and the output is as expected
	files := []string{
		filepath.Join(tempDir, "foo.baz.com.pem"),
		filepath.Join(tempDir, "foo.baz.com-key.pem"),
		cert.CertFile,
		cert.KeyFile,
	}

	if files[0] != cert.CertFile {
		t.Errorf("CertFile path = %v, wanted %v", cert.CertFile, files[0])
	}

	for _, f := range files {
		_, err = os.Stat(f)
		if err != nil {
			t.Errorf("got unexpected error: %v", err)
		}
	}

}

// don't really have a good test case of an invalid string here
func Test_validateHosts(t *testing.T) {
	type args struct {
		hosts []string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{"valid", args{[]string{"foobar", "foo.local.com"}}, false},
		{"valid ip", args{[]string{"1.1.1.1"}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := validateHosts(tt.args.hosts); (err != nil) != tt.wantErr {
				t.Logf("hosts: %#v", tt.args.hosts)
				t.Errorf("validateHosts() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
