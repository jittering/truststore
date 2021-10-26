package truststore

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp(os.TempDir(), "truststore-test-")
	if err != nil {
		panic(fmt.Errorf("failed to create temp dir: %v", err))
	}
	os.Setenv("CAROOT", dir)
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

	err := ml.MakeCert([]string{"foo.baz.com"})
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
