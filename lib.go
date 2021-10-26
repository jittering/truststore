package truststore

import (
	"errors"
	"fmt"
)

type MkcertLib struct {
	m *mkcert
}

// GetCAROOT returns the computed CAROOT path. See `getCAROOT` for search order.
func GetCAROOT() string {
	return getCAROOT()
}

// NewLib initializes a new instance of MkcertLib. It will automatically
// initialize a new CA, as needed.
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

// MakeCert for the given host names
//
// All names must be valid hostnames.
func (ml *MkcertLib) MakeCert(hosts []string) (err error) {
	return trap(func() {
		ml.m.makeCert(hosts)
	})
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
