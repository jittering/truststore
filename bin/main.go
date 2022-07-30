package main

import (
	"github.com/jittering/truststore"
)

func main() {
	truststore.Print = true
	truststore.Main()
}
