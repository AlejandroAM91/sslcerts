package main

import (
	"log"
	"os"

	"github.com/AlejandroAM91/sslcerts/internal/pkg/sslcerts"
)

func main() {
	err := sslcerts.Cli().Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}
