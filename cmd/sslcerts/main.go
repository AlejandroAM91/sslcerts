package main

import (
	"log"
	"os"

	"github.com/AlejandroAM91/sslcerts/internal/app/sslcerts"
)

func main() {
	err := sslcerts.Cli().Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}
