package main

import (
	"github.com/hupe1980/awsrecon/cmd"
)

var (
	version = "dev"
)

func main() {
	cmd.Execute(version)
}
