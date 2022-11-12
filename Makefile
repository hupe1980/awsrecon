PROJECTNAME=$(shell basename "$(PWD)")

# Go related variables.
# Make is verbose in Linux. Make it silent.
MAKEFLAGS += --silent

.PHONY: setup
## setup: Setup installes dependencies
setup:
	go mod tidy -compat=1.19

.PHONY: test
## test: Runs go test with default values
test:
	go test -v -race -count=1  ./...

.PHONY: build
## build: Builds a beta version of gotoaws
build:
	go build -o dist/

.PHONY: ci
## ci: Run all the tests and code checks
ci: build test

.PHONY: download-iam
## download-iam: Download iam definitions
download-iam: 
	go run main.go download-iam -o pkg/iam/resource/iam-definition.json

.PHONY: run
## run: Runs awsrecon
run:
	go run -race main.go -h

.PHONY: help
## help: Prints this help message
help: Makefile
	@echo
	@echo " Choose a command run in "$(PROJECTNAME)":"
	@echo
	@sed -n 's/^##//p' $< | column -t -s ':' |  sed -e 's/^/ /'
	@echo