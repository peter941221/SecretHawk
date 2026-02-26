.PHONY: test build run fmt tidy

test:
	go test ./...

build:
	go build ./cmd/secrethawk

run:
	go run ./cmd/secrethawk --help

fmt:
	gofmt -w $$(rg --files -g "*.go")

tidy:
	go mod tidy
