.PHONY: test bench lint all

test:
	go test -race -count=1 ./...

bench:
	go test -bench=. -benchmem -count=1 -run='^$$' ./cipherlock/...

lint:
	~/go/bin/golangci-lint run ./...

all: test lint bench
