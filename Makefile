.PHONY: all build test clean run

BINARY_NAME=mcpscan

all: build test

build:
	go build -o $(BINARY_NAME) main.go

test:
	go test -v ./...

clean:
	go clean
	rm -f $(BINARY_NAME) $(BINARY_NAME).exe

run: build
	./$(BINARY_NAME) --help
