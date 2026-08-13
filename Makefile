.PHONY: all build test clean run cross-build checksums

BINARY_NAME=mcpscan
DIST_DIR=dist

all: build test

build:
	go build -o $(BINARY_NAME) main.go

test:
	go test -v ./...

clean:
	go clean
	rm -rf $(BINARY_NAME) $(BINARY_NAME).exe $(DIST_DIR)

run: build
	./$(BINARY_NAME) --help

cross-build:
	mkdir -p $(DIST_DIR)
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s -w" -o $(DIST_DIR)/mcpscan-linux-amd64 main.go
	GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s -w" -o $(DIST_DIR)/mcpscan-darwin-amd64 main.go
	GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -ldflags="-s -w" -o $(DIST_DIR)/mcpscan-darwin-arm64 main.go
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s -w" -o $(DIST_DIR)/mcpscan-windows-amd64.exe main.go

checksums: cross-build
	go run scratch/gen_checksums.go
