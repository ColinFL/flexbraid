# FlexBraid build helpers.
BINARY   := flexbraid
VERSION  ?= 0.1.0-m4
LDFLAGS  := -s -w -X main.version=$(VERSION)

.PHONY: all build test vet fmt clean cross

all: build

build:
	go build -trimpath -ldflags '$(LDFLAGS)' -o $(BINARY) ./cmd/flexbraid

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -w .

clean:
	rm -f $(BINARY) $(BINARY).exe

# Cross-compile all target platforms.
cross:
	GOOS=linux   GOARCH=amd64 go build -trimpath -ldflags '$(LDFLAGS)' -o dist/flexbraid-linux-amd64   ./cmd/flexbraid
	GOOS=freebsd GOARCH=amd64 go build -trimpath -ldflags '$(LDFLAGS)' -o dist/flexbraid-freebsd-amd64 ./cmd/flexbraid
	GOOS=windows GOARCH=amd64 go build -trimpath -ldflags '$(LDFLAGS)' -o dist/flexbraid-windows-amd64.exe ./cmd/flexbraid
	@echo "cross-compiled into dist/"
