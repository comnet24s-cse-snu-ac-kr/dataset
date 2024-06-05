BINARY := ztmb-conv-json
GO_FILES := $(wildcard src/*.go)
BUILD := build

VERSION=0.1.0
COMMIT=$(shell git rev-parse HEAD)
BRANCH=$(shell git rev-parse --abbrev-ref HEAD)
LDFLAGS = -ldflags "-X main.VERSION=${VERSION} -X main.COMMIT=${COMMIT} -X main.BRANCH=${BRANCH}"

all: build

build:
	go build ${LDFLAGS} -o ${BINARY} ${GO_FILES}

build-all: build-arm

build-arm:
	GOOS=darwin GOARCH=arm64 go build ${LDFLAGS} -o ${BUILD}/${BINARY}-darwin-arm64 ${GO_FILES}

run: build
	./$(BINARY)

clean:
	rm -f $(BINARY)*
	find pcaps/ -name '*.json' | xargs -n1 rm -f

fmt:
	go fmt ./...

deps:
	go mod tidy

test:
	go test ${GO_FILES} -v

conv: build
	find pcaps/ -name '*.pcap' | xargs -n1 ./$(BINARY)

.PHONY: all build run clean test fmt lint deps help
