BINARY := ztmb-conv-json
GO_FILES := $(wildcard src/*.go)
BUILD := build

VERSION=0.1.0
COMMIT=$(shell git rev-parse HEAD)
BRANCH=$(shell git rev-parse --abbrev-ref HEAD)
LDFLAGS = -ldflags "-X main.VERSION=${VERSION} -X main.COMMIT=${COMMIT} -X main.BRANCH=${BRANCH}"

all: build

build: build-darwin-arm

build-all: build-darwin-arm build-linux-amd

build-darwin-arm:
	GOOS=darwin GOARCH=arm64 go build ${LDFLAGS} -o ${BUILD}/${BINARY}-darwin-arm64 ${GO_FILES}

build-linux-amd:
	GOOS=darwin GOARCH=arm64 go build ${LDFLAGS} -o ${BUILD}/${BINARY}-darwin-arm64 ${GO_FILES}

run: build
	find pcaps -name '*.pcap' | xargs -n1 ./${BINARY}

tar:
	cd ./pcaps/ && tar --exclude *.pcap -czvf benign.tar.gz benign/
	cd ./pcaps/ && tar --exclude *.pcap -czvf dns2tcp.tar.gz dns2tcp/
	cd ./pcaps/ && tar --exclude *.pcap -czvf dnscapy.tar.gz dnscapy/
	cd ./pcaps/ && tar --exclude *.pcap -czvf iodine.tar.gz iodine/
	cd ./pcaps/ && tar --exclude *.pcap -czvf tuns.tar.gz tuns/
	mv pcaps/*.tar.gz build/

clean:
	find pcaps -name '*.json' | xargs -n1 rm -vrf

fmt:
	go fmt ./...

deps:
	go mod tidy

test:
	go test ${GO_FILES} -v

.PHONY: all build build-all build-darwin-arm build-linux-amd run clean fmt deps test
