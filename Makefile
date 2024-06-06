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
	find pcaps -name '*.pcap' | xargs -n1 ./${BINARY}

clean:
	rm -vrf ${BINARY}* dataset
	find pcaps -name '*.json' | xargs -n1 rm -vrf

fmt:
	go fmt ./...

deps:
	go mod tidy

test:
	go test ${GO_FILES} -v

ztmb: run
	mkdir -pv ${BUILD}
	mkdir -pv dataset
	mkdir -pv dataset/benign
	mkdir -pv dataset/dns2tcp
	mkdir -pv dataset/dnscapy
	mkdir -pv dataset/iodine
	mkdir -pv dataset/tuns
	for json in $$(find pcaps -name '*.json'); do \
		tool=$$(echo $${json} | rev | cut -d '/' -f2 | rev); \
		name=$$(echo $${json} | rev | cut -d '/' -f1 | rev); \
		if `ztmb $${json} &> ./log.txt`; then \
			mv result.json dataset/$${tool}/$${name}; \
			mv log.txt dataset/$${tool}/$${name}.log; \
			echo "Done: $${name}"; \
		else \
			mv log.txt dataset/$tool/$name.error.log; \
			echo "Error: $${name}"; \
		fi; \
	done
	tar -czvf ${BUILD}/dataset.tar.gz dataset

.PHONY: all build run clean test fmt lint deps help
