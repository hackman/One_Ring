# One Ring — whois  ·  build helpers
#
# Targets:
#   make           - same as `make build`
#   make build     - produce ./whoisd
#   make rebuild   - clean + build
#   make clean     - remove built artefacts (leaves runtime data untouched)
#   make test      - run the full Go test suite
#
# Override the version embedded into the binary:
#   make build VERSION=1.1
#
# This Makefile is entirely optional and not mandatory for the build and 
# development process.

BINARY  := whoisd
VERSION ?= 3.0
LDFLAGS := -ldflags "-X main.Version=$(VERSION)"
RELEASE_DIR := one-ring-${VERSION}
RELEASE_FILE := one-ring-${VERSION}.tgz

.PHONY: all build rebuild clean test

all: build

build:
	go build $(LDFLAGS) -o $(BINARY) .

rebuild: clean build

release: build
	mkdir -p releases
	mkdir ${RELEASE_DIR}
	cp whoisd config.yaml whoisd.service install.sh docs/whoisd.8 ${RELEASE_DIR}
	tar cfz releases/${RELEASE_FILE} ${RELEASE_DIR}


# Removes the compiled binary only. var/dbase (downloaded RIR cache) and
# var/stats (dumped JSON) are intentionally left alone — they are runtime
# data, not build output.
clean:
	rm -rf $(BINARY) one-ring-*

test:
	go test ./...
