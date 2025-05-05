VERSION := $(shell git describe --tags --always)
APP := relayproxy
MAIN_FILE := ./cmd/${APP}
.PHONY: all
all: build

.PHONY: v
v:
	@echo "${VERSION}"

.PHONY: build
build:
	GOOS=linux GOARCH=amd64 go build -ldflags "-X main._BuildVersion=${VERSION}"  -v -o ${APP} ${MAIN_FILE}

.PHONY: test
test:
	go test ./...

.PHONY: test-race
test-race:
	go test -race ./...

.PHONY: test-show-failed
test-show-failed:
	go test -timeout 300s ./... 2>&1

.PHONY: fmt
fmt:
	gofmt -s -w .

.PHONY: lint
lint:
	golangci-lint run --timeout=5m
