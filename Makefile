.PHONY: build
build:
	go build -o bin/haveibeenpwned -v ./cmd/...

.PHONY: test
test:
	go test -tags debug -v ./pwned/...

.PHONY: tool
tool:
	go run -v ./cmd/...

.PHONY: clean
clean:
	rm -rf gopath bin
