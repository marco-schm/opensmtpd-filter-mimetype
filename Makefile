BINARY_NAME=mimefilter
BUILD_DIR=bin

all: build

build:
	@echo "Building $(BINARY_NAME)..."
	mkdir -p $(BUILD_DIR)
	go build -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/mimefilter

clean:
	@echo "Cleaning..."
	rm -rf $(BUILD_DIR)

run:
	go run ./cmd/mimefilter

test:
	go test ./...

fmt:
	go fmt ./...

.PHONY: all build clean run fmt test