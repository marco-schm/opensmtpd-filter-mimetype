BINARY_NAME=mimefilter
BUILD_DIR=bin

all: build

build:
	@echo "Building $(BINARY_NAME)..."
	mkdir -p $(BUILD_DIR)
	go build -o $(BUILD_DIR)/$(BINARY_NAME) cmd/mimefilter/main.go

test:
	@echo "Running tests..."
	go test -v ./...

clean:
	@echo "Cleaning..."
	rm -rf $(BUILD_DIR)

run:
	go run cmd/mimefilter/main.go

fmt:
	go fmt ./...

.PHONY: all build clean run fmt test