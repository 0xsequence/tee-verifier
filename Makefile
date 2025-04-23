APP_NAME := tee-verifier
PREFIX ?= /usr/local
BINDIR := $(PREFIX)/bin
OUTDIR := $(shell pwd)/bin
CMDDIR := $(shell pwd)/cmd/tee-verifier
VERSION := $(shell git describe --tags --always --dirty)
COMMIT := $(shell git rev-parse --short HEAD)
BUILD_DATE := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

$(OUTDIR)/$(APP_NAME): $(shell find . -name '*.go')
	@if [ "$(shell id -u)" = "0" ]; then \
		echo "❌ Building with sudo is not allowed"; \
		exit 1; \
	fi
	@echo "🔨 Building $(APP_NAME)..."
	@mkdir -p $(OUTDIR)
	@go build \
		-o $(OUTDIR)/$(APP_NAME) \
		-ldflags "-X 'main.Version=$(VERSION)' -X 'main.Commit=$(COMMIT)' -X 'main.BuildDate=$(BUILD_DATE)'" \
		$(CMDDIR)
	@echo "✅ Built $(APP_NAME) in $(OUTDIR)"

.PHONY: install
install: $(OUTDIR)/$(APP_NAME)
	@echo "📦 Installing $(APP_NAME) to $(BINDIR)..."
	@mkdir -p $(BINDIR)
	@cp $(OUTDIR)/$(APP_NAME) $(BINDIR)/
	@chmod +x $(BINDIR)/$(APP_NAME)
	@echo "✅ Installed $(APP_NAME) to $(BINDIR)"

.PHONY: clean
clean:
	@echo "🧹 Cleaning up..."
	@rm -rf $(OUTDIR)
	@echo "✅ Cleaned up"

