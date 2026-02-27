.PHONY: run build release clean dev watch help

# Default target
help:
	@echo "IDS Lab Commander - Makefile"
	@echo ""
	@echo "Usage:"
	@echo "  make run      - Build and run in release mode"
	@echo "  make dev      - Build and run in debug mode"
	@echo "  make build    - Build debug binary"
	@echo "  make release  - Build release binary"
	@echo "  make clean    - Clean build artifacts"
	@echo "  make check    - Run cargo check"
	@echo ""
	@echo "Lab management:"
	@echo "  make snort    - Start Snort lab"
	@echo "  make suricata - Start Suricata lab"
	@echo "  make zeek     - Start Zeek lab"
	@echo "  make stop-all - Stop all labs"

# Build and run release
run: release
	@echo "Starting IDS Lab Commander..."
	./target/release/ids-commander

# Build and run debug
dev:
	cargo run

# Build debug
build:
	cargo build

# Build release
release:
	cargo build --release

# Clean
clean:
	cargo clean

# Check
check:
	cargo check

# Lab shortcuts
snort:
	cd ../snort-lab && docker compose up -d

suricata:
	cd ../suricata-lab && docker compose up -d

zeek:
	cd ../zeek-lab && docker compose up -d

stop-all:
	-cd ../snort-lab && docker compose down
	-cd ../suricata-lab && docker compose down
	-cd ../zeek-lab && docker compose down
