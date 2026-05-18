CARGO := cargo
TARGETS := x86_64-apple-darwin aarch64-apple-darwin x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu x86_64-pc-windows-msvc

.PHONY: all build test lint fmt e2e release-local clean

all: build test lint

build:
	$(CARGO) build --release

test:
	$(CARGO) test

lint:
	$(CARGO) clippy --all-targets --all-features -- -D warnings

fmt:
	$(CARGO) fmt

e2e:
	$(CARGO) test --test e2e_*

release-local:
	$(CARGO) build --release
	strip target/release/brokr
	@echo "Binary: target/release/brokr"

clean:
	$(CARGO) clean

cross-release:
	@for target in $(TARGETS); do \
		echo "Building for $$target..."; \
		$(CARGO) build --release --target $$target || true; \
	done
