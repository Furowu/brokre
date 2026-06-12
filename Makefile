CARGO := cargo

.PHONY: all build test lint fmt e2e release-local clean

all: build test lint

build:
	$(CARGO) build --release

test:
	$(CARGO) test --lib

lint:
	$(CARGO) clippy --lib --all-features -- -D warnings

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
