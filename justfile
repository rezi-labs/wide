export DISABLE_HTTPS := "true"
export HTTP_PORT := "8080"
export HTTPS_PORT := "8443"


prod:
    wide

run:
    cargo run

watch:
    cargo watch -x run

verify: lint test

test:
    cargo test

lint:
    cargo fmt --all -- --check
    cargo clippy

fmt:
    cargo fmt
    cargo fix --allow-dirty --allow-staged

build:
    cargo build --release

install:
    cargo install --path .

