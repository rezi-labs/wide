import 'docker.just'
import? 'private.just'
export DISABLE_HTTPS := "true"
export HTTP_PORT := "8080"
export HTTPS_PORT := "8443"

image_name := "ghcr.io/rezi-labs/wide"

docker: db
    docker compose up

it:
    cargo install cargo-watch --locked
    curl -sSfL https://get.tur.so/install.sh | bash

run: db
    cargo run

db:
    -(kill -9 $(lsof -t -i:8080))
    turso dev &

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

generate-session-secret:
    openssl rand -base64 64
