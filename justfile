export DISABLE_HTTPS := "true"
export HTTP_PORT := "8080"
export HTTPS_PORT := "8443"

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

# Docker recipes
docker_build:
    docker build -t wide .

docker_prod:
    docker run -p 80:80 -p 443:443 -v $(pwd)/proxy.toml:/app/proxy.toml -v $(pwd)/certs:/app/certs wide

docker_run: docker_build
    docker run -p 8080:80 -p 8443:443 -e DISABLE_HTTPS=true -e HTTP_PORT=80 -e HTTPS_PORT=443 -v $(pwd)/proxy.toml:/app/proxy.toml -v $(pwd)/certs:/app/certs wide

# Build and run Docker container
docker: docker_build docker_run
