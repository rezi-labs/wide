use axum::{
    Router,
    body::Body,
    extract::Request,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use std::collections::HashMap;
use std::net::SocketAddr;
use tower::ServiceExt;

use http_body_util::BodyExt;
use serde::Deserialize;
use std::fs;

#[derive(Deserialize, Clone)]
struct Config {
    routes: HashMap<String, BackendConfig>,
}

#[derive(Deserialize, Clone)]
struct BackendConfig {
    backend: String,
    #[serde(default)]
    https: bool,
}

fn load_config() -> Config {
    let config_str = fs::read_to_string("proxy.yaml").expect("Failed to read config file");
    serde_yaml::from_str(&config_str).expect("Failed to parse config")
}

#[derive(Clone)]
struct ProxyConfig {
    routes: HashMap<String, String>,
}

impl From<Config> for ProxyConfig {
    fn from(value: Config) -> ProxyConfig {
        let routes = value
            .routes
            .into_iter()
            .map(|(domain, backend_config)| {
                let protocol = if backend_config.https {
                    "https"
                } else {
                    "http"
                };
                let backend_url = format!("{}://{}", protocol, backend_config.backend);
                (domain, backend_url)
            })
            .collect();

        ProxyConfig { routes }
    }
}

#[tokio::main]
async fn main() {
    // Load configuration from YAML file
    let yaml_config = load_config();
    let config = ProxyConfig::from(yaml_config);

    let app = Router::new().fallback(move |req: Request| proxy_handler(req, config.clone()));

    let addr = SocketAddr::from(([0, 0, 0, 0], 80));
    println!("Reverse proxy listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn proxy_handler(req: Request, config: ProxyConfig) -> Response {
    // Extract host from headers
    let host = match req.headers().get("host") {
        Some(host_header) => match host_header.to_str() {
            Ok(host_str) => host_str,
            Err(_) => {
                eprintln!("Invalid host header");
                return (StatusCode::BAD_REQUEST, "Invalid host header").into_response();
            }
        },
        None => {
            eprintln!("No host header found");
            return (StatusCode::BAD_REQUEST, "No host header").into_response();
        }
    };

    // Strip port from host if present
    let host = host.split(':').next().unwrap_or(host);

    // Find backend for this domain
    let backend = match config.routes.get(host) {
        Some(b) => b,
        None => {
            eprintln!("No backend configured for host: {}", host);
            return (StatusCode::NOT_FOUND, "Host not found").into_response();
        }
    };

    // Build the proxy service
    let service = match axum_proxy::builder_http(backend.clone()) {
        Ok(builder) => builder.build(axum_proxy::Static("/")),
        Err(e) => {
            eprintln!("Failed to build proxy for {}: {}", backend, e);
            return (StatusCode::BAD_GATEWAY, "Backend unavailable").into_response();
        }
    };

    // Forward the request
    match service.oneshot(req).await {
        Ok(Ok(response)) => {
            // Convert the response to use Axum's Body type
            let (parts, body) = response.into_parts();
            let stream = body.into_data_stream();
            Response::from_parts(parts, Body::from_stream(stream))
        }
        Ok(Err(e)) => {
            eprintln!("Proxy error: {:?}", e);
            (StatusCode::BAD_GATEWAY, "Backend error").into_response()
        }
        Err(e) => {
            eprintln!("Service error: {:?}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Internal error").into_response()
        }
    }
}
