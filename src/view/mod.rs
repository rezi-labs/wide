use axum::{Router, response::Html, routing::get};
use maud::{DOCTYPE, html};

use crate::config::ProxyConfig;

pub fn create_view_router(config: ProxyConfig) -> Router {
    Router::new().route("/view", get(move || view_config(config.clone())))
}

async fn view_config(config: ProxyConfig) -> Html<String> {
    let markup = html! {
        (DOCTYPE)
        html {
            head {
                title { "WIDE Proxy Configuration" }
                meta charset="utf-8";
                meta name="viewport" content="width=device-width, initial-scale=1";
                style {
                    r#"
                    body {
                        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
                        max-width: 1200px;
                        margin: 0 auto;
                        padding: 20px;
                        background-color: #f5f5f5;
                        color: #333;
                    }
                    .container {
                        background: white;
                        border-radius: 8px;
                        padding: 30px;
                        box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                    }
                    h1 {
                        color: #2c3e50;
                        border-bottom: 3px solid #3498db;
                        padding-bottom: 10px;
                        margin-bottom: 30px;
                    }
                    h2 {
                        color: #34495e;
                        margin-top: 30px;
                        margin-bottom: 15px;
                        border-left: 4px solid #3498db;
                        padding-left: 15px;
                    }
                    .config-section {
                        margin-bottom: 25px;
                        background: #f8f9fa;
                        padding: 20px;
                        border-radius: 6px;
                        border: 1px solid #dee2e6;
                    }
                    .route-item {
                        display: flex;
                        justify-content: space-between;
                        align-items: center;
                        padding: 12px 0;
                        border-bottom: 1px solid #eee;
                    }
                    .route-item:last-child {
                        border-bottom: none;
                    }
                    .domain {
                        font-weight: 600;
                        color: #2980b9;
                        font-size: 16px;
                    }
                    .backend {
                        color: #27ae60;
                        font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
                        background: #e8f5e8;
                        padding: 4px 8px;
                        border-radius: 4px;
                        font-size: 14px;
                    }
                    .config-item {
                        display: flex;
                        justify-content: space-between;
                        padding: 8px 0;
                        border-bottom: 1px solid #eee;
                    }
                    .config-item:last-child {
                        border-bottom: none;
                    }
                    .config-label {
                        font-weight: 600;
                        color: #555;
                    }
                    .config-value {
                        color: #333;
                        font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
                        background: #f1f1f1;
                        padding: 2px 6px;
                        border-radius: 3px;
                    }
                    .status-indicator {
                        display: inline-block;
                        width: 10px;
                        height: 10px;
                        border-radius: 50%;
                        margin-right: 8px;
                    }
                    .status-active {
                        background-color: #27ae60;
                    }
                    .status-staging {
                        background-color: #f39c12;
                    }
                    .footer {
                        margin-top: 40px;
                        text-align: center;
                        color: #7f8c8d;
                        font-size: 14px;
                        border-top: 1px solid #bdc3c7;
                        padding-top: 20px;
                    }
                    "#
                }
            }
            body {
                div class="container" {
                    h1 { "🔀 WIDE Proxy Configuration" }

                    div class="config-section" {
                        h2 { "📍 Route Mappings" }
                        @if config.routes.is_empty() {
                            p { "No routes configured" }
                        } @else {
                            @for (domain, backend) in &config.routes {
                                div class="route-item" {
                                    span class="domain" { (domain) }
                                    span class="backend" { (backend) }
                                }
                            }
                        }
                    }

                    div class="config-section" {
                        h2 { "🔒 ACME Configuration" }
                        div class="config-item" {
                            span class="config-label" { "Email:" }
                            span class="config-value" { (config.acme.email) }
                        }
                        div class="config-item" {
                            span class="config-label" { "Certificate Directory:" }
                            span class="config-value" { (config.acme.cert_dir) }
                        }
                        div class="config-item" {
                            span class="config-label" { "Environment:" }
                            span class="config-value" {
                                @if config.acme.staging {
                                    span class="status-indicator status-staging" {}
                                    "Staging"
                                } @else {
                                    span class="status-indicator status-active" {}
                                    "Production"
                                }
                            }
                        }
                    }

                    div class="config-section" {
                        h2 { "⚙️ Server Configuration" }
                        div class="config-item" {
                            span class="config-label" { "HTTP Port:" }
                            span class="config-value" { (config.server.http_port) }
                        }
                        div class="config-item" {
                            span class="config-label" { "HTTPS Port:" }
                            span class="config-value" { (config.server.https_port) }
                        }
                    }

                    div class="footer" {
                        p { "WIDE Reverse Proxy • Configuration loaded from proxy.toml" }
                    }
                }
            }
        }
    };

    Html(markup.into_string())
}
