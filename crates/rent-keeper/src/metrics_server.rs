//! Tiny Axum server exposing the Prometheus text endpoint.

use std::net::SocketAddr;

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::get;
use axum::Router;

use crate::metrics::SharedMetrics;

/// Serves `GET /metrics` until the process shuts down.
///
/// # Errors
/// Errors when the listener cannot bind to the configured port.
pub async fn serve_metrics(port: u16, metrics: SharedMetrics) -> Result<(), std::io::Error> {
    let app = Router::new()
        .route("/metrics", get(render_metrics))
        .with_state(metrics);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, "metrics endpoint listening");
    axum::serve(listener, app).await
}

async fn render_metrics(
    State(metrics): State<SharedMetrics>,
) -> Result<(StatusCode, Vec<u8>), StatusCode> {
    match metrics.gather() {
        Ok(body) => Ok((
            StatusCode::OK,
            [b"content-type: text/plain; version=0.0.4".to_vec(), body].concat(),
        )),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metrics::Metrics;

    #[tokio::test]
    async fn metrics_endpoint_serves_text() {
        let metrics: SharedMetrics = std::sync::Arc::new(Metrics::new().expect("metrics"));
        metrics.poll_cycles.inc();
        // Bind port 0 to let the OS pick a free port.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");

        let app = Router::new()
            .route("/metrics", get(render_metrics))
            .with_state(metrics);
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve");
        });

        let mut stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        stream
            .write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .expect("write");
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.expect("read");
        let response = String::from_utf8_lossy(&buf);
        assert!(response.starts_with("HTTP/1.1 200 OK"));
        assert!(response.contains("rentkeeper_poll_cycles_total 1"));

        server.abort();
    }
}
