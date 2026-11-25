// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0
//! Cost of the HTTP middleware, tracing and OpenTelemetry span per request.
//!
//! Every case sends one request through a router whose only route answers a
//! small JSON body, so the numbers are the overhead around a handler that
//! does nothing. The stack is the production one
//! ([`apply_middleware`], [`attach_http_metrics`]); the subscriber decides what
//! the `tracing` calls inside it cost:
//!
//! - `none`: no subscriber (callsites are disabled);
//! - `info`: a formatting layer writing to a sink, filtered like the log sinks
//!   (INFO, `tower_http` pinned to INFO) – the default deployment;
//! - `info+otel`: the same plus a layer that accepts the `http.server` span
//!   and records its fields, as the OpenTelemetry layer does without the
//!   exporter's network cost.
//!
//! Run with `cargo bench -p openstack-keystone --bench middleware`.

// A bench target is not test code for `allow-expect-in-tests`, and a failed
// setup must stop the run.
#![allow(clippy::expect_used)]

use std::io;
use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::routing::get;
use cadf::AuditDispatcher;
use criterion::{Criterion, criterion_group, criterion_main};
use sea_orm::DatabaseConnection;
use tower::ServiceExt as _;
use tracing::span::{Attributes, Id, Record};
use tracing::{Dispatch, Subscriber};
use tracing_subscriber::filter::{LevelFilter, Targets};
use tracing_subscriber::layer::{Context, SubscriberExt as _};
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::{Layer, Registry};

use openstack_keystone::config::{Config, ConfigManager};
use openstack_keystone::server::request_span::{RequestSpanOptions, SERVER_SPAN_TARGET};
use openstack_keystone::server::startup::router::{apply_middleware, attach_http_metrics};
use openstack_keystone_core::keystone::{Service, ServiceState};
use openstack_keystone_core::policy::MockPolicy;
use openstack_keystone_core::provider::Provider;

const BODY: &str = r#"{"project":{"id":"p","name":"n","domain_id":"d","enabled":true}}"#;

async fn ok() -> (StatusCode, [(&'static str, &'static str); 1], &'static str) {
    (StatusCode::OK, [("content-type", "application/json")], BODY)
}

async fn bad() -> (StatusCode, &'static str) {
    (StatusCode::BAD_REQUEST, r#"{"error":{"message":"bad"}}"#)
}

fn routes() -> Router {
    Router::new()
        .route("/v3/projects/{id}", get(ok))
        .route("/v3/bad", get(bad))
}

async fn state() -> ServiceState {
    Arc::new(
        Service::new(
            ConfigManager::not_watched(Config::default()),
            DatabaseConnection::default(),
            Provider::mocked_builder().build().expect("mock provider"),
            Arc::new(MockPolicy::default()),
            AuditDispatcher::noop(),
            None,
        )
        .await
        .expect("mock state"),
    )
}

/// Stands in for the OpenTelemetry layer: it takes the `http.server` span and
/// every value recorded into it (the work the SDK layer does per field), and
/// drops them.
struct SpanSink;

impl<S: Subscriber + for<'a> LookupSpan<'a>> Layer<S> for SpanSink {
    fn on_new_span(&self, attrs: &Attributes<'_>, _id: &Id, _ctx: Context<'_, S>) {
        if attrs.metadata().target() == SERVER_SPAN_TARGET {
            let mut sink = Discard;
            attrs.record(&mut sink);
        }
    }

    fn on_record(&self, _id: &Id, values: &Record<'_>, _ctx: Context<'_, S>) {
        let mut sink = Discard;
        values.record(&mut sink);
    }
}

struct Discard;

impl tracing::field::Visit for Discard {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        std::hint::black_box((field.name(), value));
    }
}

struct Sink;

impl io::Write for Sink {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn log_filter() -> Targets {
    Targets::new()
        .with_default(LevelFilter::INFO)
        .with_target("tower_http", LevelFilter::INFO)
        .with_target(SERVER_SPAN_TARGET, LevelFilter::OFF)
}

fn dispatch(name: &str) -> Dispatch {
    let fmt = || {
        tracing_subscriber::fmt::layer()
            .with_ansi(false)
            .with_writer(|| Sink)
            .with_filter(log_filter())
    };
    match name {
        "none" => Dispatch::new(tracing::subscriber::NoSubscriber::default()),
        "info" => Dispatch::new(Registry::default().with(fmt()).with(LevelFilter::INFO)),
        "info+otel" => Dispatch::new(
            Registry::default()
                .with(fmt())
                .with(
                    SpanSink.with_filter(
                        Targets::new()
                            .with_default(LevelFilter::INFO)
                            .with_target("tower_http", LevelFilter::OFF),
                    ),
                )
                .with(LevelFilter::INFO),
        ),
        other => panic!("unknown subscriber {other}"),
    }
}

fn request(uri: &str) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .header("user-agent", "python-keystoneclient/5.0")
        .header("x-auth-token", "gAAAAAB-token-that-must-not-leak")
        .body(Body::empty())
        .expect("request")
}

async fn send(app: &Router, uri: &str, status: StatusCode) {
    let response = app.clone().oneshot(request(uri)).await.expect("response");
    assert_eq!(response.status(), status);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    std::hint::black_box(body);
}

fn bench(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let state = rt.block_on(state());

    let options = |user_ids| {
        Some(Arc::new(RequestSpanOptions {
            include_user_ids: user_ids,
            ..Default::default()
        }))
    };
    // name, span options (None: no `http.server` span), with http metrics
    let stacks: Vec<(&str, Router)> = vec![
        ("bare", routes()),
        ("stack", apply_middleware(routes(), &state, None)),
        (
            "stack+span",
            apply_middleware(routes(), &state, options(false)),
        ),
        (
            "stack+span+ids",
            apply_middleware(routes(), &state, options(true)),
        ),
        (
            "stack+span+metrics",
            rt.block_on(attach_http_metrics(
                apply_middleware(routes(), &state, options(false)),
                &state,
            ))
            .0,
        ),
    ];

    for subscriber in ["none", "info", "info+otel"] {
        let dispatch = dispatch(subscriber);
        let mut group = c.benchmark_group(format!("middleware/{subscriber}"));
        for (name, app) in &stacks {
            // A span can only be exported when a layer consumes it: the
            // `+span` stacks are measured under every subscriber so the cost
            // of the span alone (`none`) and with a consumer is visible.
            group.bench_function(format!("ok/{name}"), |b| {
                let _guard = tracing::dispatcher::set_default(&dispatch);
                b.to_async(&rt)
                    .iter(|| send(app, "/v3/projects/6fa1d8c0", StatusCode::OK));
            });
            group.bench_function(format!("error/{name}"), |b| {
                let _guard = tracing::dispatcher::set_default(&dispatch);
                b.to_async(&rt)
                    .iter(|| send(app, "/v3/bad", StatusCode::BAD_REQUEST));
            });
        }
        group.finish();
    }
}

/// Each middleware of the stack alone, on top of the bare router, under the
/// `info` subscriber: what every layer costs and which ones to tune.
fn bench_layers(c: &mut Criterion) {
    use axum::middleware::{from_fn, from_fn_with_state};
    use openstack_keystone::audit::with_audit_request_context;
    use openstack_keystone::server::access_log::log_request;
    use openstack_keystone::server::error_log::log_error_body;
    use openstack_keystone::server::http_metrics::{HttpMetrics, record_http_metrics};
    use openstack_keystone::server::request_cache::with_request_cache;
    use openstack_keystone::server::request_span::server_span;
    use tower_http::request_id::SetRequestIdLayer;
    use tower_http::trace::{DefaultOnRequest, TraceLayer};

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let state = rt.block_on(state());
    let metrics = Arc::new(HttpMetrics::new(
        &openstack_keystone_telemetry::metrics::meter(),
    ));
    let header = axum::http::HeaderName::from_static("x-openstack-request-id");

    let layers: Vec<(&str, Router)> = vec![
        ("none", routes()),
        (
            "set_request_id",
            routes().layer(SetRequestIdLayer::new(
                header,
                openstack_keystone::server::startup::router::OpenStackRequestId::default(),
            )),
        ),
        ("request_cache", routes().layer(from_fn(with_request_cache))),
        (
            "audit_context",
            routes().layer(from_fn_with_state(
                state.clone(),
                with_audit_request_context,
            )),
        ),
        (
            "trace_layer",
            routes().layer(
                TraceLayer::new(openstack_keystone::common::KeystoneResponseClassifier)
                    .make_span_with(|r: &Request<_>| {
                        tracing::info_span!(
                            "request",
                            method = ?r.method(),
                            client.addr = ?Option::<std::net::SocketAddr>::None,
                            uri = ?r.uri().path(),
                            x_request_id = ?r.headers().get("x-openstack-request-id")
                        )
                    })
                    .on_request(DefaultOnRequest::new().level(tracing::Level::DEBUG))
                    .on_response(()),
            ),
        ),
        ("access_log", routes().layer(from_fn(log_request))),
        ("error_log", routes().layer(from_fn(log_error_body))),
        (
            "http_metrics",
            routes()
                .layer(from_fn(record_http_metrics))
                .layer(axum::Extension(metrics)),
        ),
        (
            "server_span",
            routes().layer(from_fn_with_state(
                Arc::new(RequestSpanOptions::default()),
                server_span,
            )),
        ),
    ];

    let dispatch = dispatch("info+otel");
    let mut group = c.benchmark_group("layers");
    for (name, app) in &layers {
        group.bench_function(format!("ok/{name}"), |b| {
            let _guard = tracing::dispatcher::set_default(&dispatch);
            b.to_async(&rt)
                .iter(|| send(app, "/v3/projects/6fa1d8c0", StatusCode::OK));
        });
        group.bench_function(format!("error/{name}"), |b| {
            let _guard = tracing::dispatcher::set_default(&dispatch);
            b.to_async(&rt)
                .iter(|| send(app, "/v3/bad", StatusCode::BAD_REQUEST));
        });
    }
    group.finish();
}

criterion_group!(benches, bench, bench_layers);
criterion_main!(benches);
