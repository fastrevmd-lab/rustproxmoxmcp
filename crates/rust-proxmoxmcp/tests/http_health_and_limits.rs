//! MEC-449: `/healthz`, `/readyz`, and the default rate limit that comes
//! with mecmcp 0.24.1.
//!
//! `/healthz` and `/readyz` are mounted unconditionally by
//! `mecmcp-transport`'s router assembly -- this server wires in no readiness
//! checks of its own, so `/readyz` degrades to "200 when nothing is
//! configured to fail." Rate limiting is enforced by the same
//! `LimitsConfig::default()` this server already passes to
//! `build_http_router`; as of mecmcp 0.24.1 that default is no longer
//! unmetered.

mod common;

use reqwest::StatusCode;

/// `/healthz` reports the process is up, unauthenticated and with no bearer token.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn healthz_responds_ok_without_auth() {
    let h = common::TestServer::start(common::TokenSpec::full()).await;
    let client = reqwest::Client::new();
    let response = client
        .get(format!("{}/healthz", h.url))
        .header(reqwest::header::HOST, "localhost")
        .send()
        .await
        .expect("request");
    assert_eq!(response.status(), StatusCode::OK);
}

/// `/readyz` reports ready, unauthenticated, when no readiness checks are configured.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn readyz_responds_ok_without_auth() {
    let h = common::TestServer::start(common::TokenSpec::full()).await;
    let client = reqwest::Client::new();
    let response = client
        .get(format!("{}/readyz", h.url))
        .header(reqwest::header::HOST, "localhost")
        .send()
        .await
        .expect("request");
    assert_eq!(response.status(), StatusCode::OK);
}

/// mecmcp 0.24.1 makes `LimitsConfig::default()` rate-limit by default (50
/// requests/second and a burst of 100 per IP). This server passes
/// `LimitsConfig::default()` straight through, so a burst of requests from one
/// IP must eventually see 429 -- proving the limiter is live, not merely
/// configured and ignored. Before 0.24.1 the same flood ran fully unmetered.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_request_flood_from_one_ip_is_rate_limited() {
    let h = common::TestServer::start(common::TokenSpec::full()).await;
    let client = reqwest::Client::new();

    // The default burst is 100/ip, refilling at 50/s. Fire all 200 requests
    // concurrently rather than sequentially awaiting each one: on a loaded
    // CI runner, a sequential loop can take long enough between requests
    // that the bucket refills as fast as it drains, and the flood never
    // exceeds the burst.
    let mut handles = Vec::with_capacity(200);
    for _ in 0..200 {
        let client = client.clone();
        let url = format!("{}/healthz", h.url);
        handles.push(tokio::spawn(async move {
            client
                .get(url)
                .header(reqwest::header::HOST, "localhost")
                .send()
                .await
                .expect("request")
                .status()
        }));
    }

    let mut saw_too_many_requests = false;
    for handle in handles {
        if handle.await.expect("task") == StatusCode::TOO_MANY_REQUESTS {
            saw_too_many_requests = true;
        }
    }

    assert!(
        saw_too_many_requests,
        "a flood of 200 concurrent requests from one IP must be rate-limited (429); \
         LimitsConfig::default() is supposed to be metered as of mecmcp 0.24.1"
    );
}
