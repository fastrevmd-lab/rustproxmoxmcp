//! MEC-449: `/healthz`, `/readyz`, and the default rate limit that comes
//! with mecmcp 0.24.1.
//!
//! `/healthz` and `/readyz` are mounted unconditionally by
//! `mecmcp-transport`'s router assembly. MEC-983 wires in a single
//! fleet-wide readiness check covering every configured Proxmox cluster
//! (`readiness::spawn_cluster_readiness`), backed by a background poller per
//! cluster rather than a synchronous call from inside the `/readyz` handler
//! itself -- so these tests poll for the result to converge instead of
//! asserting on the first response. Rate limiting is enforced by the same
//! `LimitsConfig::default()`
//! this server already passes to `build_http_router`; as of mecmcp 0.24.1
//! that default is no longer unmetered.

mod common;

use reqwest::StatusCode;
use std::time::Duration;

/// Poll `{base_url}/readyz` until it reports `expected`, or give up at the
/// deadline and return whatever the last response was.
///
/// The cluster-reachability poller runs in the background on its own
/// interval, so a test cannot assume the first `/readyz` response already
/// reflects a poll that has run.
async fn wait_for_readyz_status(
    client: &reqwest::Client,
    base_url: &str,
    expected: StatusCode,
) -> StatusCode {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let status = client
            .get(format!("{base_url}/readyz"))
            .header(reqwest::header::HOST, "localhost")
            .send()
            .await
            .expect("request")
            .status();
        if status == expected || tokio::time::Instant::now() >= deadline {
            return status;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

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

/// `/readyz` reports ready, unauthenticated, when every configured cluster
/// answers its reachability probe -- the default test fixture's mock Proxmox
/// serves `/api2/json/nodes`, the probe path.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn readyz_responds_ok_without_auth() {
    let h = common::TestServer::start(common::TokenSpec::full()).await;
    let client = reqwest::Client::new();
    let status = wait_for_readyz_status(&client, &h.url, StatusCode::OK).await;
    assert_eq!(status, StatusCode::OK);
}

/// MEC-983: a configured cluster whose API does not answer the reachability
/// probe must flip `/readyz` to 503, rather than reporting ready because no
/// check happens to be wired in. The failing cluster's name must not appear
/// in the unauthenticated response body -- only in the server-side log.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn readyz_reports_unready_when_a_cluster_is_unreachable() {
    // No `/api2/json/nodes` route: the mock answers every request 404, so
    // the cluster-reachability poller's probe call fails.
    let h = common::TestServer::start_with_routes(common::TokenSpec::full(), vec![]).await;
    let client = reqwest::Client::new();
    let status = wait_for_readyz_status(&client, &h.url, StatusCode::SERVICE_UNAVAILABLE).await;
    assert_eq!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "an unreachable cluster must fail /readyz"
    );

    let body = client
        .get(format!("{}/readyz", h.url))
        .header(reqwest::header::HOST, "localhost")
        .send()
        .await
        .expect("request")
        .text()
        .await
        .expect("body");
    assert!(
        !body.contains("pve3"),
        "/readyz is unauthenticated and must not name which cluster failed, got: {body}"
    );
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
