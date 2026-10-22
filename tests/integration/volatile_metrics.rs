//! Volatile diagnostics measured through real requests and the public counters.

use std::time::{Duration, SystemTime};

use crate::{mock_upstream::*, testbed::*};

#[test]
fn volatile_revalidation_matrix_tracks_sent_validators_and_final_heads() {
    let body = b"index bytes";
    let upstream = MockUpstream::routing(move |req| {
        let status = if req.path().contains("unchanged") {
            304
        } else if req.path().contains("missing") {
            404
        } else {
            200
        };
        if status == 304 {
            ResponseSpec::new(status, b"").without_content_length()
        } else {
            ResponseSpec::new(status, body)
        }
    });
    let server = TestServer::start_with_config(&splice_config(""));
    for (mode, etag, modified) in [
        ("ETag only", true, false),
        ("Last-Modified only", false, true),
        ("both validators", true, true),
        ("no validators", false, false),
    ] {
        for (case, outcome, status) in [
            ("unchanged", "304", 200),
            ("body", "Body (200/206)", 200),
            ("missing", "Other Status", 404),
        ] {
            let suite = format!("{case}-{}-{}", u8::from(etag), u8::from(modified));
            let rel = upstream.cache_rel(&format!("debian/dists/{suite}_Release"));
            server.seed_cache(&rel, body);
            let path = server.cache_dir().join(&rel);
            backdate(&path, Duration::from_mins(2));
            if etag {
                xattr::set(&path, "user.apt_cacher_rs.etag", b"\"stored\"").unwrap();
            }
            if modified {
                xattr::set(
                    &path,
                    "user.apt_cacher_rs.last_modified",
                    MOCK_LAST_MODIFIED.as_bytes(),
                )
                .unwrap();
            }
            assert_served_status(
                &server,
                upstream.url(&format!("/debian/dists/{suite}/Release")),
                status,
                body,
            );
            let requests = upstream.recorded_headers();
            let headers = requests.last().expect("upstream request");
            assert_eq!(
                headers.iter().any(|(name, _)| name == "if-none-match"),
                etag
            );
            assert_eq!(
                headers.iter().any(|(name, _)| name == "if-modified-since"),
                modified
            );
            let page = dashboard(&server);
            assert_eq!(metric_cell(&page, &format!("{mode}: {outcome}")), "1");
        }
        assert_eq!(
            metric_cell(&dashboard(&server), &format!("Revalidations ({mode})")),
            "3"
        );
    }
    let page = dashboard(&server);
    assert_eq!(metric_cell(&page, "Volatile Expired"), "12");
    assert_eq!(metric_cell(&page, "Volatile Fetch Owners"), "12");
    assert_eq!(metric_cell(&page, "Volatile Fetch Joiners"), "0");
    let renewed: u64 = metric_cell(&page, "Volatile Freshness Renewed")
        .parse()
        .unwrap();
    let skipped: u64 = metric_cell(&page, "Volatile Renewal Skipped (no birth time)")
        .parse()
        .unwrap();
    assert_eq!(renewed + skipped, 4, "one renewal outcome per upstream 304");
    assert_eq!(metric_cell(&page, "Volatile Renewal Failed"), "0");
}

#[test]
fn volatile_lookup_distinguishes_missing_fresh_and_future_files() {
    let body = b"index bytes";
    let upstream = MockUpstream::fixed(ResponseSpec::new(200, body));
    let server = TestServer::start_with_config(&splice_config(""));
    let rel = upstream.cache_rel("debian/dists/sid_Release");
    let url = upstream.url("/debian/dists/sid/Release");
    assert_served(&server, &url, body);
    let path = server.wait_for_cached(&rel, body.len());
    assert_served(&server, &url, body);
    filetime::set_file_mtime(
        &path,
        filetime::FileTime::from_system_time(SystemTime::now() + Duration::from_secs(3600)),
    )
    .unwrap();
    assert_served(&server, &url, body);
    let page = dashboard(&server);
    assert_eq!(metric_cell(&page, "Volatile Hits"), "1 (33.3%)");
    assert_eq!(metric_cell(&page, "Volatile Absent"), "1");
    assert_eq!(metric_cell(&page, "Volatile Future Timestamp"), "1");
    assert_eq!(metric_cell(&page, "Volatile Expired"), "0");
    assert_eq!(metric_cell(&page, "Volatile Fetch Owners"), "2");
    assert_eq!(metric_cell(&page, "no validators: Body (200/206)"), "1");
}

#[test]
fn volatile_revalidation_transport_failure_is_not_a_body_response() {
    let upstream = MockUpstream::serve(|_, _| Reply::Close);
    let server = TestServer::start_with_config(&splice_config(""));
    server.seed_stale_volatile(
        &upstream.cache_rel("debian/dists/sid_Release"),
        b"old index",
    );
    let response = server.get(upstream.url("/debian/dists/sid/Release"));
    assert_eq!(response.status(), 502);
    let page = dashboard(&server);
    assert_eq!(metric_cell(&page, "Last-Modified only: Failed"), "1");
    assert_eq!(metric_cell(&page, "Last-Modified only: Interrupted"), "0");
    assert_eq!(
        metric_cell(&page, "Last-Modified only: Body (200/206)"),
        "0"
    );
}

#[test]
fn volatile_revalidation_redirect_counts_only_final_response() {
    let target = MockUpstream::fixed(ResponseSpec::new(304, b"").without_content_length());
    let upstream = MockUpstream::fixed(ResponseSpec::new(302, b"").header(format!(
        "Location: {}",
        target.url("/debian/dists/sid/Release")
    )));
    let server = TestServer::start_with_config(&splice_config(""));
    server.seed_stale_volatile(
        &upstream.cache_rel("debian/dists/sid_Release"),
        b"old index",
    );
    assert_served(
        &server,
        upstream.url("/debian/dists/sid/Release"),
        b"old index",
    );
    assert_eq!(upstream.recorded_paths().len(), 1);
    assert_eq!(target.recorded_paths().len(), 1);
    let page = dashboard(&server);
    assert_eq!(
        metric_cell(&page, "Revalidations (Last-Modified only)"),
        "1"
    );
    assert_eq!(metric_cell(&page, "Last-Modified only: 304"), "1");
    assert_eq!(metric_cell(&page, "Last-Modified only: Other Status"), "0");
}

#[test]
fn volatile_admission_refusal_is_not_an_owner_or_revalidation() {
    let body = resume_test_body(10_000);
    let gate = Gate::default();
    let reply_gate = gate.clone();
    let spec = ResponseSpec::new(200, &body);
    let upstream = MockUpstream::serve(move |_, _| Reply::Held {
        spec: spec.clone(),
        send_bytes: 4_000,
        gate: reply_gate.clone(),
    });
    let server = TestServer::start_with_config(&splice_config("max_upstream_downloads = 1"));
    let proxy = proxy_client(&server);
    let url = upstream.url("/debian/dists/sid/Release");
    let origin = std::thread::spawn(move || proxy.get(url).send().unwrap().bytes().unwrap());
    assert!(
        wait_until(Duration::from_secs(10), || upstream.sent_bytes() >= 4_000),
        "owner must hold the slot"
    );
    // A stale copy proves that refusal happens before any revalidation starts.
    server.seed_stale_volatile(
        &upstream.cache_rel("debian/dists/stable_Release"),
        b"old index",
    );
    let response = server.get(upstream.url("/debian/dists/stable/Release"));
    gate.open();
    assert_eq!(response.status(), 503);
    assert_eq!(&origin.join().unwrap()[..], &body[..]);
    let page = dashboard(&server);
    assert_eq!(metric_cell(&page, "Volatile Refetches"), "2");
    assert_eq!(metric_cell(&page, "Volatile Absent"), "1");
    assert_eq!(metric_cell(&page, "Volatile Expired"), "1");
    assert_eq!(metric_cell(&page, "Volatile Fetch Owners"), "1");
    assert_eq!(metric_cell(&page, "Volatile Admission Refused"), "1");
    assert_eq!(
        metric_cell(&page, "Revalidations (Last-Modified only)"),
        "0"
    );
}
