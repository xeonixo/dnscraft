//! GF2: list fetch failures surface as `filter_list.*` module errors on apply.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod support;

use std::sync::Arc;

use axum::http::StatusCode;
use axum::routing::get;
use dnscraft_filtering::{
    FilterConfig, FilterSetConfig, ListConfig, ListId, ListSelection, ListSourceSpec, SetId,
};
use dnscraft_filtering::{ListStore, StoreConfig};

use dnscraft_api::{ControlApiError, apply_filter_config};
use support::{TempDir, TestServer, at};

#[tokio::test]
async fn apply_filter_config_reports_filter_list_fetch_failed() {
    let server = TestServer::start(
        axum::Router::new().route("/list.txt", get(|| async { StatusCode::NOT_FOUND })),
    )
    .await;

    let temp = TempDir::new("filter-fetch-failed");
    let clock = Arc::new(dnscraft_api::ManualClock::new(at(support::NOW)));
    let store_config = StoreConfig {
        allow_http_for_tests: true,
        ..Default::default()
    };
    let store = ListStore::open_with(temp.path(), store_config, clock.clone()).expect("store");
    let mut config = FilterConfig::default();
    config.lists.push(ListConfig {
        id: ListId::new("ads").unwrap(),
        name: "ads".to_owned(),
        source: ListSourceSpec::Url(server.url("/list.txt")),
        enabled: true,
    });
    config.sets.push({
        let mut set = FilterSetConfig::new(SetId::new("default").unwrap(), "Default");
        set.lists = vec![ListId::new("ads").unwrap()];
        set
    });
    let filter_clock: Arc<dyn dnscraft_filtering::Clock> = clock;
    let engine = dnscraft_filtering::FilterEngine::open_without_scheduler(
        config.clone(),
        store,
        filter_clock,
    )
    .expect("engine");

    let err = apply_filter_config(&engine, config).await.unwrap_err();
    let ControlApiError::Module { code, params } = err else {
        panic!("expected module error");
    };
    assert_eq!(code, "filter_list.fetch_failed");
    let params = params.expect("params");
    assert_eq!(params["url"], serde_json::json!(server.url("/list.txt")));
    assert_eq!(params["status"], serde_json::json!(404));

    let status = engine
        .update_lists(ListSelection::All)
        .await
        .into_iter()
        .find(|entry| entry.id == ListId::new("ads").unwrap())
        .expect("list status");
    assert_eq!(
        status.error_code.as_deref(),
        Some("filter_list.fetch_failed")
    );
}

#[tokio::test]
async fn apply_filter_config_reports_filter_list_too_large() {
    let temp = TempDir::new("filter-too-large");
    let clock = Arc::new(dnscraft_api::ManualClock::new(at(support::NOW)));
    let path = temp.path().join("big.txt");
    let line = "||host000000.example^\n";
    let mut body = String::new();
    while body.len() <= 2 * 1024 * 1024 {
        body.push_str(line);
    }
    std::fs::write(&path, &body).unwrap();

    let store =
        ListStore::open_with(temp.path(), StoreConfig::default(), clock.clone()).expect("store");
    let mut config = FilterConfig {
        max_list_size_mb: 1,
        ..Default::default()
    };
    config.lists.push(ListConfig {
        id: ListId::new("big").unwrap(),
        name: "big".to_owned(),
        source: ListSourceSpec::File(path.clone()),
        enabled: true,
    });
    config.sets.push({
        let mut set = FilterSetConfig::new(SetId::new("default").unwrap(), "Default");
        set.lists = vec![ListId::new("big").unwrap()];
        set
    });
    let filter_clock: Arc<dyn dnscraft_filtering::Clock> = clock;
    let engine = dnscraft_filtering::FilterEngine::open_without_scheduler(
        config.clone(),
        store,
        filter_clock,
    )
    .expect("engine");

    let err = apply_filter_config(&engine, config).await.unwrap_err();
    let ControlApiError::Module { code, params } = err else {
        panic!("expected module error");
    };
    assert_eq!(code, "filter_list.too_large");
    assert_eq!(params.unwrap()["max"], serde_json::json!(1));
}
