//! Property tests: arbitrary JSON into classic / Integration parsers never panics.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use dnscraft_clients::{parse_classic_clients_json, parse_integration_clients_json};
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1024))]

    #[test]
    fn classic_parser_never_panics(data in prop::collection::vec(any::<u8>(), 0..4096)) {
        let _ = parse_classic_clients_json(&data);
    }

    #[test]
    fn integration_parser_never_panics(data in prop::collection::vec(any::<u8>(), 0..4096)) {
        let _ = parse_integration_clients_json(&data);
    }

    #[test]
    fn classic_valid_envelope_with_junk_rows(
        rows in prop::collection::vec(any_json_value(), 0..32)
    ) {
        let body = serde_json::json!({ "meta": { "rc": "ok" }, "data": rows });
        let bytes = serde_json::to_vec(&body).unwrap();
        let (obs, skipped) = parse_classic_clients_json(&bytes).expect("envelope ok");
        prop_assert_eq!(obs.len() as u64 + skipped, rows.len() as u64);
    }

    #[test]
    fn integration_valid_envelope_with_junk_rows(
        rows in prop::collection::vec(any_json_value(), 0..32)
    ) {
        let body = serde_json::json!({ "data": rows, "offset": 0, "limit": 200, "count": rows.len() });
        let bytes = serde_json::to_vec(&body).unwrap();
        let (obs, skipped) = parse_integration_clients_json(&bytes).expect("envelope ok");
        prop_assert!(obs.len() + skipped as usize <= rows.len());
    }
}

fn any_json_value() -> impl Strategy<Value = serde_json::Value> {
    prop_oneof![
        Just(serde_json::Value::Null),
        any::<bool>().prop_map(serde_json::Value::Bool),
        any::<i64>().prop_map(|n| serde_json::json!(n)),
        ".*".prop_map(serde_json::Value::String),
        prop::collection::vec(".*", 0..4).prop_map(|v| {
            serde_json::Value::Array(v.into_iter().map(serde_json::Value::String).collect())
        }),
        // Client-shaped-ish objects with random fields.
        (
            proptest::option::of(".*"),
            proptest::option::of(".*"),
            proptest::option::of(".*"),
            proptest::option::of(prop::collection::vec(".*", 0..4)),
        )
            .prop_map(|(id, name, ip, v6)| {
                let mut m = serde_json::Map::new();
                if let Some(id) = id {
                    m.insert("_id".into(), id.clone().into());
                    m.insert("id".into(), id.into());
                }
                if let Some(name) = name {
                    m.insert("name".into(), name.clone().into());
                    m.insert("hostname".into(), name.into());
                }
                if let Some(ip) = ip {
                    m.insert("ip".into(), ip.clone().into());
                    m.insert("ipAddress".into(), ip.into());
                }
                if let Some(v6) = v6 {
                    m.insert(
                        "ipv6_addresses".into(),
                        serde_json::Value::Array(v6.into_iter().map(Into::into).collect()),
                    );
                }
                m.insert("mac".into(), "aa:bb:cc:dd:ee:ff".into());
                m.insert("macAddress".into(), "aa:bb:cc:dd:ee:ff".into());
                m.insert(
                    "weird".into(),
                    serde_json::json!({"nested": [1, true, null]}),
                );
                serde_json::Value::Object(m)
            }),
    ]
}
