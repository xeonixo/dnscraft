//! Filtering apply helpers: map list fetch failures to API module errors (GF2).
//!
//! After a config rebuild, remote lists are refreshed once; a list-level fetch
//! or size failure is returned as a module error with the `filter_list.*` codes
//! from `SPEC.md`.

use dnscraft_filtering::{
    FilterConfig, FilterEngine, FilterError, ListSelection, ListSourceSpec, ListStatus,
};
use serde_json::json;

use crate::error::ControlApiError;

const LIST_FETCH_FAILED: &str = "filter_list.fetch_failed";
const LIST_TOO_LARGE: &str = "filter_list.too_large";

/// Rebuilds the filter snapshot from config and cached list bodies only (no network).
pub async fn apply_filter_config_offline(
    engine: &FilterEngine,
    config: FilterConfig,
) -> Result<(), ControlApiError> {
    engine.apply_config(config).await.map_err(filter_error)?;
    Ok(())
}

/// Refreshes remote filter lists (and the services catalog when `All`) after a
/// versioned config write; surfaces list-level fetch/size errors (GF2).
pub async fn refresh_filter_lists_after_config(
    engine: &FilterEngine,
    config: &FilterConfig,
) -> Result<(), ControlApiError> {
    let statuses = engine.update_lists(ListSelection::All).await;
    if let Some(error) = list_level_error(&statuses, config) {
        return Err(error);
    }
    Ok(())
}

/// Applies a filtering section: rebuild, refresh remote lists, then surface
/// list-level fetch/size errors promised by `SPEC.md`.
pub async fn apply_filter_config(
    engine: &FilterEngine,
    config: FilterConfig,
) -> Result<(), ControlApiError> {
    apply_filter_config_offline(engine, config.clone()).await?;
    refresh_filter_lists_after_config(engine, &config).await
}

/// Maps a [`FilterError`] to a forwarded module error.
pub fn filter_error(error: FilterError) -> ControlApiError {
    ControlApiError::Module {
        code: error.code(),
        params: Some(json!({ "reason": error.to_string() })),
    }
}

fn list_level_error(statuses: &[ListStatus], config: &FilterConfig) -> Option<ControlApiError> {
    for status in statuses {
        let code = status.error_code.as_deref()?;
        if code != LIST_FETCH_FAILED && code != LIST_TOO_LARGE {
            continue;
        }
        let list = config.lists.iter().find(|entry| entry.id == status.id)?;
        if !list.enabled {
            continue;
        }
        return Some(list_status_module_error(status, list, config, code));
    }
    None
}

fn list_status_module_error(
    status: &ListStatus,
    list: &dnscraft_filtering::ListConfig,
    config: &FilterConfig,
    code: &str,
) -> ControlApiError {
    let mut params = json!({ "list_id": list.id.as_str() });
    if let ListSourceSpec::Url(url) = &list.source {
        params["url"] = json!(url);
    }
    if let Some(http_status) = status.http_status {
        params["status"] = json!(http_status);
    }
    if code == LIST_TOO_LARGE {
        params["max"] = json!(config.max_list_size_mb);
    }
    let code = match code {
        LIST_FETCH_FAILED => LIST_FETCH_FAILED,
        LIST_TOO_LARGE => LIST_TOO_LARGE,
        _ => LIST_FETCH_FAILED,
    };
    ControlApiError::Module {
        code,
        params: Some(params),
    }
}
