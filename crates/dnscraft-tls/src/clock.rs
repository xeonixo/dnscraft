pub use dnscraft_common::clock::{Clock, ManualClock, SystemClock};
use std::time::SystemTime;

/// TLS-specific [`wait_until`] without an extra wake `Notify`.
pub async fn wait_until(clock: &dyn Clock, deadline: SystemTime) {
    // ponytail: dummy Notify — never fired, common select always
    // takes the tick/sleep branch
    let wake = tokio::sync::Notify::new();
    dnscraft_common::clock::wait_until(clock, deadline, &wake).await;
}
