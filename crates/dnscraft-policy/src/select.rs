//! View and profile selection for an incoming request.
//!
//! Order: Client ID exact match → longest-prefix subnet → default view.
//! The hot path allocates neither `String` nor `Vec` (only `Arc` clones of
//! the selected ids).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ipnet::{Ipv4Net, Ipv6Net};

use crate::config::RequestContext;
use crate::ids::{ProfileId, ViewId};
use crate::snapshot::{PolicySnapshot, ViewIdx};

/// Why a view was selected for a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]

pub enum SelectionCause {
    /// Exact match on a view's Client ID list.
    ClientId,
    /// Longest-prefix match of the source address.
    Subnet {
        /// Network address of the matching prefix (host bits cleared).
        network: IpAddr,
        /// Prefix length in bits.
        prefix_len: u8,
    },
    /// Catch-all default view.
    Default,
}

/// Result of selecting a view and its profile for one request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Selection {
    /// Selected view.
    pub view_id: ViewId,
    /// Profile attached to that view.
    pub profile_id: ProfileId,
    /// Which rule produced this selection.
    pub matched_by: SelectionCause,
    /// Index into [`PolicySnapshot::views`] for the hot path.
    pub view_idx: ViewIdx,
}

impl PolicySnapshot {
    /// Selects the view and profile for `ctx`.
    ///
    /// Always succeeds when the snapshot was built successfully (a default
    /// view is guaranteed).
    pub fn select(&self, ctx: &RequestContext) -> Selection {
        if let Some(client_id) = ctx.client_id.as_ref()
            && let Some(&view_idx) = self.client_ids.get(client_id)
        {
            return self.finish(view_idx, SelectionCause::ClientId);
        }

        if let Some((view_idx, cause)) = self.match_subnet(ctx.source_ip) {
            return self.finish(view_idx, cause);
        }

        self.finish(self.default_view, SelectionCause::Default)
    }

    fn finish(&self, view_idx: ViewIdx, matched_by: SelectionCause) -> Selection {
        let view = &self.views[usize::from(view_idx)];
        let profile = &self.profiles[usize::from(view.profile_idx)];
        Selection {
            view_id: view.id.clone(),
            profile_id: profile.id.clone(),
            matched_by,
            view_idx,
        }
    }

    fn match_subnet(&self, source: IpAddr) -> Option<(ViewIdx, SelectionCause)> {
        match selection_ip(source) {
            IpAddr::V4(addr) => {
                for &len in &self.v4.lengths_desc {
                    let Some(masked) = mask_v4(addr, len) else {
                        continue;
                    };
                    let Some(&view_idx) = self.v4.by_len.get(&len).and_then(|m| m.get(&masked))
                    else {
                        continue;
                    };
                    return Some((
                        view_idx,
                        SelectionCause::Subnet {
                            network: IpAddr::V4(Ipv4Addr::from(masked)),
                            prefix_len: len,
                        },
                    ));
                }
                None
            }
            IpAddr::V6(addr) => {
                for &len in &self.v6.lengths_desc {
                    let Some(masked) = mask_v6(addr, len) else {
                        continue;
                    };
                    let Some(&view_idx) = self.v6.by_len.get(&len).and_then(|m| m.get(&masked))
                    else {
                        continue;
                    };
                    return Some((
                        view_idx,
                        SelectionCause::Subnet {
                            network: IpAddr::V6(Ipv6Addr::from(masked)),
                            prefix_len: len,
                        },
                    ));
                }
                None
            }
        }
    }
}

/// Treats IPv4-mapped IPv6 (`::ffff:a.b.c.d`) as IPv4 for subnet matching.
#[inline]
fn selection_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(v6)),
        other => other,
    }
}

#[inline]
fn mask_v4(addr: Ipv4Addr, len: u8) -> Option<[u8; 4]> {
    Ipv4Net::new(addr, len).ok().map(|n| n.network().octets())
}

#[inline]
fn mask_v6(addr: Ipv6Addr, len: u8) -> Option<[u8; 16]> {
    Ipv6Net::new(addr, len).ok().map(|n| n.network().octets())
}

#[cfg(test)]
mod unit {
    use super::*;

    #[test]
    fn select_maps_ipv4_mapped_to_v4() {
        let mapped = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0xc000, 0x020a));
        assert_eq!(
            selection_ip(mapped),
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))
        );
        assert_eq!(
            selection_ip(IpAddr::V6(Ipv6Addr::LOCALHOST)),
            IpAddr::V6(Ipv6Addr::LOCALHOST)
        );
    }
}
