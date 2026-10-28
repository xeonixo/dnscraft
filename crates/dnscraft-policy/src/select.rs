//! View and profile selection for an incoming request.
//!
//! Order: longest-prefix subnet (views valid on this node) → Client-ID pin
//! (views valid on this node) → default view. A Client ID is a selection input
//! only through its pin, and a pin never beats a matching subnet. The hot path
//! allocates neither `String` nor `Vec` (only `Arc` clones of the selected ids).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ipnet::{Ipv4Net, Ipv6Net};

use crate::config::RequestContext;
use crate::ids::{NodeId, ProfileId, ViewId};
use crate::snapshot::{PolicySnapshot, ViewIdx};

/// Why a view was selected for a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]

pub enum SelectionCause {
    /// Longest-prefix match of the source address.
    Subnet {
        /// Network address of the matching prefix (host bits cleared).
        network: IpAddr,
        /// Prefix length in bits.
        prefix_len: u8,
    },
    /// The request's admitted Client ID is pinned to the view, and no subnet matched.
    ClientId,
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
    /// Order: longest-prefix subnet among views valid on the request's node,
    /// then the Client-ID pin (if the request's Client ID is pinned to a view
    /// valid on the node), then the default view.
    ///
    /// Always succeeds when the snapshot was built successfully (a default
    /// view is guaranteed).
    pub fn select(&self, ctx: &RequestContext) -> Selection {
        if let Some((view_idx, cause)) = self.match_subnet(ctx.source_ip, ctx.node_id.as_ref()) {
            return self.finish(view_idx, cause);
        }

        if let Some(view_idx) = self.match_client_pin(ctx) {
            return self.finish(view_idx, SelectionCause::ClientId);
        }

        self.finish(self.default_view, SelectionCause::Default)
    }

    /// The pinned view of the request's Client ID, when that view is valid on
    /// the request's node. A pin to a view not valid on the node is ignored.
    fn match_client_pin(&self, ctx: &RequestContext) -> Option<ViewIdx> {
        let client = ctx.client_id.as_ref()?;
        let &view_idx = self.client_pins.get(client)?;
        self.views[usize::from(view_idx)]
            .valid_on(ctx.node_id.as_ref())
            .then_some(view_idx)
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

    /// Longest prefix whose view is valid on `node`. A view that is not valid
    /// on this node is treated as absent, so a shorter prefix may still match.
    fn match_subnet(
        &self,
        source: IpAddr,
        node: Option<&NodeId>,
    ) -> Option<(ViewIdx, SelectionCause)> {
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
                    if !self.views[usize::from(view_idx)].valid_on(node) {
                        continue;
                    }
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
                    if !self.views[usize::from(view_idx)].valid_on(node) {
                        continue;
                    }
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
