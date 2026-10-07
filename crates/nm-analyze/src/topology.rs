//! Offline topology inference from station MACs, OSPF peers and reciprocal ARP.
use crate::{view::normalize_mac, SnapshotView};
use nm_core::{ChainSignal, Confidence, DeviceId, OspfState, RadioMode, SiteId};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
/// Serializable inferred graph. Edges retain their observation confidence.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct TopologyGraph {
    pub nodes: Vec<Node>,
    pub edges: Vec<Edge>,
}
/// Stable identifiers allow frontends to navigate enrolled devices.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum Node {
    Site {
        id: SiteId,
        name: String,
    },
    Device {
        id: DeviceId,
        name: String,
        site: Option<SiteId>,
    },
    UnknownStation {
        mac: String,
    },
}
/// A station endpoint may be enrolled or visible only from an AP scan.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum StationNode {
    Device(DeviceId),
    Unknown(String),
}
/// Inference source for an L2 edge; ARP is deliberately a heuristic.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum ArpOrBridge {
    Arp,
    Bridge,
}
/// Observed links; site membership belongs to device nodes rather than edges.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum Edge {
    Wireless {
        ap: DeviceId,
        station: StationNode,
        signal: Option<i16>,
        chains: Vec<ChainSignal>,
        confidence: Confidence,
    },
    Ospf {
        a: DeviceId,
        b: DeviceId,
        state: Option<OspfState>,
        confidence: Confidence,
    },
    L2Adjacent {
        a: DeviceId,
        b: DeviceId,
        via: ArpOrBridge,
        confidence: Confidence,
    },
}
/// Build a deterministic graph without guessing unknown station identities.
pub fn infer(view: &SnapshotView<'_>) -> TopologyGraph {
    let mut graph = TopologyGraph::default();
    graph.nodes.extend(view.sites().map(|s| Node::Site {
        id: s.id,
        name: s.name.clone(),
    }));
    graph
        .nodes
        .extend(view.devices().map(|(d, _)| Node::Device {
            id: d.id,
            name: d.display_name.clone(),
            site: d.site,
        }));
    let mut unknown = BTreeSet::new();
    let mut ospf = BTreeSet::new();
    let mut l2 = BTreeSet::new();
    for (d, r) in view.devices() {
        if let Some(radio) = r
            .facts
            .radio
            .as_ref()
            .filter(|r| matches!(r.mode, Some(RadioMode::Ap | RadioMode::PtpMaster)))
        {
            for s in &radio.stations {
                if let Some(mac) = &s.mac {
                    let mac = normalize_mac(mac);
                    let station = if let Some(id) = view.mac_index.get(&mac) {
                        if *id == d.id {
                            continue;
                        }
                        StationNode::Device(*id)
                    } else {
                        if unknown.insert(mac.clone()) {
                            graph.nodes.push(Node::UnknownStation { mac: mac.clone() });
                        }
                        StationNode::Unknown(mac)
                    };
                    graph.edges.push(Edge::Wireless {
                        ap: d.id,
                        station,
                        signal: s.signal_dbm,
                        chains: s.chains.clone(),
                        confidence: Confidence::Certain,
                    });
                }
            }
        }
        if let Some(routing) = &r.facts.routing {
            for n in &routing.ospf_neighbors {
                let peer = n
                    .router_id
                    .as_ref()
                    .and_then(|a| view.ip_index.get(a))
                    .or_else(|| n.address.as_ref().and_then(|a| view.ip_index.get(a)));
                if let Some(peer) = peer {
                    if *peer != d.id
                        && ospf.insert((d.id, *peer, n.router_id.clone(), n.address.clone()))
                    {
                        graph.edges.push(Edge::Ospf {
                            a: d.id,
                            b: *peer,
                            state: n.state,
                            confidence: Confidence::Likely,
                        });
                    }
                }
            }
        }
        for n in &r.facts.neighbors {
            let Some(peer) = n
                .mac
                .as_ref()
                .and_then(|m| view.mac_index.get(&normalize_mac(m)))
                .filter(|p| **p != d.id)
            else {
                continue;
            };
            let reciprocal = view.device(*peer).is_some_and(|(_, p)| {
                p.facts.neighbors.iter().any(|n| {
                    n.mac
                        .as_ref()
                        .and_then(|m| view.mac_index.get(&normalize_mac(m)))
                        == Some(&d.id)
                })
            });
            let pair = if d.id < *peer {
                (d.id, *peer)
            } else {
                (*peer, d.id)
            };
            if reciprocal && l2.insert(pair) {
                graph.edges.push(Edge::L2Adjacent {
                    a: pair.0,
                    b: pair.1,
                    via: ArpOrBridge::Arp,
                    confidence: Confidence::Heuristic,
                });
            }
        }
    }
    graph
}
