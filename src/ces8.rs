//! CES-8 v0.1, nested cells and recursive capabilities (docs/standards/CES-8-nesting.md).
//!
//! A holder cell runs a box holding an inner door and inner cells; a box may hold another holder.
//! A box instance is named by its path from the outermost box, `["a7", "b2"]`, and an inner door
//! carries one tag per prefix of its path: `box:a7`, `box:a7/b2`. A link that carries a
//! capability across a boundary into a box is scoped to that box with
//! `ResourceV3::AllOf(box_tags(path))`, so by cap v3 it verifies only at that box and boxes inside
//! it, and a copy replayed in another box instance fails.
//!
//! [`authorize_inner`] is what an inner door runs: the full cap v3 check ([`authorize_v3`]) at a
//! node carrying the box's tags, then the CES-8 rules on top of it ([`check_boundaries`]).
use crate::program::ResourceV3;
use crate::v3::verify::{Node, Request, Roots, VerifiedV3, authorize_v3};
use crate::v3::{CapabilityV3, Key, Link, TokenV3};

/// Most boxes inside each other a node accepts by default (`nest_max`).
pub const DEFAULT_NEST_MAX: usize = 4;
pub const TAG_PREFIX: &str = "box:";

/// The tags of the inner door of box `path`: one per prefix, outermost first.
pub fn box_tags(path: &[String]) -> Vec<String> {
    (1..=path.len()).map(|n| format!("{TAG_PREFIX}{}", path[..n].join("/"))).collect()
}

/// The resource a link into box `path` carries.
pub fn box_resource(path: &[String]) -> ResourceV3 {
    ResourceV3::AllOf(box_tags(path))
}

/// The box path a resource is scoped to (empty: not scoped to any box). Err: box tags that are
/// not one well-formed chain of prefixes.
pub fn box_path_of(r: &ResourceV3) -> Result<Vec<String>, String> {
    let tags: Vec<&str> = match r {
        ResourceV3::Tag(t) => vec![t.as_str()],
        ResourceV3::AllOf(ts) => ts.iter().map(String::as_str).collect(),
        _ => vec![],
    };
    let mut boxes: Vec<&str> = tags.iter().filter_map(|t| t.strip_prefix(TAG_PREFIX)).collect();
    boxes.sort_by_key(|b| b.split('/').count());
    let deepest = boxes.last().map(|b| b.split('/').map(str::to_string).collect::<Vec<_>>()).unwrap_or_default();
    let want = box_tags(&deepest);
    let have: Vec<String> = boxes.iter().map(|b| format!("{TAG_PREFIX}{b}")).collect();
    if have != want || deepest.iter().any(|s| s.is_empty()) {
        return Err(format!("CES-8 B1: box tags {have:?} are not the prefixes of one box path"));
    }
    Ok(deepest)
}

fn v3(l: &Link) -> Option<&CapabilityV3> {
    match l {
        Link::V3 { cap, .. } => Some(cap),
        Link::V1(_) => None,
    }
}

/// The CES-8 rules over a chain that already verified under cap v3 (root first):
/// - B1 a link enters at most one box deeper than its parent, and never a box beside it;
/// - B2 the leaf is scoped to exactly `door_path` (a link for an outer box is not used inside);
/// - B3 a link that enters a box has an expiry (v3 already keeps it at most the parent's);
/// - B4 depth: v3 already drops `delegate.depth` by at least 1 on every link, so each boundary;
/// - B5 at most `nest_max` boxes deep;
/// - B6 rights: a link that enters box P lists only abilities in `declared(P)`, when the holder
///   declared them (`[box.export.<Op>] inner = [...]`).
pub fn check_boundaries(
    links: &[Link],
    door_path: &[String],
    nest_max: usize,
    declared: &dyn Fn(&[String]) -> Option<Vec<String>>,
) -> Result<(), String> {
    let mut prev: Vec<String> = vec![];
    for (i, l) in links.iter().enumerate() {
        let Some(c) = v3(l) else {
            if !prev.is_empty() {
                return Err(format!("CES-8 B1: link {i} is a v1 link inside a box"));
            }
            continue;
        };
        let path = box_path_of(&c.resource).map_err(|e| format!("{e} (link {i})"))?;
        if path.len() > prev.len() {
            if path.len() != prev.len() + 1 || path[..prev.len()] != prev[..] {
                return Err(format!("CES-8 B1: link {i} jumps from box {:?} to {:?}: one boundary per link", prev.join("/"), path.join("/")));
            }
            if path.len() > nest_max {
                return Err(format!("CES-8 B5: box {:?} is {} deep, nest_max is {nest_max}", path.join("/"), path.len()));
            }
            if c.caveats.not_after == 0 {
                return Err(format!("CES-8 B3: link {i} enters box {:?} with no expiry", path.join("/")));
            }
            if let Some(allowed) = declared(&path) {
                let mut asked = c.abilities.clone();
                if let Some(d) = &c.delegate {
                    asked.extend(d.abilities.iter().cloned());
                }
                if let Some(a) = asked.iter().find(|a| !allowed.contains(a)) {
                    return Err(format!("CES-8 B6: link {i} gives {a:?} into box {:?}, which declares only {allowed:?}", path.join("/")));
                }
            }
        } else if path.len() < prev.len() {
            return Err(format!("CES-8 B1: link {i} leaves box {:?}", prev.join("/")));
        }
        prev = path;
    }
    if prev != door_path {
        return Err(format!(
            "CES-8 B2: the chain is scoped to box {:?}, this door is box {:?}",
            prev.join("/"),
            door_path.join("/")
        ));
    }
    Ok(())
}

/// What an inner door checks before relaying a call to an inner cell: cap v3 at a node with the
/// box's tags, then [`check_boundaries`]. `door_key` is the inner door's own key.
#[allow(clippy::too_many_arguments)]
pub fn authorize_inner(
    door_key: [u8; 32],
    door_path: &[String],
    roots: &[Key],
    now: u64,
    requester: &Key,
    ability: &str,
    t: &TokenV3,
    nest_max: usize,
    declared: &dyn Fn(&[String]) -> Option<Vec<String>>,
) -> Result<VerifiedV3, String> {
    let tags = box_tags(door_path);
    let node = Node { id: door_key, tags: &tags, host: None };
    let roots = Roots { keys: roots, owners: &[] };
    let v = authorize_v3(&node, &roots, now, requester, &Request::Call(ability), t, &|_, _| false, &mut |_| Ok(()))?;
    check_boundaries(&t.links, door_path, nest_max, declared)?;
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &[&str]) -> Vec<String> {
        s.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn tags_and_paths_round_trip() {
        let path = p(&["a7", "b2"]);
        assert_eq!(box_tags(&path), p(&["box:a7", "box:a7/b2"]));
        assert_eq!(box_path_of(&box_resource(&path)).unwrap(), path);
        assert_eq!(box_path_of(&ResourceV3::Any).unwrap(), Vec::<String>::new());
        assert!(box_path_of(&ResourceV3::AllOf(p(&["box:a7/b2"]))).is_err());
        assert!(box_path_of(&ResourceV3::AllOf(p(&["box:a7", "box:x/b2"]))).is_err());
    }
}
