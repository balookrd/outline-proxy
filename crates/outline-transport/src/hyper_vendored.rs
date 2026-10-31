//! Gate for the patched `hyper` API (see PATCHES.md). Production code reaches the
//! patch only through this module, so a rebase of the vendored crate touches one file.

use bytes::Bytes;
use http::{HeaderMap, Request};
use hyper::ext::HeaderCaseMap;

use crate::fingerprint_profile::Profile;
use crate::request_headers::{h1_browser_case, h1_wire_name};

/// The HTTP/1.1 spelling of every header in `headers`, as `profile`'s browser
/// writes it ([`h1_wire_name`]); one entry per value, since hyper pairs the
/// n-th spelling of a name with its n-th value.
pub(crate) fn header_case_map(headers: &HeaderMap, profile: Option<&Profile>) -> HeaderCaseMap {
    let mut map = HeaderCaseMap::default();
    for name in headers.keys() {
        let wire = Bytes::from(h1_wire_name(name, profile).into_owned());
        for _ in headers.get_all(name) {
            map.append(name, wire.clone());
        }
    }
    map
}

/// Make hyper's h1 client write `request`'s header names in `profile`'s browser
/// case. Call it after the headers are final. Without a profile nothing is
/// attached, so hyper keeps writing the lowercase names it always wrote.
pub(crate) fn set_h1_header_case<B>(request: &mut Request<B>, profile: Option<&Profile>) {
    if !h1_browser_case(profile) {
        return;
    }
    let map = header_case_map(request.headers(), profile);
    request.extensions_mut().insert(map);
}
