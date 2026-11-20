use super::*;
use crate::proxy::hysteria2::h3::huffman_encoded_len;

fn obfs_node(method: &str, placement: &str) -> Node {
    let mut node = node(XhttpMode::StreamUp, 32);
    let options = node.transport_mut().unwrap().xhttp.as_mut().unwrap();
    options.x_padding_obfs_mode = true;
    options.x_padding_method = Some(method.into());
    options.x_padding_placement = Some(placement.into());
    options.x_padding_header = Some("x-pad".into());
    options.x_padding_key = Some("pad".into());
    options.x_padding_bytes = XhttpRange { min: 100, max: 100 };
    node
}

fn template(node: &Node) -> super::super::request::RequestTemplate {
    super::super::request::RequestTemplate::new(node).unwrap()
}

fn referer_padding(request: &http::Request<()>) -> String {
    request.headers()["referer"]
        .to_str()
        .unwrap()
        .strip_prefix("http://peer.example/raw/../%252f/?x_padding=")
        .expect("Referer must carry the standard padding")
        .to_owned()
}

#[test]
fn query_in_header_replaces_the_query_with_the_padding_url() {
    let node = obfs_node("tokenish", "queryInHeader");
    let template = template(&node);
    for (session, seq, post, length) in [
        ("session", None, false, None),
        ("session", Some(0), true, Some(1)),
    ] {
        let request = template.request(session, seq, post, length).unwrap();
        assert!(request.headers().get(http::header::REFERER).is_none());
        let value = request.headers()["x-pad"].to_str().unwrap();
        let (url, padding) = value
            .split_once("?pad=")
            .expect("queryInHeader must carry the padding under its key");
        // The nested URL is the template base URL: no session/sequence,
        // matching Xray (padding first, session/sequence after) and the
        // legacy Referer, which also uses the pre-session URL.
        assert_eq!(url, format!("http://peer.example{WIRE_PREFIX}"));
        assert!(padding.bytes().all(|byte| byte.is_ascii_alphanumeric()));
        assert!((98..=102).contains(&huffman_encoded_len(padding.as_bytes())));
    }
}

#[test]
fn query_in_header_repeat_x_is_literal_xs() {
    let node = obfs_node("repeat-x", "queryInHeader");
    let request = template(&node)
        .request("session", None, false, None)
        .unwrap();
    assert!(request.headers().get(http::header::REFERER).is_none());
    assert_eq!(
        request.headers()["x-pad"].to_str().unwrap(),
        format!("http://peer.example{WIRE_PREFIX}?pad={}", "X".repeat(100))
    );
}

#[test]
fn header_placement_carries_the_padding_itself() {
    let node = obfs_node("repeat-x", "header");
    let request = template(&node)
        .request("session", None, false, None)
        .unwrap();
    assert!(request.headers().get(http::header::REFERER).is_none());
    assert_eq!(request.headers()["x-pad"], "X".repeat(100));
}

#[test]
fn query_placement_appends_the_key_to_the_request_uri() {
    let node = obfs_node("repeat-x", "query");
    let request = template(&node)
        .request("session", None, false, None)
        .unwrap();
    assert!(request.headers().get(http::header::REFERER).is_none());
    assert_eq!(
        request.uri().query(),
        Some(format!("token=a%2Fb&empty=&pad={}", "X".repeat(100)).as_str())
    );

    let mut node = obfs_node("repeat-x", "query");
    node.transport_mut().unwrap().xhttp.as_mut().unwrap().path = "/p/".into();
    let request = template(&node)
        .request("session", None, false, None)
        .unwrap();
    assert_eq!(
        request.uri().query(),
        Some(format!("pad={}", "X".repeat(100)).as_str())
    );
}

#[test]
fn cookie_placement_appends_to_an_existing_cookie() {
    let node = obfs_node("repeat-x", "cookie");
    let request = template(&node)
        .request("session", None, false, None)
        .unwrap();
    assert!(request.headers().get(http::header::REFERER).is_none());
    assert_eq!(
        request.headers()["cookie"],
        format!("pad={}", "X".repeat(100))
    );

    let mut node = obfs_node("repeat-x", "cookie");
    node.transport_mut()
        .unwrap()
        .xhttp
        .as_mut()
        .unwrap()
        .headers
        .insert("cookie".into(), "session=abc".into());
    let request = template(&node)
        .request("session", None, false, None)
        .unwrap();
    assert_eq!(
        request.headers()["cookie"],
        format!("session=abc; pad={}", "X".repeat(100))
    );
}

#[test]
fn tokenish_padding_huffman_length_stays_within_two_of_target() {
    let node = obfs_node("tokenish", "header");
    let template = template(&node);
    for _ in 0..32 {
        let request = template.request("session", None, false, None).unwrap();
        let padding = request.headers()["x-pad"].to_str().unwrap();
        assert!(padding.bytes().all(|byte| byte.is_ascii_alphanumeric()));
        assert!((98..=102).contains(&huffman_encoded_len(padding.as_bytes())));
    }
}

#[test]
fn incomplete_obfs_fields_fall_back_to_referer_padding() {
    for (method, placement, header, key) in [
        (None, Some("queryInHeader"), Some("x-pad"), Some("pad")),
        (Some("tokenish"), None, Some("x-pad"), Some("pad")),
        (Some("tokenish"), Some("queryInHeader"), None, Some("pad")),
        (Some("tokenish"), Some("queryInHeader"), Some("x-pad"), None),
    ] {
        let mut node = node(XhttpMode::StreamUp, 32);
        let options = node.transport_mut().unwrap().xhttp.as_mut().unwrap();
        options.x_padding_obfs_mode = true;
        options.x_padding_method = method.map(str::to_owned);
        options.x_padding_placement = placement.map(str::to_owned);
        options.x_padding_header = header.map(str::to_owned);
        options.x_padding_key = key.map(str::to_owned);
        options.x_padding_bytes = XhttpRange { min: 100, max: 100 };
        let request = template(&node)
            .request("session", None, false, None)
            .unwrap();
        assert!(request.headers().get("x-pad").is_none());
        assert_eq!(referer_padding(&request), "X".repeat(100));
    }
}

#[test]
fn unhandled_placements_fall_back_to_referer_padding() {
    for placement in ["path", "body", "auto"] {
        let node = obfs_node("tokenish", placement);
        let request = template(&node)
            .request("session", None, false, None)
            .unwrap();
        assert!(request.headers().get("x-pad").is_none(), "{placement}");
        assert_eq!(referer_padding(&request), "X".repeat(100), "{placement}");
    }
}

#[test]
fn node_without_obfs_fields_keeps_referer_padding() {
    let node = node(XhttpMode::StreamUp, 32);
    let request = template(&node)
        .request("session", None, false, None)
        .unwrap();
    assert!(request.headers().get("x-pad").is_none());
    assert_eq!(referer_padding(&request), "X".repeat(7));
}
