use honk_config::node::{Node, XhttpOptions, XhttpRange};

use crate::proxy::hysteria2::h3::huffman_encoded_len;

pub(super) use honk_config::node::XhttpResolvedMode as ResolvedMode;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ObfsMethod {
    RepeatX,
    Tokenish,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ObfsPlacement {
    QueryInHeader,
    Header,
    Query,
    Cookie,
}

/// Parsed once per template: how obfs padding replaces the Referer padding.
#[derive(Debug, Clone)]
struct ObfsPadding {
    method: ObfsMethod,
    placement: ObfsPlacement,
    header: http::header::HeaderName,
    key: String,
}

#[derive(Debug)]
pub(super) struct RequestTemplate {
    pub(super) mode: ResolvedMode,
    scheme: http::uri::Scheme,
    authority: http::uri::Authority,
    prefix: String,
    query: Option<String>,
    headers: http::HeaderMap,
    base_url: String,
    referer: String,
    no_grpc_header: bool,
    padding: XhttpRange,
    obfs: Option<ObfsPadding>,
    pub(super) post_bytes: XhttpRange,
    pub(super) post_interval: XhttpRange,
}

impl RequestTemplate {
    pub(super) fn new(node: &Node) -> anyhow::Result<Self> {
        let options = node
            .transport()
            .and_then(|transport| transport.xhttp.as_ref())
            .ok_or_else(|| anyhow::anyhow!("XHTTP options missing"))?;
        let tls = node.tls().unwrap();
        let mode = options.resolved_mode(tls).map_err(anyhow::Error::msg)?;
        let scheme = if tls.is_secure() {
            http::uri::Scheme::HTTPS
        } else {
            http::uri::Scheme::HTTP
        };
        let host = options
            .host
            .as_deref()
            .or(tls.sni.as_deref())
            .unwrap_or(node.host());
        let authority: http::uri::Authority = if host.parse::<std::net::Ipv6Addr>().is_ok() {
            format!("[{host}]").parse()?
        } else {
            host.parse()?
        };
        let (prefix, query) = options
            .path
            .split_once('?')
            .map_or((options.path.as_str(), None), |(path, query)| {
                (path, Some(query))
            });
        let mut headers = http::HeaderMap::new();
        for (name, value) in &options.headers {
            headers.insert(
                http::header::HeaderName::from_bytes(name.as_bytes())?,
                value.parse()?,
            );
        }
        super::browser::apply_chrome_fetch(&mut headers);
        let base_url = format!("{scheme}://{authority}{}", escape_path(prefix.to_owned()));
        let referer = format!("{base_url}?x_padding=");
        Ok(Self {
            mode,
            scheme,
            authority,
            prefix: prefix.to_owned(),
            query: query.map(str::to_owned),
            headers,
            base_url,
            referer,
            no_grpc_header: options.no_grpc_header,
            padding: options.x_padding_bytes,
            obfs: parse_obfs(options),
            post_bytes: options.sc_max_each_post_bytes,
            post_interval: options.sc_min_posts_interval_ms,
        })
    }

    pub(super) fn request(
        &self,
        session: &str,
        seq: Option<u64>,
        post: bool,
        length: Option<usize>,
    ) -> anyhow::Result<http::Request<()>> {
        let mut path = self.prefix.clone();
        if !session.is_empty() {
            path.push_str(session);
            if let Some(seq) = seq {
                path.push('/');
                path.push_str(&seq.to_string());
            }
        }
        let mut path = escape_path(path);
        if let Some(query) = &self.query {
            path.push('?');
            path.push_str(query);
        }
        let uri = http::Uri::builder()
            .scheme(self.scheme.clone())
            .authority(self.authority.clone())
            .path_and_query(path)
            .build()?;
        let mut request = http::Request::builder()
            .method(if post { "POST" } else { "GET" })
            .uri(uri)
            .body(())?;
        *request.headers_mut() = self.headers.clone();
        if post && length.is_none() && !self.no_grpc_header {
            request.headers_mut().insert(
                http::header::CONTENT_TYPE,
                http::HeaderValue::from_static("application/grpc"),
            );
        }
        if let Some(length) = length {
            request
                .headers_mut()
                .insert(http::header::CONTENT_LENGTH, length.to_string().parse()?);
        }
        let target = sample(self.padding);
        if let Some(obfs) = &self.obfs {
            apply_obfs_padding(&mut request, obfs, target, &self.base_url)?;
        } else {
            // Legacy padding uses the base URL, before session/sequence placement.
            let padding = "X".repeat(target as usize);
            request.headers_mut().insert(
                http::header::REFERER,
                format!("{}{padding}", self.referer).parse()?,
            );
        }
        Ok(request)
    }
}

/// Parse the Xray obfs padding claims once per template; anything the
/// dialer cannot send falls back to the standard Referer padding with one
/// warning. The parse layer already rejects unknown methods/placements
/// and empty header/key values, so only a missing claim, an unhandled
/// placement or an unparsable header name can reach this fallback.
fn parse_obfs(options: &XhttpOptions) -> Option<ObfsPadding> {
    if !options.x_padding_obfs_mode {
        return None;
    }
    let parsed = parse_obfs_claims(options);
    if parsed.is_none() {
        tracing::warn!(
            "XHTTP obfs padding disabled: incomplete or unhandled padding claims; falling back to Referer padding"
        );
    }
    parsed
}

fn parse_obfs_claims(options: &XhttpOptions) -> Option<ObfsPadding> {
    let method = match options.x_padding_method.as_deref()? {
        "repeat-x" => ObfsMethod::RepeatX,
        "tokenish" => ObfsMethod::Tokenish,
        _ => return None,
    };
    let placement = match options.x_padding_placement.as_deref()? {
        "queryInHeader" => ObfsPlacement::QueryInHeader,
        "header" => ObfsPlacement::Header,
        "query" => ObfsPlacement::Query,
        "cookie" => ObfsPlacement::Cookie,
        // Xray's Apply leaves path/body/auto alone, so the dialer does too.
        _ => return None,
    };
    let header =
        http::header::HeaderName::from_bytes(options.x_padding_header.as_deref()?.as_bytes())
            .ok()?;
    let key = options.x_padding_key.as_deref()?;
    Some(ObfsPadding {
        method,
        placement,
        header,
        key: key.to_owned(),
    })
}

fn apply_obfs_padding(
    request: &mut http::Request<()>,
    obfs: &ObfsPadding,
    target: u32,
    base_url: &str,
) -> anyhow::Result<()> {
    let padding = obfs_padding(obfs.method, target);
    match obfs.placement {
        ObfsPlacement::QueryInHeader => {
            // Xray adds padding before session/sequence, so the nested
            // URL is the template base URL, not the request URI; the
            // whole query is replaced with the padding key.
            let value = format!("{base_url}?{}={padding}", obfs.key);
            request
                .headers_mut()
                .insert(obfs.header.clone(), value.parse()?);
        }
        ObfsPlacement::Header => {
            request
                .headers_mut()
                .insert(obfs.header.clone(), padding.parse()?);
        }
        ObfsPlacement::Query => {
            let uri = request.uri().clone();
            let separator = if uri.query().is_some() { '&' } else { '?' };
            let path_and_query = format!(
                "{}{separator}{}={padding}",
                uri.path_and_query()
                    .map(|part| part.as_str())
                    .unwrap_or("/"),
                obfs.key
            );
            let mut parts = uri.into_parts();
            parts.path_and_query = Some(path_and_query.parse()?);
            *request.uri_mut() = http::Uri::from_parts(parts)?;
        }
        ObfsPlacement::Cookie => {
            let headers = request.headers_mut();
            let value = match headers.get(http::header::COOKIE) {
                Some(existing) => format!("{}; {}={padding}", existing.to_str()?, obfs.key),
                None => format!("{}={padding}", obfs.key),
            };
            headers.insert(http::header::COOKIE, value.parse()?);
        }
    }
    Ok(())
}

/// Padding bytes for one obfs placement. The length is the HPACK Huffman
/// byte count for `tokenish` and the character count for `repeat-x`
/// (`'X'` Huffman-codes to exactly one byte).
fn obfs_padding(method: ObfsMethod, target: u32) -> String {
    match method {
        ObfsMethod::RepeatX => "X".repeat(target as usize),
        ObfsMethod::Tokenish => tokenish_padding(target),
    }
}

fn tokenish_padding(target: u32) -> String {
    use rand::RngExt;
    use rand::distr::Alphanumeric;
    let mut rng = rand::rng();
    // Base62 symbols Huffman-code to 5-8 bits, about 6.3 on average, so
    // this slightly overestimates the character count; the loops below
    // trim or extend it to within two bytes of the target.
    let estimate = (target as usize * 8).div_ceil(6);
    let mut padding: String = (&mut rng)
        .sample_iter(Alphanumeric)
        .take(estimate)
        .map(char::from)
        .collect();
    while huffman_encoded_len(padding.as_bytes()) > target as usize + 2 {
        padding.pop();
    }
    while huffman_encoded_len(padding.as_bytes()) < target.saturating_sub(2) as usize {
        padding.push(rng.sample(Alphanumeric) as char);
    }
    padding
}

fn escape_path(path: String) -> String {
    let needs_escape = |byte: u8| {
        !matches!(byte, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9'
            | b'-' | b'_' | b'.' | b'~' | b'/' | b'$' | b'&' | b'+'
            | b',' | b':' | b';' | b'=' | b'@')
    };
    let count = path.bytes().filter(|&byte| needs_escape(byte)).count();
    if count == 0 {
        return path;
    }
    let mut escaped = String::with_capacity(path.len() + 2 * count);
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for byte in path.bytes() {
        if needs_escape(byte) {
            escaped.push('%');
            escaped.push(HEX[(byte >> 4) as usize] as char);
            escaped.push(HEX[(byte & 15) as usize] as char);
        } else {
            escaped.push(byte as char);
        }
    }
    escaped
}

pub(super) fn sample(range: XhttpRange) -> u32 {
    use rand::RngExt;
    rand::rng().random_range(range.min..=range.max)
}
