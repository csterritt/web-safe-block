//! Header, cookie, and HTML helpers shared by the request handlers.

use std::net::SocketAddr;
use std::time::Duration;

use axum::http::{HeaderMap, HeaderValue, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};

pub const SESSION_COOKIE: &str = "wsb_session";
pub const LOGIN_PATH: &str = "/__wsb/login";
pub const LOGOUT_PATH: &str = "/__wsb/logout";

/// Parse all Cookie headers and return (name, value) pairs in order.
pub(crate) fn parse_cookies(headers: &HeaderMap) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for hv in headers.get_all(header::COOKIE).iter() {
        if let Ok(s) = hv.to_str() {
            for part in s.split(';') {
                let part = part.trim();
                if let Some((name, value)) = part.split_once('=') {
                    out.push((name.trim().to_string(), value.trim().to_string()));
                }
            }
        }
    }
    out
}

/// Remove `SESSION_COOKIE` from the Cookie header(s), rebuilding a single
/// Cookie header (or removing it entirely if nothing remains).
pub(crate) fn strip_session_cookie(headers: &mut HeaderMap) {
    let remaining: Vec<String> = parse_cookies(headers)
        .into_iter()
        .filter(|(name, _)| name != SESSION_COOKIE)
        .map(|(n, v)| format!("{n}={v}"))
        .collect();
    while headers.remove(header::COOKIE).is_some() {}
    if !remaining.is_empty()
        && let Ok(v) = HeaderValue::from_str(&remaining.join("; "))
    {
        headers.insert(header::COOKIE, v);
    }
}

/// Sanitize a `next` redirect target; falls back to `/`.
pub(crate) fn sanitize_next(next: &str) -> String {
    let ok = next.starts_with('/')
        && !next.starts_with("//")
        && !next.starts_with("/\\")
        && !next.starts_with("/__wsb/")
        && !next.chars().any(|c| c.is_control());
    if ok {
        next.to_string()
    } else {
        "/".to_string()
    }
}

pub(crate) fn html_escape(s: &str) -> String {
    s.chars()
        .flat_map(|c| match c {
            '&' => "&amp;".chars().collect::<Vec<_>>(),
            '<' => "&lt;".chars().collect(),
            '>' => "&gt;".chars().collect(),
            '"' => "&quot;".chars().collect(),
            '\'' => "&#39;".chars().collect(),
            _ => vec![c],
        })
        .collect()
}

/// True if a Set-Cookie header value sets the session cookie.
pub(crate) fn sets_session_cookie(value: &str) -> bool {
    match value.split_once('=') {
        Some((name, _)) => name.trim() == SESSION_COOKIE,
        None => false,
    }
}

pub(crate) fn login_page(message: Option<&str>, next: &str) -> String {
    let msg = message
        .map(|m| format!("<p>{}</p>\n", html_escape(m)))
        .unwrap_or_default();
    format!(
        "<!DOCTYPE html>\n<html>\n<head>\n<meta charset=\"utf-8\">\n<title>Login</title>\n</head>\n<body>\n{msg}<form method=\"post\" action=\"{LOGIN_PATH}\">\n<label for=\"phrase\">Phrase</label>\n<input type=\"password\" id=\"phrase\" name=\"phrase\" autofocus>\n<input type=\"hidden\" name=\"next\" value=\"{}\">\n<button type=\"submit\">Submit</button>\n</form>\n</body>\n</html>\n",
        html_escape(next)
    )
}

pub(crate) fn html_response(status: StatusCode, body: String) -> Response {
    let mut resp = (status, body).into_response();
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    resp
}

pub(crate) fn session_cookie_header(token: &str, ttl: Duration, secure: bool) -> String {
    let mut s = format!(
        "{SESSION_COOKIE}={token}; HttpOnly; SameSite=Lax; Path=/; Max-Age={}",
        ttl.as_secs()
    );
    if secure {
        s.push_str("; Secure");
    }
    s
}

pub(crate) fn clear_cookie_header(secure: bool) -> String {
    let mut s = format!("{SESSION_COOKIE}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0");
    if secure {
        s.push_str("; Secure");
    }
    s
}

pub(crate) fn client_key(headers: &HeaderMap, peer: Option<SocketAddr>) -> String {
    headers
        .get("CF-Connecting-IP")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().parse::<std::net::IpAddr>().ok())
        .map(|ip| ip.to_string())
        .or_else(|| peer.map(|a| a.ip().to_string()))
        .unwrap_or_else(|| "unknown".to_string())
}

/// True if a POST came from another site, per Sec-Fetch-Site or Origin.
pub(crate) fn cross_site(headers: &HeaderMap) -> bool {
    if let Some(v) = headers.get("sec-fetch-site").and_then(|v| v.to_str().ok()) {
        return !(v.trim().eq_ignore_ascii_case("same-origin")
            || v.trim().eq_ignore_ascii_case("none"));
    }
    if let Some(origin) = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) {
        let host = headers
            .get(header::HOST)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let authority = origin
            .parse::<Uri>()
            .ok()
            .and_then(|u| u.authority().map(|a| a.as_str().to_string()));
        return match authority {
            Some(a) => !a.eq_ignore_ascii_case(host.trim()),
            None => true,
        };
    }
    false
}

/// Remove hop-by-hop headers: `Connection`, the names it lists, and a fixed set.
pub(crate) fn strip_hop_by_hop(headers: &mut HeaderMap) {
    let mut names: Vec<String> = Vec::new();
    for hv in headers.get_all(header::CONNECTION).iter() {
        if let Ok(s) = hv.to_str() {
            for n in s.split(',') {
                let n = n.trim();
                if !n.is_empty() {
                    names.push(n.to_string());
                }
            }
        }
    }
    names.extend([
        "connection".to_string(),
        "keep-alive".to_string(),
        "proxy-connection".to_string(),
        "te".to_string(),
        "trailer".to_string(),
        "transfer-encoding".to_string(),
        "upgrade".to_string(),
        "proxy-authorization".to_string(),
        "proxy-authenticate".to_string(),
    ]);
    for name in names {
        if let Ok(hn) = name.parse::<header::HeaderName>() {
            while headers.remove(&hn).is_some() {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers_with_cookies(vals: &[&str]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for v in vals {
            h.append(header::COOKIE, HeaderValue::from_str(v).unwrap());
        }
        h
    }

    #[test]
    fn strip_only_cookie() {
        let mut h = headers_with_cookies(&["wsb_session=abc"]);
        strip_session_cookie(&mut h);
        assert!(h.get(header::COOKIE).is_none());
    }

    #[test]
    fn strip_first_cookie() {
        let mut h = headers_with_cookies(&["wsb_session=abc; a=1; b=2"]);
        strip_session_cookie(&mut h);
        assert_eq!(h.get(header::COOKIE).unwrap(), "a=1; b=2");
    }

    #[test]
    fn strip_middle_cookie() {
        let mut h = headers_with_cookies(&["a=1; wsb_session=abc; b=2"]);
        strip_session_cookie(&mut h);
        assert_eq!(h.get(header::COOKIE).unwrap(), "a=1; b=2");
    }

    #[test]
    fn strip_last_cookie() {
        let mut h = headers_with_cookies(&["a=1; b=2; wsb_session=abc"]);
        strip_session_cookie(&mut h);
        assert_eq!(h.get(header::COOKIE).unwrap(), "a=1; b=2");
    }

    #[test]
    fn strip_multiple_cookie_headers() {
        let mut h = headers_with_cookies(&["a=1; wsb_session=abc", "b=2"]);
        strip_session_cookie(&mut h);
        assert_eq!(h.get(header::COOKIE).unwrap(), "a=1; b=2");
    }

    #[test]
    fn keep_similarly_named_cookie() {
        let mut h = headers_with_cookies(&["wsb_session2=keep; wsb_session=drop"]);
        strip_session_cookie(&mut h);
        assert_eq!(h.get(header::COOKIE).unwrap(), "wsb_session2=keep");
    }

    #[test]
    fn sanitize_next_cases() {
        assert_eq!(sanitize_next("/a?b=1"), "/a?b=1");
        assert_eq!(sanitize_next("//evil.com"), "/");
        assert_eq!(sanitize_next("/\\evil"), "/");
        assert_eq!(sanitize_next("http://x"), "/");
        assert_eq!(sanitize_next(""), "/");
        assert_eq!(sanitize_next("/__wsb/login"), "/");
        assert_eq!(sanitize_next("/a\nb"), "/");
    }

    #[test]
    fn html_escape_cases() {
        assert_eq!(html_escape("a&<b>\"'c"), "a&amp;&lt;b&gt;&quot;&#39;c");
    }

    #[test]
    fn set_cookie_name_matching() {
        assert!(sets_session_cookie("wsb_session=x; Path=/"));
        assert!(sets_session_cookie(" wsb_session =x"));
        assert!(!sets_session_cookie("wsb_session2=x"));
    }

    #[test]
    fn cross_site_cases() {
        let h = |pairs: &[(&str, &str)]| {
            let mut m = HeaderMap::new();
            for (k, v) in pairs {
                m.insert(
                    k.parse::<header::HeaderName>().unwrap(),
                    HeaderValue::from_str(v).unwrap(),
                );
            }
            m
        };
        assert!(!cross_site(&h(&[("sec-fetch-site", "same-origin")])));
        assert!(!cross_site(&h(&[("sec-fetch-site", "none")])));
        assert!(cross_site(&h(&[("sec-fetch-site", "cross-site")])));
        assert!(cross_site(&h(&[("sec-fetch-site", "same-site")])));
        assert!(!cross_site(&h(&[
            ("origin", "http://example.com"),
            ("host", "example.com")
        ])));
        assert!(!cross_site(&h(&[
            ("origin", "http://Example.com:8443"),
            ("host", "example.com:8443")
        ])));
        assert!(cross_site(&h(&[
            ("origin", "http://evil.example"),
            ("host", "example.com")
        ])));
        assert!(cross_site(&h(&[
            ("origin", "null"),
            ("host", "example.com")
        ])));
        assert!(cross_site(&h(&[("origin", "http://nohost.example"),])));
        assert!(!cross_site(&h(&[])));
    }

    #[test]
    fn client_key_requires_ip_header() {
        let peer = "9.9.9.9:1234".parse().unwrap();
        let mut h = HeaderMap::new();
        h.insert("cf-connecting-ip", HeaderValue::from_static("not an ip"));
        assert_eq!(client_key(&h, Some(peer)), "9.9.9.9");
        h.insert(
            "cf-connecting-ip",
            HeaderValue::from_static(" 203.0.113.5 "),
        );
        assert_eq!(client_key(&h, Some(peer)), "203.0.113.5");
    }
}
