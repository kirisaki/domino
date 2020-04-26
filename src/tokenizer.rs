use percent_encoding::{utf8_percent_encode, AsciiSet};
use chrono::Utc;

const FRAGMENT: &AsciiSet = &percent_encoding::NON_ALPHANUMERIC
    .remove(b'*')
    .remove(b'-')
    .remove(b'.')
    .remove(b'_');

fn create_oauth_signature(
    http_method: &str,
    endpoint: &str,
    oauth_consumer_secret: &str,
    oauth_token_secret: &str,
    params: &std::collections::HashMap<&str, &str>
) -> String {
    let cs_encoded = utf8_percent_encode(oauth_consumer_secret, FRAGMENT);
    let ts_encoded = utf8_percent_encode(oauth_token_secret, FRAGMENT);
    let key: String = format!("{}&{}", cs_encoded, ts_encoded);

    let mut params: Vec<(&&str, &&str)> = params.into_iter().collect();
    params.sort();

    let param = params
        .into_iter()
        .map(|(k, v)| {
            format!(
                "{}={}",
                utf8_percent_encode(k, FRAGMENT),
                utf8_percent_encode(v, FRAGMENT)
                )
            })
        .collect::<Vec<String>>()
        .join("&");

    let http_method_encoded = utf8_percent_encode(http_method, FRAGMENT);
    let endpoint_encoded = utf8_percent_encode(endpoint, FRAGMENT);
    let param_encoded = utf8_percent_encode(&param, FRAGMENT);

    let data = format!("{}&{}&{}", http_method_encoded, endpoint_encoded, param_encoded);

    let hash = hmacsha1::hmac_sha1(key.as_bytes(), data.as_bytes());
    base64::encode(&hash)
}

pub fn get_request_header(endpoint: &str, oauth_consumer_key: &str, oauth_consumer_secret: &str, oauth_callback: &str) -> String {
    let oauth_nonce: &str = &format!("nonce{}", Utc::now().timestamp());
    let oauth_signature_method: &str = "HMAC-SHA1";
    let oauth_timestamp: &str = &format!("{}", Utc::now().timestamp());
    let oauth_version: &str = "1.0";

    let mut params: std::collections::HashMap<&str, &str> = std::collections::HashMap::new();
    params.insert("oauth_nonce", oauth_nonce);
    params.insert("oauth_callback", oauth_callback);
    params.insert("oauth_signature_method", oauth_signature_method);
    params.insert("oauth_timestamp", oauth_timestamp);
    params.insert("oauth_version", oauth_version);
    params.insert("oauth_consumer_key", oauth_consumer_key);

    let oauth_signature: &str = &create_oauth_signature(
        "POST",
        &endpoint,
        oauth_consumer_secret,
        "",
        &params
    );

    format!(
        "OAuth oauth_nonce=\"{}\", oauth_callback=\"{}\", oauth_signature_method=\"{}\", oauth_timestamp=\"{}\", oauth_consumer_key=\"{}\", oauth_signature=\"{}\", oauth_version=\"{}\"",
        utf8_percent_encode(oauth_nonce, FRAGMENT),
        utf8_percent_encode(oauth_callback, FRAGMENT),
        utf8_percent_encode(oauth_signature_method, FRAGMENT),
        utf8_percent_encode(oauth_timestamp, FRAGMENT),
        utf8_percent_encode(oauth_consumer_key, FRAGMENT),
        utf8_percent_encode(oauth_signature, FRAGMENT),
        utf8_percent_encode(oauth_version, FRAGMENT),
    )
}


