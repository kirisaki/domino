#[macro_use]
extern crate serde_derive;
use actix_web::{web, App, HttpResponse, HttpServer};
use actix_web::http::header;
use actix_session::{CookieSession, Session};
use chrono::Utc;
use percent_encoding::{utf8_percent_encode, AsciiSet};
use std::env;

const FRAGMENT: &AsciiSet = &percent_encoding::NON_ALPHANUMERIC
    .remove(b'*')
    .remove(b'-')
    .remove(b'.')
    .remove(b'_');

#[derive(Clone,Debug)]
struct RequestToken {
    oauth_token: String,
    oauth_token_secret: String,
    oauth_callback_confirmed: String,
}

struct AppState {
    consumer_key: String,
    consumer_secret: String,
    auth_url: String,
    token_url: String,
    access_url: String,
    redirect_url: String,
    callback_url: String,
}
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

fn get_request_header(endpoint: &str, oauth_consumer_key: &str, oauth_consumer_secret: &str, oauth_callback: &str) -> String {
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

async fn login(data: web::Data<AppState>) -> HttpResponse {
    let header_auth = get_request_header(&data.token_url, &data.consumer_key, &data.consumer_secret, &data.callback_url);
    let client = awc::Client::default();

    let mut body = std::collections::HashMap::new();
    body.insert("oauth_callback", data.callback_url.clone());
    let response0 = client
        .post(&data.token_url)
        .header("Authorization", header_auth)
        .content_type("application/x-www-form-urlencoded")
        .send_form(&body)
        .await
        .unwrap()
        .body()
        .await
        .unwrap();

    let tokens: Vec<&str> = (std::str::from_utf8(&response0).unwrap())
        .split('&')
        .map(|s| s.split('=').collect::<Vec<&str>>()[1])
        .collect();

    HttpResponse::Found()
        .header(header::LOCATION, format!("{}?oauth_token={}", data.auth_url, tokens[0]))
        .finish()
}

fn logout(session: Session) -> HttpResponse {
    session.remove("login");
    HttpResponse::Found()
        .header(header::LOCATION, "/".to_string())
        .finish()
}

#[derive(Deserialize)]
pub struct AuthRequest {
    oauth_token: String,
    oauth_verifier: String,
}

async fn oauth_callback(
    session: Session,
    data: web::Data<AppState>,
    params: web::Query<AuthRequest>,
) -> HttpResponse {

    session.set("login", true).unwrap();
    let client = awc::Client::default();

    let mut body = std::collections::HashMap::new();
    body.insert("oauth_token", &params.oauth_token);
    body.insert("oauth_verifier", &params.oauth_verifier);
    let response = client
        .post(&data.access_url)
        .content_type("application/x-www-form-urlencoded")
        .send_form(&body)
        .await
        .unwrap()
        .body()
        .await
        .unwrap();

    let html = format!(
        r#"<html>
        <head><title>Domino</title></head>
        <body>
            {:?}
        </body>
    </html>"#,
       response
    );
    HttpResponse::Ok().body(html)
}

async fn index(session: Session) -> HttpResponse{
    let link= if let Some(_login) = session.get::<bool>("login").unwrap() {
        "logout"
    } else {
        "login"
    };
    let html = format!(
        r#"<html>
        <head><title>Domino</title></head>
        <body>
            <a href="/{}">{}</a>
        </body>
    </html>"#,
        link, link
    );

    HttpResponse::Ok().body(html)
}

#[actix_rt::main]
async fn main() {
    HttpServer::new(|| {
        let consume_key = env::var("TWITTER_CLIENT_ID")
            .expect("require TWITTER_CLIENT_ID");
        let consumer_secret = env::var("TWITTER_CLIENT_SECRET")
            .expect("require TWITTER_CLIENT_SECRET");

        let state = AppState{
            consumer_key: consume_key,
            consumer_secret: consumer_secret,
            auth_url: "https://api.twitter.com/oauth/authorize".to_string(),
            access_url: "https://api.twitter.com/oauth/access_token".to_string(),
            token_url: "https://api.twitter.com/oauth/request_token".to_string(),
            redirect_url: "https://kirisaki.ngrok.io".to_string(),
            callback_url: "https://kirisaki.ngrok.io/oauth_callback".to_string(),
        };

        App::new()
            .data(state)
            .wrap(CookieSession::signed(&[0; 32]).secure(false))
            .route("/", web::get().to(index))
            .route("/login", web::get().to(login))
            .route("/logout", web::get().to(logout))
            .route("/oauth_callback", web::get().to(oauth_callback))
    })
    .bind("127.0.0.1:8000")
    .expect("Can not bind to port 8000")
    .run()
    .await
    .unwrap();
}
