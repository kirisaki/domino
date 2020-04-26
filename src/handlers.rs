use actix_web::{web, HttpResponse};
use actix_web::http::header;
use actix_session::{Session};

pub struct AppState {
    pub consumer_key: String,
    pub consumer_secret: String,
    pub auth_url: String,
    pub token_url: String,
    pub access_url: String,
    pub redirect_url: String,
    pub callback_url: String,
}
pub async fn login(data: web::Data<AppState>) -> HttpResponse {
    let header_auth = crate::tokenizer::get_request_header(
        &data.token_url,
        &data.consumer_key,
        &data.consumer_secret,
        &data.callback_url
        );
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

pub fn logout(session: Session) -> HttpResponse {
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

pub async fn oauth_callback(
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

pub async fn index(session: Session) -> HttpResponse{
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


