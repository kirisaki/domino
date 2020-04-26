#[macro_use]
extern crate serde_derive;
use actix_web::{web, App, HttpServer};
use actix_session::{CookieSession};
use std::env;

pub mod handlers;
pub mod tokenizer;

#[actix_rt::main]
async fn main() {
    HttpServer::new(|| {
        let consume_key = env::var("TWITTER_CLIENT_ID")
            .expect("require TWITTER_CLIENT_ID");
        let consumer_secret = env::var("TWITTER_CLIENT_SECRET")
            .expect("require TWITTER_CLIENT_SECRET");

        let state = handlers::AppState{
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
            .route("/", web::get().to(handlers::index))
            .route("/login", web::get().to(handlers::login))
            .route("/logout", web::get().to(handlers::logout))
            .route("/oauth_callback", web::get().to(handlers::oauth_callback))
    })
    .bind("127.0.0.1:8000")
    .expect("Can not bind to port 8000")
    .run()
    .await
    .unwrap();
}
