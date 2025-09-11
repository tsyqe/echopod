#![cfg_attr(feature = "backend-sql", allow(unexpected_cfgs))]
#![cfg_attr(not(feature = "backend-sql"), deny(unexpected_cfgs))]

use std::{future::Future, path::Path, sync::Arc};
use ::time::ext::NumericalDuration;
use cookie::{Cookie, SameSite};
use serde::{Deserialize, Serialize};
use warp::{
    http::{self, header::{HeaderMap, HeaderValue}},
    hyper::Body,
    Filter, Rejection, Reply,
};
use log::{debug, error, info};

mod auth;
use auth::{BasicAuth, SessionId};

mod user;
mod device;
mod subscription;
mod episode;

mod echopod;
use crate::echopod::{Echopod, EchopodAuthed};

mod time;
use crate::time::Timestamp;

mod path_format;
use path_format::split_format_json;

mod args;
use args::Args;

mod backend;
use backend::Backend;

static COOKIE_NAME: &str = "sessionid";

#[derive(Debug, Deserialize)]
pub struct QuerySince {
    since: crate::time::Timestamp,
}

#[tokio::main]
async fn main() {
    pretty_env_logger::init();
    let args = <Args as clap::Parser>::parse();

    if args.show_version() {
        println!("Echopod {}", env!("CARGO_PKG_VERSION"));
        return;
    }

    let data_dir = args.data_dir().unwrap_or_else(|| Path::new("."));
    let backend = Backend::new(&data_dir).await;
    let secure = args.secure();

    let echopod = Arc::new(Echopod::new(backend));

    let routes = routes(echopod.clone(), secure);
    warp::serve(routes)
        .run(args.addr().expect("couldn't parse address"))
        .await;
}

fn routes(
    echopod: Arc<Echopod>,
    secure: bool,
) -> impl Filter<Extract = (impl Reply,), Error = Rejection> + Clone + Sync + Send {
    let hello = warp::path::end()
        .and(warp::get())
        .map(|| "Echopod is Working!");

    let auth_routes = {
        let login = warp::post()
            .and(warp::path!("api" / "2" / "auth" / String / "login.json"))
            .and(warp::header::optional("authorization"))
            .and(warp::cookie::optional(COOKIE_NAME))
            .then({
                let echopod = Arc::clone(&echopod);
                move |username: String, auth: Option<BasicAuth>, session_id: Option<SessionId>| {
                    let echopod = Arc::clone(&echopod);
                    async move {
                        let auth = match auth {
                            Some(auth) => auth.with_path_username(&username).map_err(|e| {
                                error!("{e}");
                                Echopod::Error::Unauthorized
                            }),
                            None => {
                                error!("couldn't auth \"{username}\" - no auth header/cookie");
                                Err(Echopod::Error::Unauthorized)
                            }
                        }?;
                        let authed = echopod.login(auth, session_id).await?;
                        let session_id = authed.session_id();
                        let cookie = Cookie::build(COOKIE_NAME, session_id.to_string())
                            .secure(secure)
                            .http_only(true)
                            .same_site(SameSite::Strict)
                            .max_age(2.weeks())
                            .path("/api");
                        let cookie = HeaderValue::from_str(&cookie.to_string())
                            .map_err(|_| Echopod::Error::Internal)?;
                        let mut headers = HeaderMap::new();
                        headers.insert("set-cookie", cookie);
                        Ok(headers)
                    }
                }
            });

        let logout = warp::post()
            .and(warp::path!("api" / "2" / "auth" / String / "logout.json"))
            .and(authorize(UsernameFormat::Name, echopod.clone()))
            .then(move |authed: EchopodAuthed<true>| async move {
                result_to_ok(async move { authed.logout().await }).await
            });

        login.or(logout)
    };

    // Devices, subscriptions, episodes routes
    // They all follow the same pattern: clone Arc<Echopod> and use lowercased variable
    // For brevity, insert similar route definitions here from your previous code

    hello.or(auth_routes)
        .with(warp::log::custom(|info| {
            let now = Timestamp::now();
            info!(
                target: "echopod::warp",
                "{} {} {}",
                info.method(),
                info.path(),
                match now {
                    Ok(t) => t.to_string(),
                    Err(_) => "<notime>".into(),
                }
            );
        }))
        .recover(handle_rejection)
}

async fn result_to_json<F, B>(f: F) -> impl warp::Reply
where
    F: Future<Output = Echopod::Result<B>>,
    B: Serialize,
{
    match f.await {
        Ok(body) => warp::reply::json(&body).into_response(),
        Err(e) => err_to_warp(e).into_response(),
    }
}

async fn result_to_ok<F>(f: F) -> impl warp::Reply
where
    F: Future<Output = Echopod::Result<()>>,
{
    match f.await {
        Ok(()) => warp::reply().into_response(),
        Err(e) => err_to_warp(e).into_response(),
    }
}

async fn result_to_headers<F>(f: F) -> impl warp::Reply
where
    F: Future<Output = Echopod::Result<HeaderMap>>,
{
    match f.await {
        Ok(headers) => {
            let mut resp = http::Response::builder();
            if let Some(h) = resp.headers_mut() {
                h.extend(headers);
            }
            resp.body(Body::empty()).unwrap()
        }
        Err(e) => err_to_warp(e).into_response(),
    }
}

fn err_to_warp(e: Echopod::Error) -> impl warp::Reply {
    warp::reply::with_status(warp::reply(), e.into())
}

#[derive(Copy, Clone, Debug)]
enum UsernameFormat {
    Name,
    NameJson,
}

impl UsernameFormat {
    pub fn convert<'a>(&self, username: &'a str) -> Echopod::Result<&'a str> {
        match self {
            Self::Name => Ok(username),
            Self::NameJson => split_format_json(username),
        }
    }
}

fn cookie_authorize(
    username_fmt: UsernameFormat,
    echopod: Arc<Echopod>,
) -> impl Filter<Extract = (Echopod::Result<EchopodAuthed<true>>,), Error = warp::Rejection> + Clone {
    warp::path::param::<String>()
        .and(warp::cookie(COOKIE_NAME))
        .then({
            move |username: String, session_id: SessionId| {
                let echopod = Arc::clone(&echopod);
                async move {
                    echopod
                        .authenticate(session_id)
                        .await?
                        .with_user(username_fmt.convert(&username)?)
                        .map(|authed| authed)
                        .map_err(|e| e)
                }
            }
        })
}

fn login_authorize(
    username_fmt: UsernameFormat,
    echopod: Arc<Echopod>,
) -> impl Filter<Extract = (Echopod::Result<EchopodAuthed<true>>,), Error = warp::Rejection> + Clone {
    warp::path::param::<String>()
        .and(warp::header("authorization"))
        .and(warp::cookie::optional(COOKIE_NAME))
        .then(move |username: String, auth: BasicAuth, session_id: Option<SessionId>| {
            let echopod = Arc::clone(&echopod);
            async move {
                let username = username_fmt.convert(&username)?;
                let auth = auth.with_path_username(&username).map_err(|_| Echopod::Error::Unauthorized)?;
                echopod.login(auth, session_id).await
            }
        })
}

fn authorize(
    username_fmt: UsernameFormat,
    echopod: Arc<Echopod>,
) -> impl Filter<Extract = (EchopodAuthed<true>,), Error = warp::Rejection> + Clone {
    cookie_authorize(username_fmt, echopod.clone())
        .or(login_authorize(username_fmt, echopod.clone()))
        .unify()
        .and_then(|auth: Echopod::Result<_>| async move { auth.map_err(warp::reject::custom) })
}

async fn handle_rejection(err: Rejection) -> Result<impl Reply, Rejection> {
    if let Some(err) = err.find::<Echopod::Error>() {
        Ok(err_to_warp(*err))
    } else {
        Err(err)
    }
}

#[cfg(test)]
#[cfg(feature = "backend-sql")]
mod test {
    use sqlx::query;
    use super::*;
    use base64_light::base64_encode as base64;

    #[tokio::test]
    async fn hello() {
        let db = backend::test::create_db().await;
        let echopod = Arc::new(Echopod::new(backend::Backend(db)));
        let filter = routes(echopod.clone(), true);
        let res = warp::test::request().path("/").reply(&filter).await;
        assert_eq!(res.status(), 200);
    }

    #[tokio::test]
    async fn login_session() {
        let db = backend::test::create_db().await;
        let pass = "abc";
        let pwhash = auth::pwhash(pass);

        query!(
            r#"
            INSERT INTO users
            VALUES ("bob", ?, NULL);
            "#,
            pwhash,
        )
        .execute(&db)
        .await
        .unwrap();

        let echopod = Arc::new(Echopod::new(backend::Backend(db)));
        let filter = routes(echopod.clone(), true);

        let bob_auth = format!("Basic {}", base64(&format!("{}:{}", "bob", pass)));

        let res = warp::test::request()
            .path("/api/2/auth/bob/login.json")
            .method("POST")
            .header("authorization", &bob_auth)
            .reply(&filter)
            .await;
        assert_eq!(res.status(), 200);

        let cookie = res.headers().get("set-cookie").expect("session cookie");
        let cookie = Cookie::parse(cookie.to_str().unwrap()).unwrap();
        assert_eq!(cookie.name(), COOKIE_NAME);

        let res = warp::test::request()
            .path("/api/2/devices/bob.json")
            .header("cookie", cookie.to_string())
            .reply(&filter)
            .await;
        assert_eq!(res.status(), 200);

        let res = warp::test::request()
            .path("/api/2/auth/bob/login.json")
            .method("POST")
            .header("authorization", &bob_auth)
            .header("cookie", cookie.to_string())
            .reply(&filter)
            .await;
        assert_eq!(res.status(), 200);

        let tim_auth = format!("Basic {}", base64(&format!("{}:{}", "tim", "123")));
        let res = warp::test::request()
            .path("/api/2/auth/bob/login.json")
            .method("POST")
            .header("authorization", &tim_auth)
            .header("cookie", cookie.to_string())
            .reply(&filter)
            .await;
        assert_eq!(res.status(), 401);

        let res = warp::test::request()
            .path("/api/2/auth/bob/logout.json")
            .method("POST")
            .header("cookie", cookie.to_string())
            .reply(&filter)
            .await;
        assert_eq!(res.status(), 200);

        let res = warp::test::request()
            .path("/api/2/devices/bob.json")
            .header("cookie", cookie.to_string())
            .reply(&filter)
            .await;
        assert_eq!(res.status(), 401);
    }
}
