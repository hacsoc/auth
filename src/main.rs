extern crate r2d2;
extern crate r2d2_postgres;
extern crate openssl;
#[macro_use] extern crate nickel;
extern crate nickel_postgres;
extern crate uuid;
extern crate serde_json;
extern crate cas;
extern crate cookie;
extern crate core;
extern crate url;
extern crate authtoken;

use std::env;
use std::io::Read;
use r2d2::{NopErrorHandler, PooledConnection};
use r2d2_postgres::{SslMode, PostgresConnectionManager};
use nickel::{Nickel, HttpRouter, QueryString};
use nickel_postgres::{PostgresMiddleware, PostgresRequestExtensions};
use uuid::Uuid;
use nickel::status::StatusCode;
use nickel::extensions::response::Redirect;
use serde_json::Value;
use cas::{CasClient, ServiceResponse, VerifyError};
use url::form_urlencoded::parse as urlparse;
use authtoken::{set_auth_cookie, verify_auth_cookie,
                get_auth_token_from_headers};

macro_rules! try_or_return {
    ( $op:expr, $error:expr ) => {
        match $op {
            Some(v) => v,
            None => return $error
        }
    }
}

macro_rules! try_or {
    ( $op:expr, $error:expr ) => {
        match $op {
            Ok(v) => v,
            Err(e) => {
                println!("error: {:?}", e);
                return $error;
            }
        }
    }
}

fn create_tables(conn: PooledConnection<PostgresConnectionManager>) {
    let _r = conn.execute(
            "CREATE TABLE IF NOT EXISTS services (
                key UUID PRIMARY KEY,
                name VARCHAR NOT NULL
                )",
            &[]
        );

    let _r = conn.execute(
            "CREATE TABLE IF NOT EXISTS users (
                key SERIAL PRIMARY KEY,
                caseid VARCHAR UNIQUE NOT NULL,
                slackid VARCHAR UNIQUE
                )",
            &[]
        );

    let _r = conn.execute(
            "CREATE TABLE IF NOT EXISTS permissions (
                key UUID REFERENCES services,
                username integer REFERENCES users,
                permissions JSONB,
                PRIMARY KEY (key, username)
                )",
            &[]
        );
}

fn main() {
    let mut app = Nickel::new();

    let hmac_secret = env::var("SECRET").expect("No SECRET found");

    let postgres_url = env::var("DATABASE_URL")
        .expect("Failed to get DATABASE_URL");

    let dbpool = PostgresMiddleware::new(&*postgres_url,
                                         SslMode::None,
                                         5,
                                         Box::new(NopErrorHandler)).unwrap();

    create_tables(dbpool.pool.clone().get().unwrap());
    app.utilize(dbpool);
    app.get("/register", middleware! { |request, response|
        let conn = request.db_conn();

        let name = try_or_return!(request.query().get("service_name"),
            response.error(
                StatusCode::BadRequest, "No service_name specified"));

        let key = Uuid::new_v4();

        let r = conn.execute(
            "INSERT INTO services (key, name) VALUES ($1, $2)",
            &[&key, &name]
            );
        println!("{:?}", r);

        key.to_hyphenated_string()
    });

    app.post("/adduser", middleware! { |request, response|
        let conn = request.db_conn();

        let mut body = vec![];
        try_or!(request.origin.read_to_end(&mut body),
                       response.error(StatusCode::InternalServerError,
                                      "Failed"));

        let permissions = try_or!(String::from_utf8(body),
            response.error(StatusCode::InternalServerError, "Failed"));

        let data: Value = try_or_return!(
            serde_json::from_str(&permissions).ok(),
            response.error(StatusCode::InternalServerError, "Failed"));

        let q = request.query();

        let caseid = try_or_return!(q.get("caseid"),
            response.error(StatusCode::BadRequest, "No username specified"));
        let key = try_or_return!(q.get("key").map(|s| Uuid::parse_str(s).ok()),
            response.error(StatusCode::BadRequest, "No key specified"));

        let user_rows = try_or!(conn.query(
                "INSERT INTO users (caseid) VALUES ($1)
                    ON CONFLICT (caseid) DO UPDATE SET caseid=users.caseid
                    RETURNING key",
                &[&caseid]
                ), response.error(StatusCode::InternalServerError,
                                  "Server Error")
            );
        if user_rows.len() != 1 {
            return response.error(StatusCode::InternalServerError,
                                  "Server Error");
        }

        let user = user_rows.get(0);
        let user_key: i32 = user.get(0);

        let r = try_or!(conn.execute(
            "INSERT INTO permissions (key, username, permissions)
                VALUES ($1, $2, $3)
                ON CONFLICT (key, username) DO UPDATE SET
                permissions=excluded.permissions",
                &[&key, &user_key, &data]
            ),
            response.error(StatusCode::InternalServerError, "Server error"));
        println!("{:?}", r);
        format!("You posted {}", permissions)
    });

    app.get("/getperms", middleware! { |request, response|
        let conn = request.db_conn();
        let q = request.query();
        let key = try_or_return!(q.get("key").map(|s| Uuid::parse_str(s).ok()),
            response.error(StatusCode::BadRequest, "No key specified"));

        let caseid = q.get("caseid").unwrap_or("");
        let slackid = q.get("slackid").unwrap_or("");

        let r = try_or!(conn.query(
                "SELECT permissions FROM permissions
                    INNER JOIN users
                    ON (permissions.username = users.key)
                    WHERE (caseid=$1 or slackid=$2) and permissions.key=$3",
                &[&caseid, &slackid, &key]
                ), response.error(StatusCode::InternalServerError,
                                  "Server Error")
            );
        println!("{:?}", r);

        if r.len() < 1 {
            return response.error(StatusCode::NotFound, "User not found");
        }
        let row = r.get(0);
        let s: Value = row.get(0);

        format!("{:?}", s)
    });

    let secret = hmac_secret.clone();
    app.get("/login", middleware! { |request, mut response|
        let base_url = env::var("BASE_URL")
            .unwrap_or("https://login.case.edu".to_string());
        let login_path = env::var("LOGIN_PATH")
            .unwrap_or("/cas/login".to_string());
        let logout_path = env::var("LOGOUT_PATH")
            .unwrap_or("/cas/logout".to_string());
        let verify_path = env::var("VERIFY_PATH")
            .unwrap_or("/cas/serviceValidate".to_string());
        let service_url = env::var("URL")
            .unwrap_or("http://hacsoc-auth.case.edu/login".to_string());

        let cas = try_or!(CasClient::new(&base_url, &login_path, &logout_path,
                                         &verify_path, &service_url),
                          response.error(StatusCode::InternalServerError,
                                         "Server Error"));
        match cas.verify_from_request(&request.origin) {
            Ok(ServiceResponse::Success(v)) => {
                set_auth_cookie(&secret, v, response.headers_mut());
                return response.redirect("/setslackid");
            }
            Ok(ServiceResponse::Failure(e)) => format!("error: {:?}", e),
            Err(VerifyError::NoTicketFound) =>
                return response.redirect(cas.get_login_url()),
            Err(_) => return response.error(StatusCode::InternalServerError,
                                            "Server Error"),
        }
    });

    let secret = hmac_secret.clone();
    app.get("/setslackid", middleware! { |request, response|
        if verify_auth_cookie::<String>(&secret, &request.origin.headers) {
            let data = "";
            return response.render("assets/slackform.html", &data);
        } else {
            return response.redirect("/login");
        }
    });

    let secret = hmac_secret.clone();
    app.post("/setslackid", middleware! { |request, response|
        if verify_auth_cookie::<String>(&secret, &request.origin.headers) {
            let token = match get_auth_token_from_headers(
                &request.origin.headers) {
                Some(v) => v,
                None => return response.redirect("/login")
            };
            let caseid: String = token.data;
            let conn = request.db_conn();
            let mut s: Vec<u8> = Vec::new();
            let _r = try_or!(request.origin.read_to_end(&mut s),
                             response.error(StatusCode::InternalServerError,
                                            "Server Error"));
            let data = urlparse(&s[..]);
            let mut slackid = "".to_string();
            for (name, value) in data {
                if name == "slackid" {
                    slackid = value.to_string();
                    break;
                }
            }

            let r = try_or!(conn.execute("INSERT INTO users (caseid, slackid)
                                    VALUES ($1, $2)
                                    ON CONFLICT (caseid) DO UPDATE SET
                                    slackid=excluded.slackid",
                                    &[&caseid, &slackid]
                                ),
                                response.error(StatusCode::InternalServerError,
                                               "Server Error"));
            println!("{}", r);
            format!("You have successfully associated the slack id {} with the case id {}",
                    slackid, caseid)
        } else {
            return response.redirect("/login");
        }
    });


    let listen = match env::var("LISTEN") {
        Ok(s) => s,
        Err(_) => "127.0.0.1:8080".to_string()
    };

    app.listen(&listen[..]);
}
