extern crate r2d2;
extern crate r2d2_postgres;
extern crate openssl;
#[macro_use] extern crate nickel;
extern crate nickel_postgres;
extern crate uuid;
extern crate serde_json;

use std::env;
use std::io::Read;
use r2d2::{NopErrorHandler, PooledConnection};
use r2d2_postgres::{SslMode, PostgresConnectionManager};
use nickel::{Nickel, HttpRouter, QueryString};
use nickel_postgres::{PostgresMiddleware, PostgresRequestExtensions};
use uuid::Uuid;
use nickel::status::StatusCode;
use serde_json::Value;

macro_rules! try_or_return {
    ( $op:expr, $error:expr ) => {
        match $op {
            Some(v) => v,
            None => return $error
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
            "CREATE TABLE IF NOT EXISTS permissions (
                key UUID REFERENCES services,
                username VARCHAR NOT NULL,
                permissions JSONB,
                PRIMARY KEY (key, username)
                )",
            &[]
        );
}

fn main() {
    let mut app = Nickel::new();

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
        try_or_return!(request.origin.read_to_end(&mut body).ok(),
                       response.error(StatusCode::InternalServerError,
                                      "Failed"));

        let permissions = try_or_return!(String::from_utf8(body).ok(),
            response.error(StatusCode::InternalServerError, "Failed"));

        let data: Value = try_or_return!(
            serde_json::from_str(&permissions).ok(),
            response.error(StatusCode::InternalServerError, "Failed"));

        let q = request.query();

        let username = try_or_return!(q.get("username"),
            response.error(StatusCode::BadRequest, "No username specified"));
        let key = try_or_return!(q.get("key").map(|s| Uuid::parse_str(s).ok()),
            response.error(StatusCode::BadRequest, "No key specified"));

        let r = conn.execute(
            "INSERT INTO permissions (key, username, permissions)
                VALUES ($1, $2, $3)
                ON CONFLICT (key, username) DO UPDATE SET
                permissions=excluded.permissions",
                &[&key, &username, &data]
            );
        println!("{:?}", r); // TODO: something with r
        format!("You posted {}", permissions)
    });

    app.get("/getperms", middleware! { |request, response|
        let conn = request.db_conn();
        let q = request.query();
        let key = try_or_return!(q.get("key").map(|s| Uuid::parse_str(s).ok()),
            response.error(StatusCode::BadRequest, "No key specified"));

        let username = try_or_return!(q.get("username"),
            response.error(StatusCode::BadRequest, "No username specified"));

        let r = try_or_return!(conn.query(
            "SELECT permissions FROM permissions
            WHERE key=$1 and username=$2",
            &[&key, &username]
            ).ok(), response.error(StatusCode::InternalServerError,
                              "Failed"));

        let row = r.get(0);
        let s: Value = row.get(0);

        format!("{:?}", s)
    });

    let listen = match env::var("LISTEN") {
        Ok(s) => s,
        Err(_) => "127.0.0.1:8080".to_string()
    };

    app.listen(&listen[..]);
}
