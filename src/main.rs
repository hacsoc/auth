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

        let name = match request.query().get("service_name") {
            Some(s) => s,
            None => {
                println!("No service_name, quitting");
                return response.error(StatusCode::BadRequest,
                                      "No service_name specified");
            }
        };

        let key = Uuid::new_v4();

        println!("Name: {}; key: {:?}", &name, &key);

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
        request.origin.read_to_end(&mut body).unwrap();
        let permissions = match String::from_utf8(body) {
            Ok(s) => s,
            Err(e) => {
                println!("Error decoding input string: {}", e);
                return response.error(StatusCode::InternalServerError,
                                      "Failed");
            }
        };

        let data: Value = serde_json::from_str(&permissions).unwrap();

        let q = request.query();

        // TODO: I'm writting a lot of code like this, to get stuff from the
        // get/post params.  This should become a macro (or something)
        let username = match q.get("username") {
            Some(s) => s,
            None => {
                println!("No username, quitting");
                return response.error(StatusCode::BadRequest,
                                      "No username specified");
            }
        };

        let key = match q.get("key") {
            Some(s) => s,
            None => {
                println!("No key, quitting");
                return response.error(StatusCode::BadRequest,
                                      "No key specified");
            }
        };

        let key = match Uuid::parse_str(key) {
            Ok(u) => u,
            Err(e) => {
                println!("Error with uuid conversion: {}", e);
                return response.error(StatusCode::BadRequest,
                                      "Bad key format");
            }
        };

        let r = conn.execute(
            "INSERT INTO permissions (key, username, permissions)
                VALUES ($1, $2, $3)
                ON CONFLICT (key, username) DO UPDATE SET
                permissions=excluded.permissions",
                &[&key, &username, &data]
            );
        println!("{:?}", r);
        // TODO: add username and permission to the database, if it works
        format!("You posted {}", permissions)
    });

    app.get("/getperms", middleware! { |request, response|
        let conn = request.db_conn();
        let q = request.query();
        let key = match q.get("key") {
            Some(s) => s,
            None => {
                println!("No key, quitting");
                return response.error(StatusCode::BadRequest,
                                      "No key specified");
            }
        };

        let key = Uuid::parse_str(&key).unwrap();
        let username = match q.get("username") {
            Some(s) => s,
            None => {
                println!("No username, quitting");
                return response.error(StatusCode::BadRequest,
                                      "No username specified");
            }
        };

        let r = &conn.query(
            "SELECT permissions FROM permissions
            WHERE key=$1 and username=$2",
            &[&key, &username]
            ).unwrap();

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
