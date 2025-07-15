use actix_web::{App, HttpResponse, HttpServer, Responder, get, web};
use ldap3::ldap_escape;
use serde::Deserialize;

#[derive(Deserialize)]
struct SearchQuery {
    username: String,
}

#[get("/vulnerable/search")]
async fn vulnerable_search(query: web::Query<SearchQuery>) -> impl Responder {
    // Directly using user input to construct the LDAP filter.
    // This is vulnerable to LDAP injection.
    let filter = format!("(uid={})", &query.username);

    // In a real application, you would connect to an LDAP server and perform the search.
    // For this example, we'll just return the generated filter.
    HttpResponse::Ok().body(format!("Vulnerable LDAP filter: {}", filter))
}

#[get("/secure/search")]
async fn secure_search(query: web::Query<SearchQuery>) -> impl Responder {
    // Properly escape the user input before using it in the filter.
    let escaped_username = ldap_escape(&query.username);
    let filter = format!("(uid={})", &escaped_username);

    HttpResponse::Ok().body(format!("Secure LDAP filter: {}", filter))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    println!("Starting server at http://127.0.0.1:8080");
    HttpServer::new(|| App::new().service(vulnerable_search).service(secure_search))
        .bind("127.0.0.1:8080")?
        .run()
        .await
}
