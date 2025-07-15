
# LDAP injection

LDAP (Lightweight Directory Access Protocol) is used for accessing and maintaining distributed directory information services. An LDAP injection attack occurs when an application improperly sanitizes user input, which is then used in an LDAP query. This is similar to SQL injection and can lead to unauthorized data access or authentication bypass.

In this lesson, we will build a simple actix-web application in Rust to demonstrate this vulnerability. The application will have two endpoints: one that is vulnerable to LDAP injection and another that contains the fix.

1. Project Setup
First, let's set up our Rust project. Make sure you have Rust and Cargo installed.

Create a new project:

Bash

cargo new rust_ldap_injection_lesson
cd rust_ldap_injection_lesson
Next, add the necessary dependencies to your Cargo.toml file. We'll use actix-web for the web server and ldap3 for LDAP operations.

Ini, TOML

[dependencies]
actix-web = "4"
ldap3 = "0.11"
serde = { version = "1.0", features = ["derive"] }
2. The Vulnerable Code
Now, let's create our main application file, src/main.rs. We'll start by setting up a basic actix-web server and defining a vulnerable handler. This handler will take a username from a query parameter and directly use it to construct an LDAP filter.

Rust

use actix_web::{get, web, App, HttpServer, Responder, HttpResponse};
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

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        App::new()
            .service(vulnerable_search)
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
Vulnerability Explained:

The vulnerable_search function takes a username from the request's query string. It then constructs an LDAP filter by embedding this username directly into the string "(uid={})". The issue here is the lack of input sanitization. An attacker can provide a malicious string as the username to alter the structure of the LDAP query.

For instance, an attacker could send a request with the username set to *)(uid=*))(|(uid=*. The resulting filter would be (uid=*)(uid=*))(|(uid=*). This manipulates the query to potentially return all users, bypassing the intended filter logic.

3. The Secure Code
To mitigate this vulnerability, we must escape any special characters in the user-provided input before incorporating it into the LDAP filter. The ldap3 crate provides a handy function for this: ldap3::ldap_escape.

Let's add a secure handler to our src/main.rs:

Rust

use actix_web::{get, web, App, HttpServer, Responder, HttpResponse};
use ldap3::ldap_escape;
use serde::Deserialize;

#[derive(Deserialize)]
struct SearchQuery {
    username: String,
}

#[get("/vulnerable/search")]
async fn vulnerable_search(query: web::Query<SearchQuery>) -> impl Responder {
    let filter = format!("(uid={})", &query.username);
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
    HttpServer::new(|| {
        App::new()
            .service(vulnerable_search)
            .service(secure_search)
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
Mitigation Explained:

In the secure_search function, we use ldap_escape(&query.username) to sanitize the input. This function will escape any characters that have special meaning in an LDAP filter, such as *, (, ), and \. By doing this, we ensure that the user input is treated as a literal value and cannot alter the structure of the LDAP query.

4. Running and Testing the Application
Now, you can run the application:

Bash

cargo run
You will see the output: Starting server at http://127.0.0.1:8080.

Demonstrating the Vulnerability:

Open a new terminal and use curl to send a request to the vulnerable endpoint with a malicious payload:

Bash

curl "http://127.0.0.1:8080/vulnerable/search?username=*%29%28uid=*%29%29%28|%28uid=*"
The server will respond with the malformed and injected filter:

Vulnerable LDAP filter: (uid=*)(uid=*))(|(uid=*)
Demonstrating the Mitigation:

Now, send the same malicious payload to the secure endpoint:

Bash

curl "http://127.0.0.1:8080/secure/search?username=*%29%28uid=*%29%29%28|%28uid=*"
The server will respond with the properly escaped and secure filter:

Secure LDAP filter: (uid=\2a\29\28uid=\2a\29\29\28|\28uid=\2a)
As you can see, the special characters have been escaped with their hexadecimal representations, preventing the injection attack.

README.md
Here is a README file summarizing the lesson.

Rust LDAP Injection Lesson
This project demonstrates an LDAP injection vulnerability and its mitigation in a Rust web application built with the actix-web framework.

Lesson Summary
LDAP injection is a security vulnerability that occurs when an application fails to properly sanitize user input that is used to construct LDAP queries. This can allow an attacker to manipulate the queries, potentially leading to unauthorized data disclosure or authentication bypass.

This lesson covers:

What LDAP injection is and how it is similar to SQL injection.

How to create a vulnerable actix-web application that directly uses user input in an LDAP filter.

How to mitigate the vulnerability by properly escaping user input using the ldap3::ldap_escape function.

Application Setup
Prerequisites
Rust and Cargo installed on your system.

Installation
Clone the repository (or create the files as described below).

Navigate to the project directory.

Add the required dependencies to Cargo.toml:

Ini, TOML

[dependencies]
actix-web = "4"
ldap3 = "0.11"
serde = { version = "1.0", features = ["derive"] }
Running the Application
In your terminal, run the following command from the project root:

Bash

cargo run
The server will start and listen on http://127.0.0.1:8080.

Demonstrating the Vulnerability and Mitigation
Vulnerable Endpoint
The /vulnerable/search endpoint is susceptible to LDAP injection.

To demonstrate the vulnerability, send a curl request with a malicious username. The special characters are URL encoded.

Bash

curl "http://127.0.0.1:8080/vulnerable/search?username=*%29%28uid=*%29%29%28|%28uid=*"
Expected Vulnerable Output:
The server will respond with a filter that has been manipulated by the injected payload:

Vulnerable LDAP filter: (uid=*)(uid=*))(|(uid=*)
Secure Endpoint
The /secure/search endpoint mitigates the LDAP injection vulnerability.

To demonstrate the fix, send the same curl request to the secure endpoint:

Bash

curl "http://127.0.0.1:8080/secure/search?username=*%29%28uid=*%29%29%28|%28uid=*"
Expected Secure Output:
The server will respond with a filter where the special characters from the user input have been properly escaped:

Secure LDAP filter: (uid=\2a\29\28uid=\2a\29\29\28|\28uid=\2a)
This demonstrates that the input is treated as a literal string, preventing the injection attack.