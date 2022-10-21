use std::collections::HashMap;

use colored::Colorize;
use form_urlencoded;
use text_io::read;
use tiny_http::{Response, Server};
use url::Url;

use reqwest::blocking::ClientBuilder;
use serde_json;
use std::fs::File;
use twitch_irc::login::GetAccessTokenResponse;
use twitch_irc::login::UserAccessToken;

fn main() {
    // Get the server set up
    let server = Server::http("127.0.0.1:8000").unwrap();
    let this_document = Url::parse("http://127.0.0.1:8000").unwrap();

    println!("{}", "Ghirahim_Bot Token Helper".underline());
    println!("Please ensure that http://localhost:8000 is set as a redirect URI in your application settings.");
    println!("Please enter the following information.");

    // Collect the information we need
    print!("Client ID: ");
    let client_id: String = read!("{}\n");
    print!("Client secret: ");
    let client_secret: String = read!("{}\n");

    let scopes = "chat:read chat:edit moderator:manage:chat_messages";

    let auth_url = form_urlencoded::Serializer::new(String::new())
        .append_pair("client_id", &client_id)
        .append_pair("redirect_uri", "http://localhost:8000")
        .append_pair("response_type", "code")
        .append_pair("scope", scopes)
        .finish();

    println!(
        "Please open the following URL and authenticate {}: ",
        "as your bot account".red()
    );
    println!("https://id.twitch.tv/oauth2/authorize?{}", auth_url);
    println!("\nWaiting for response...");

    let mut auth_code: Option<String> = None;

    for request in server.incoming_requests() {
        let this_url = this_document.join(request.url()).unwrap();
        let params: HashMap<String, String> = this_url.query_pairs().into_owned().collect();

        if params.contains_key("error") {
            panic!(
                "Received an error from the API: {}\n{}",
                params["error"], params["error_description"]
            );
        }

        if params["scope"] != scopes {
            panic!("Incorrect scopes received: {}", params["scope"]);
        }

        auth_code = Some(params["code"].clone());

        let response = Response::from_string("You may close this window.");
        request.respond(response).unwrap();
        break;
    }

    // It should be impossible to get here without auth_code being Some(String)
    let auth_code = auth_code.unwrap();

    let params = HashMap::from([
        ("client_id", client_id),
        ("client_secret", client_secret),
        ("code", auth_code),
        ("grant_type", "authorization_code".to_owned()),
        ("redirect_uri", "http://localhost:8000".to_owned()),
    ]);

    // Build the REST client and send the POST to get our access/refresh tokens
    let client = ClientBuilder::new().build().unwrap();
    let resp = client
        .post("https://id.twitch.tv/oauth2/token")
        .form(&params)
        .send()
        .unwrap();

    if resp.status().is_success() {
        let json_resp = resp.text().unwrap();
        let decoded_response: GetAccessTokenResponse = serde_json::from_str(&json_resp).unwrap();
        let user_access_token = UserAccessToken::from(decoded_response);
        let secrets_file = File::create("secrets.json").expect("Unable to create secrets.json");
        serde_json::to_writer_pretty(secrets_file, &user_access_token).unwrap();
    }
}
