use libghirahim::ghirahim;
use std::borrow::Cow;
use std::fs::File;
use std::io::prelude::*;
use std::sync::Arc;
use tldextract::{TldExtractor, TldOption};
use tokio::sync::Semaphore;
use twitch_irc::login::StaticLoginCredentials;
use twitch_irc::ClientConfig;
use twitch_irc::SecureWSTransport;
use twitch_irc::TwitchIRCClient;

#[tokio::main]
pub async fn main() {
    // load in the config
    let config: serde_yaml::Value;

    // Limit the scope of our file reads
    {
        let mut config_file = File::open("ghirahim.yaml").expect("Unable to open ghirahim.yaml");
        let mut config_contents = String::new();
        config_file
            .read_to_string(&mut config_contents)
            .expect("Unable to read ghirahim.yaml");
        config = serde_yaml::from_str(&config_contents).expect("Unable to parse ghirahim.yaml");
    }

    // set up the TLD list
    let temp_folder = tempfile::tempdir().expect("Couldn't create temporary folder");
    let option = TldOption {
        cache_path: Some(temp_folder.path().to_str().unwrap().to_owned() + ".tldcache"),
        private_domains: false,
        update_local: true,
        naive_mode: false,
    };
    let ext = TldExtractor::new(option);

    let login_name = config["ghirahim"]["username"].as_str().unwrap().to_string();
    let oauth_token = config["ghirahim"]["password"].as_str().unwrap().to_string();
    let irc_config = ClientConfig {
        login_credentials: StaticLoginCredentials::new(login_name, Some(oauth_token)),
        metrics_identifier: Some(Cow::from("Ghirahim_Bot")),
        connection_rate_limiter: Arc::new(Semaphore::new(2)),
        ..Default::default()
    };
    let (mut incoming_messages, client) =
        TwitchIRCClient::<SecureWSTransport, StaticLoginCredentials>::new(irc_config);

    let join_handle = tokio::spawn(async move {
        while let Some(message) = incoming_messages.recv().await {
            println!("Received message: {:?}", message);
        }
    });

    client.join("demize95".to_owned());
    join_handle.await.unwrap();
}
