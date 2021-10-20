use libghirahim::GhirahimDB;
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
    let _ext = TldExtractor::new(option);

    // Set up the IRC config based on the config file
    let login_name = config["ghirahim"]["username"].as_str().unwrap().to_string();
    let oauth_token = config["ghirahim"]["password"].as_str().unwrap().to_string();
    let irc_config = ClientConfig {
        login_credentials: StaticLoginCredentials::new(login_name, Some(oauth_token)),
        metrics_identifier: Some(Cow::from("Ghirahim_Bot")), // Collect metrics; TODO: actually consume these
        connection_rate_limiter: Arc::new(Semaphore::new(2)), // Open two connections at once, if necessary
        ..Default::default()
    };
    // Set up the IRC client
    let (mut incoming_messages, client) =
        TwitchIRCClient::<SecureWSTransport, StaticLoginCredentials>::new(irc_config);

    // Set up the database connections
    let mongo_str = config["mongo"]["connect_string"].as_str().unwrap();
    let redis_str = format!(
        "redis://{}:{}/{}",
        config["redis"]["host"].as_str().unwrap(),
        config["redis"]["port"].as_u64().unwrap(),
        config["redis"]["db"].as_u64().unwrap()
    );
    let mut db = GhirahimDB::new(mongo_str, &redis_str)
        .await
        .expect("Could not get database");

    // Get the list of all the channels we're supposed to be in
    let mut channels = db.get_all_channels().await.unwrap();
    channels.insert("ghirahim_bot".to_owned());
    client.set_wanted_channels(channels);

    // Set up the actual event loop
    let join_handle = tokio::spawn(async move {
        while let Some(message) = incoming_messages.recv().await {
            println!("Received message: {:?}", message);
        }
    });

    // Start the bot
    join_handle.await.unwrap();
}
