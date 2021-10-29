use libghirahim::{GhirahimDB, UserRole};
use std::borrow::Cow;
use std::fs::File;
use std::io::prelude::*;
use std::str::FromStr;
use std::sync::Arc;
use tldextract::{TldExtractor, TldOption};
use tokio::sync::Semaphore;
use twitch_irc::login::StaticLoginCredentials;
use twitch_irc::message::{PrivmsgMessage, ServerMessage};
use twitch_irc::ClientConfig;
use twitch_irc::SecureWSTransport;
use twitch_irc::TwitchIRCClient;

use nom::{branch::alt, bytes::complete::tag_no_case, Finish};

use tracing::{error, info, instrument, subscriber::set_global_default, trace, warn};
use tracing_bunyan_formatter::{BunyanFormattingLayer, JsonStorageLayer};
use tracing_log::LogTracer;
use tracing_subscriber::{layer::SubscriberExt, EnvFilter, Registry};

const LEAVE_NOTICES: [&str; 6] = [
    "msg_banned",
    "msg_channel_blocked",
    "msg_room_not_found",
    "msg_timedout",
    "msg_verified_email",
    "tos_ban",
];

const COOLDOWN_NOTICES: [&str; 13] = [
    "msg_duplicate",
    "msg_emoteonly",
    "msg_facebook",
    "msg_followersonly",
    "msg_followersonly_followed",
    "msg_followersonly_zero",
    "msg_r9k",
    "msg_ratelimit",
    "msg_rejected",
    "msg_rejected_mandatory",
    "msg_slowmode",
    "msg_subsonly",
    "no_permission",
];

#[instrument(level = "trace")]
async fn parse_command(msg: &str) -> nom::IResult<&str, &str> {
    alt((
        tag_no_case("!links"),
        tag_no_case("!permit"),
        tag_no_case("!join"),
        tag_no_case("!leave"),
    ))(msg.trim())
}

#[instrument(level = "trace")]
async fn parse_command_links(args: &str) -> nom::IResult<&str, &str> {
    alt((
        tag_no_case("list"),
        tag_no_case("allow"),
        tag_no_case("deny"),
        tag_no_case("slash"),
        tag_no_case("dot"),
        tag_no_case("subdomains"),
        tag_no_case("role"),
        tag_no_case("reply"),
        tag_no_case("test"),
    ))(args.trim())
}

#[instrument(level = "trace")]
async fn parse_bool_inner(args: &str) -> nom::IResult<&str, &str> {
    alt((
        tag_no_case("true"),
        tag_no_case("yes"),
        tag_no_case("on"),
        tag_no_case("false"),
        tag_no_case("no"),
        tag_no_case("off"),
    ))(args.trim())
}

#[instrument(level = "trace")]
async fn parse_bool(args: &str) -> Option<bool> {
    match parse_bool_inner(args).await {
        Err(_) => None,
        Ok((_, arg)) => match arg {
            "true" | "yes" | "on" => Some(true),
            "false" | "no" | "off" => Some(false),
            _ => None,
        },
    }
}

#[instrument(level = "debug")]
fn generate_reply(reply_str: &str, user: &str) -> String {
    if reply_str == "default" {
        format!(
            "@{}, please ask for permission before posting a link.",
            user
        )
    } else {
        reply_str.replace("__user__", user)
    }
}

#[instrument(level = "debug")]
async fn try_send_privmsg<
    T: twitch_irc::transport::Transport,
    L: twitch_irc::login::LoginCredentials,
>(
    client: &TwitchIRCClient<T, L>,
    channel: &str,
    msg: &str,
) {
    if client
        .privmsg(channel.to_owned(), msg.to_owned())
        .await
        .is_err()
    {
        if let Err(e) = client.privmsg(channel.to_owned(), msg.to_owned()).await {
            warn!("Error sending message: {}", e);
        }
    }
}

#[instrument(level = "debug")]
async fn try_say<T: twitch_irc::transport::Transport, L: twitch_irc::login::LoginCredentials>(
    client: &TwitchIRCClient<T, L>,
    channel: &str,
    msg: &str,
) {
    if client
        .say(channel.to_owned(), msg.to_owned())
        .await
        .is_err()
    {
        if let Err(e) = client.say(channel.to_owned(), msg.to_owned()).await {
            warn!("Error sending message: {}", e);
        }
    }
}

#[instrument(level = "debug")]
async fn try_respond<
    T: twitch_irc::transport::Transport,
    L: twitch_irc::login::LoginCredentials,
>(
    client: &TwitchIRCClient<T, L>,
    channel: &str,
    msg: &str,
    msg_id: &str,
) {
    if client
        .say_in_response(channel.to_owned(), msg.to_owned(), Some(msg_id.to_owned()))
        .await
        .is_err()
    {
        if let Err(e) = client
            .say_in_response(channel.to_owned(), msg.to_owned(), Some(msg_id.to_owned()))
            .await
        {
            warn!("Error sending message: {}", e);
        }
    }
}

#[instrument(level = "debug")]
async fn send_channel_list<
    T: twitch_irc::transport::Transport,
    L: twitch_irc::login::LoginCredentials,
>(
    client: &TwitchIRCClient<T, L>,
    msg: &PrivmsgMessage,
    chan: &libghirahim::Channel,
) {
    // Print the list of allowed links in the channel
    let message = format!(
        "Allowed links in {}: {}",
        chan.name,
        chan.allow_list.join(", ")
    );
    try_respond(
        client,
        msg.channel_login.as_str(),
        message.as_str(),
        msg.message_id.as_str(),
    )
    .await;
}

#[instrument(skip(ext), level = "debug")]
async fn handle_command<
    T: twitch_irc::transport::Transport,
    L: twitch_irc::login::LoginCredentials,
>(
    db: &GhirahimDB,
    msg: PrivmsgMessage,
    client: TwitchIRCClient<T, L>,
    ext: &TldExtractor,
) {
    if let Ok((args, command)) = parse_command(msg.message_text.as_str()).await.finish() {
        if msg.channel_login != "ghirahim_bot" {
            match command {
                "!links" => {
                    let chan = match db.get_channel(&msg.channel_login).await {
                        Some(chan) => chan,
                        None => {
                            client.part(msg.channel_login);
                            return;
                        }
                    };
                    if let Ok((args, command)) = parse_command_links(args).await.finish() {
                        match command {
                            "list" => send_channel_list(&client, &msg, &chan).await,
                            "allow" => {
                                if !args.is_empty() {
                                    let domains = args.split_whitespace();
                                    let mut chan = chan.clone();
                                    for domain in domains {
                                        let domain = domain.to_owned();
                                        if !chan.allow_list.contains(&domain) {
                                            chan.allow_list.push(domain);
                                        }
                                    }
                                    if let Err(e) = db.set_channel(&chan).await {
                                        error!("Error setting channel: {}", e);
                                        try_respond(&client, msg.channel_login.as_str(), "Could not update channel allow list! Please report this error.", msg.message_id.as_str()).await;
                                    } else {
                                        send_channel_list(&client, &msg, &chan).await;
                                    }
                                }
                            }
                            "deny" => {
                                if !args.is_empty() {
                                    let domains: Vec<&str> = args.split_whitespace().collect();
                                    let mut chan = chan.clone();
                                    chan.allow_list.retain(|x| !domains.contains(&x.as_str()));
                                    if let Err(e) = db.set_channel(&chan).await {
                                        error!("Error setting channel: {}", e);
                                        try_respond(&client, msg.channel_login.as_str(), "Could not update channel allow list! Please report this error.", msg.message_id.as_str()).await;
                                    } else {
                                        send_channel_list(&client, &msg, &chan).await;
                                    }
                                }
                            }
                            "slash" => {
                                // If args is empty, print whether slash is currently enabled
                                if args.is_empty() {
                                    let message = format!(
                                        "Slash matching is currently {} in {}.",
                                        if chan.slash { "enabled" } else { "not enabled" },
                                        msg.channel_login
                                    );
                                    try_respond(
                                        &client,
                                        msg.channel_login.as_str(),
                                        message.as_str(),
                                        msg.message_id.as_str(),
                                    )
                                    .await;
                                } else if let Some(slash) = parse_bool(args).await {
                                    let mut chan = chan.clone();
                                    chan.slash = slash;
                                    if let Err(e) = db.set_channel(&chan).await {
                                        error!("Error setting channel: {}", e);
                                        try_respond(&client, msg.channel_login.as_str(), "Could not update channel slash setting! Please report this error.", msg.message_id.as_str()).await;
                                    }
                                }
                            }
                            "dot" => {
                                if args.is_empty() {
                                    let message = format!(
                                        "Dot matching is currently {} in {}.",
                                        if chan.dot { "enabled" } else { "not enabled" },
                                        msg.channel_login
                                    );
                                    try_respond(
                                        &client,
                                        msg.channel_login.as_str(),
                                        message.as_str(),
                                        msg.message_id.as_str(),
                                    )
                                    .await;
                                } else if let Some(dot) = parse_bool(args).await {
                                    let mut chan = chan.clone();
                                    chan.dot = dot;
                                    if let Err(e) = db.set_channel(&chan).await {
                                        error!("Error setting channel: {}", e);
                                        try_respond(&client, msg.channel_login.as_str(), "Could not update channel dot setting! Please report this error.", msg.message_id.as_str()).await;
                                    }
                                }
                            }
                            "subdomains" => {
                                if args.is_empty() {
                                    let message = format!(
                                        "Subdomain matching is currently {} in {}.",
                                        if chan.subdomains {
                                            "enabled"
                                        } else {
                                            "not enabled"
                                        },
                                        msg.channel_login
                                    );
                                    try_respond(
                                        &client,
                                        msg.channel_login.as_str(),
                                        message.as_str(),
                                        msg.message_id.as_str(),
                                    )
                                    .await;
                                } else if let Some(subdomains) = parse_bool(args).await {
                                    let mut chan = chan.clone();
                                    chan.subdomains = subdomains;
                                    if let Err(e) = db.set_channel(&chan).await {
                                        error!("Error setting channel: {}", e);
                                        try_respond(&client, msg.channel_login.as_str(), "Could not update channel subdomains setting! Please report this error.", msg.message_id.as_str()).await;
                                    }
                                }
                            }
                            "role" => {
                                if args.is_empty() {
                                    let message = format!(
                                        "The current allowed user role in {} is {}",
                                        msg.channel_login, chan.userlevel
                                    );
                                    try_respond(
                                        &client,
                                        msg.channel_login.as_str(),
                                        message.as_str(),
                                        msg.message_id.as_str(),
                                    )
                                    .await;
                                } else if let Ok(role) = UserRole::from_str(args) {
                                    let mut chan = chan.clone();
                                    chan.userlevel = role;
                                    if let Err(e) = db.set_channel(&chan).await {
                                        error!("Error setting channel: {}", e);
                                        try_respond(&client, msg.channel_login.as_str(), "Could not update channel role setting! Please report this error.", msg.message_id.as_str()).await;
                                    }
                                }
                            }
                            "reply" => {
                                // If no reply is specified, output the current reply; otherwise, set the reply from args
                                if args.is_empty() {
                                    let message = format!(
                                        "Current reply in {}: {}",
                                        chan.name,
                                        generate_reply(&chan.reply, msg.sender.name.as_str())
                                    );
                                    try_respond(
                                        &client,
                                        msg.channel_login.as_str(),
                                        message.as_str(),
                                        msg.message_id.as_str(),
                                    )
                                    .await;
                                } else {
                                    let mut chan = chan.clone();
                                    let bot_reply: String;
                                    if args.trim().to_lowercase() == "off" {
                                        chan.reply = "off".to_owned();
                                        bot_reply = "Replies disabled.".to_owned();
                                    } else if args.trim().to_lowercase() == "default" {
                                        chan.reply = "default".to_owned();
                                        bot_reply = format!(
                                            "Reply set to: {}",
                                            generate_reply(&chan.reply, msg.sender.name.as_str())
                                        );
                                    } else if !args.trim().to_lowercase().contains("__user__") {
                                        chan.reply = format!("{} __user__", args.trim());
                                        bot_reply = format!(
                                            "Reply set to: {}",
                                            generate_reply(&chan.reply, msg.sender.name.as_str())
                                        );
                                    } else {
                                        chan.reply = args.trim().to_owned();
                                        bot_reply = format!(
                                            "Reply set to: {}",
                                            generate_reply(&chan.reply, msg.sender.name.as_str())
                                        );
                                    }
                                    if let Err(e) = db.set_channel(&chan).await {
                                        error!("Error setting channel: {}", e);
                                        try_respond(&client, msg.channel_login.as_str(), "Could not update channel reply! Please report this error.", msg.message_id.as_str()).await;
                                    } else {
                                        try_respond(
                                            &client,
                                            msg.channel_login.as_str(),
                                            bot_reply.as_str(),
                                            msg.message_id.as_str(),
                                        )
                                        .await;
                                    }
                                }
                            }
                            "test" => {
                                // Detect any links in the message and reply to the user with the detected links
                                let message: String;
                                if let (Some(links), _) =
                                    libghirahim::extract_urls(ext, args, &chan).await
                                {
                                    message = format!(
                                        "Would have deleted for the following links: {}",
                                        links.join(", ")
                                    );
                                } else {
                                    message = "No blocked links detected.".to_owned();
                                }
                                try_respond(
                                    &client,
                                    msg.channel_login.as_str(),
                                    message.as_str(),
                                    msg.message_id.as_str(),
                                )
                                .await;
                            }
                            _ => (),
                        }
                    }
                }
                "!permit" => {
                    if !args.is_empty() {
                        let chan = match db.get_channel(&msg.channel_login).await {
                            Some(chan) => chan,
                            None => {
                                client.part(msg.channel_login);
                                return;
                            }
                        };
                        if let Err(e) = db.issue_permit(&chan, args).await {
                            error!("Error issuing permit: {}", e);
                            try_respond(
                                &client,
                                msg.channel_login.as_str(),
                                "Could not issue permit! Please report this error.",
                                msg.message_id.as_str(),
                            )
                            .await;
                        } else {
                            let reply = format!(
                                "Permit issued! {} will be allowed to send links for the next five minutes.",
                                args
                            );
                            try_respond(
                                &client,
                                msg.channel_login.as_str(),
                                reply.as_str(),
                                msg.message_id.as_str(),
                            )
                            .await;
                        }
                    }
                }
                _ => (),
            }
        } else {
            match command {
                "!join" => {
                    // Join the channel of the user who sent the message
                    client.join(msg.sender.login.clone());
                    // Don't bother adding the channel to the database if it's already there
                    if db.get_channel(&msg.sender.login).await.is_none() {
                        if let Err(e) = db
                            .set_channel(&libghirahim::Channel {
                                name: msg.sender.login.to_owned(),
                                ..Default::default()
                            })
                            .await
                        {
                            error!(
                                "Database error joining channel {}: {}",
                                &msg.sender.login, e
                            );
                            try_respond(
                                &client,
                                "ghirahim_bot",
                                "Error joining channel! Please report this error.",
                                msg.message_id.as_str(),
                            )
                            .await;
                        } else {
                            info!("Joined channel {}", &msg.sender.login);
                            try_respond(
                                &client,
                                "ghirahim_bot",
                                "Joined channel. Remember to set up your settings and allow list!",
                                msg.message_id.as_str(),
                            )
                            .await;
                        }
                    }
                }
                "!leave" => {
                    // Leave the channel of the user who sent the message
                    client.part(msg.sender.login.clone());
                    info!("Left channel {}", &msg.sender.login);
                    if let Some(chan) = db.get_channel(&msg.sender.login).await {
                        db.del_channel(&chan).await;
                        try_respond(
                            &client,
                            "ghirahim_bot",
                            "Left channel.",
                            msg.message_id.as_str(),
                        )
                        .await;
                    }
                }
                _ => (),
            }
        }
    }
}

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

    // Set up the IRC config based on the config file
    let login_name = config["ghirahim"]["username"].as_str().unwrap().to_owned();
    let oauth_token = config["ghirahim"]["password"].as_str().unwrap().to_owned();
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
    let db = GhirahimDB::new(mongo_str, &redis_str)
        .await
        .expect("Could not get database");

    // Get the list of all the channels we're supposed to be in
    let mut channels = db.get_all_channels().await.unwrap();
    // Insert the bot's own channel
    channels.insert("ghirahim_bot".to_owned());
    // Set the list of wanted channels to the channels from the DB plus the bot's own channel
    client.set_wanted_channels(channels);

    // Set up logging (based on https://www.lpalmieri.com/posts/2020-09-27-zero-to-production-4-are-we-observable-yet/)
    LogTracer::init().expect("Failed to set logger");
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let formatting_layer = BunyanFormattingLayer::new("ghirahim_bot".into(), std::io::stdout);
    let subscriber = Registry::default()
        .with(env_filter)
        .with(JsonStorageLayer)
        .with(formatting_layer);
    set_global_default(subscriber).expect("Failed to set subscriber");

    // Set up the actual event loop
    let join_handle = tokio::spawn(async move {
        info!("Started Ghirahim_Bot and connected to Twitch.");
        while let Some(message) = incoming_messages.recv().await {
            match message {
                ServerMessage::Privmsg(message) => {
                    trace!("Received privmsg: {:?}", message);
                    let user_role = libghirahim::parse_badges(message.badges.clone());
                    if (user_role >= UserRole::MODERATOR)
                        || (message.channel_login == "ghirahim_bot")
                    {
                        if let Some(chan) = db.get_channel(&message.channel_login).await {
                            let cooldown_status = db.check_channel_cooldown(&chan).await;
                            if let Err(e) = cooldown_status {
                                error!("Database error when checking cooldown: {}", e);
                            } else if !cooldown_status.unwrap()  {
                                handle_command(&db, message, client.clone(), &ext).await;
                            }
                        }
                    } else if let Some(chan) = db.get_channel(&message.channel_login).await {
                        let cooldown_status = db.check_channel_cooldown(&chan).await;
                        if let Err(e) = cooldown_status {
                            error!("Database error when checking cooldown: {}", e);
                        } else if !cooldown_status.unwrap() {
                            let permitted =
                                match db.check_permit(&chan, &message.sender.login).await {
                                    Ok(permitted) => match permitted {
                                        true => true,
                                        false => {
                                            match db.check_permit(&chan, &message.sender.name).await
                                            {
                                                Ok(permitted) => permitted,
                                                Err(e) => {
                                                    error!("Database error checking permit: {}", e);
                                                    false
                                                }
                                            }
                                        }
                                    },
                                    Err(e) => {
                                        error!("Database error checking permit: {}", e);
                                        false
                                    }
                                };
                            if !permitted && user_role < chan.userlevel {
                                let (bad_links, bad_regexes) =
                                    libghirahim::extract_urls(&ext, &message.message_text, &chan)
                                        .await;
                                if let Some(bad_regexes) = bad_regexes {
                                    info!(
                                        "Removed the following regexes from {}: {:?}",
                                        chan.name, bad_regexes
                                    );
                                    let mut chan = chan.clone();
                                    chan.allow_list.retain(|x| !bad_regexes.contains(x));
                                    if let Err(e) = db.set_channel(&chan).await {
                                        error!(
                                            "Database error updating channel {}: {}",
                                            &message.channel_login, e
                                        );
                                    }
                                }
                                if bad_links.is_some() {
                                    trace!(
                                        "Deleting message in {} with ID {}",
                                        &message.channel_login,
                                        &message.message_id
                                    );
                                    try_send_privmsg(
                                        &client,
                                        message.channel_login.as_str(),
                                        format!("/delete {}", message.message_id).as_str(),
                                    )
                                    .await;
                                    let reply = generate_reply(&chan.reply, &message.sender.name);
                                    try_say(
                                        &client,
                                        message.channel_login.as_str(),
                                        reply.as_str(),
                                    )
                                    .await;
                                }
                            }
                        }
                    } else {
                        info!(
                            "Received message from unknown channel {}",
                            &message.channel_login
                        );
                        client.part(message.channel_login.clone());
                    }
                }
                ServerMessage::Notice(message) => {
                    if let Some(message_id) = message.message_id.clone() {
                        if LEAVE_NOTICES.contains(&message_id.as_str()) {
                            error!("Received notice in leave list: {:?}", message);
                            let channel_login = message.channel_login.unwrap();
                            client.part(channel_login.clone());
                            if let Some(chan) = db.get_channel(&channel_login).await {
                                db.del_channel(&chan).await;
                            }
                        } else if COOLDOWN_NOTICES.contains(&message_id.as_str()) {
                            error!("Received notice in cooldown list: {:?}", message);
                            let channel_login = message.channel_login.unwrap();
                            if let Some(chan) = db.get_channel(&channel_login).await {
                                if let Err(e) = db.set_channel_cooldown(&chan).await {
                                    error!("Database error setting cooldown: {}", e);
                                }
                            } else {
                                client.part(channel_login.clone());
                            }
                        }
                    }
                }
                _ => trace!("Received message: {:?}", message),
            }
        }
    });

    // Start the bot
    join_handle.await.unwrap();
}
