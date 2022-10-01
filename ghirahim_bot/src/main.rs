use governor::{Quota, RateLimiter};
use lazy_static::lazy_static;
use libghirahim::{GhirahimDB, UserRole};
use nonzero_ext::*;
use std::borrow::Cow;
use std::fs::File;
use std::io::prelude::*;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tldextract::{TldExtractor, TldOption};
use tokio::sync::Semaphore;
use twitch_irc::login::StaticLoginCredentials;
use twitch_irc::message::{PrivmsgMessage, ServerMessage};
use twitch_irc::ClientConfig;
use twitch_irc::SecureWSTransport;
use twitch_irc::TwitchIRCClient;

use nom::{branch::alt, bytes::complete::tag_no_case, Finish};

use serde_json;

use tracing::{debug, error, info, instrument, subscriber::set_global_default, trace, warn};
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

const IGNORE_NOTICES: [&str; 25] = [
    "bad_delete_message_broadcaster",
    "bad_delete_message_mod",
    "ban_success",
    "delete_message_success",
    "emote_only_off",
    "emote_only_on",
    "followers_off",
    "followers_on",
    "followers_onzero",
    "host_off",
    "host_on",
    "host_success",
    "host_success_viewers",
    "host_target_went_offline",
    "hosts_remaining",
    "not_hosting",
    "r9k_off",
    "r9k_on",
    "slow_off",
    "slow_on",
    "subs_off",
    "subs_on",
    "timeout_success",
    "unban_success",
    "unmod_success",
];

fn get_ghirahim_rs_version() -> String {
    format!(
        "{}.{}.{}",
        pkg_version::pkg_version_major!(),
        pkg_version::pkg_version_minor!(),
        pkg_version::pkg_version_patch!()
    )
}

#[instrument(level = "trace")]
async fn parse_command(args: &str) -> nom::IResult<&str, &str> {
    alt((
        tag_no_case("!links"),
        tag_no_case("!permit"),
        tag_no_case("!join"),
        tag_no_case("!leave"),
        tag_no_case("!version"),
    ))(args.trim())
}

#[instrument(level = "trace")]
async fn parse_command_links(args: &str) -> nom::IResult<&str, &str> {
    alt((
        tag_no_case("list"),
        tag_no_case("allow"),
        tag_no_case("add"),
        tag_no_case("deny"),
        tag_no_case("del"),
        tag_no_case("remove"),
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
fn generate_reply(reply_str: &str, user: &str) -> Option<String> {
    if reply_str == "default" {
        Some(format!(
            "@{}, please ask for permission before posting a link.",
            user
        ))
    } else if reply_str == "off" {
        None
    } else {
        Some(reply_str.replace("__user__", user))
    }
}

#[instrument(level = "debug")]
async fn try_send_privmsg<
    T: twitch_irc::transport::Transport,
    L: twitch_irc::login::LoginCredentials,
    S: governor::state::StateStore<Key = governor::state::NotKeyed> + std::fmt::Debug,
    C: governor::clock::Clock + governor::clock::ReasonablyRealtime + std::fmt::Debug,
>(
    client: &TwitchIRCClient<T, L>,
    channel: &str,
    msg_contents: &str,
    limiter: Arc<
        RateLimiter<
            governor::state::NotKeyed,
            S,
            C,
            governor::middleware::NoOpMiddleware<C::Instant>,
        >,
    >,
) {
    limiter.until_ready().await;
    if client
        .privmsg(channel.to_owned(), msg_contents.to_owned())
        .await
        .is_err()
    {
        if let Err(e) = client
            .privmsg(channel.to_owned(), msg_contents.to_owned())
            .await
        {
            warn!("Error sending message: {}", e);
        }
    }
}

#[instrument(level = "debug")]
async fn try_say<
    T: twitch_irc::transport::Transport,
    L: twitch_irc::login::LoginCredentials,
    S: governor::state::StateStore<Key = governor::state::NotKeyed> + std::fmt::Debug,
    C: governor::clock::Clock + governor::clock::ReasonablyRealtime + std::fmt::Debug,
>(
    client: &TwitchIRCClient<T, L>,
    channel: &str,
    msg_contents: &str,
    limiter: Arc<
        RateLimiter<
            governor::state::NotKeyed,
            S,
            C,
            governor::middleware::NoOpMiddleware<C::Instant>,
        >,
    >,
) {
    limiter.until_ready().await;
    if client
        .say(channel.to_owned(), msg_contents.to_owned())
        .await
        .is_err()
    {
        if let Err(e) = client
            .say(channel.to_owned(), msg_contents.to_owned())
            .await
        {
            warn!("Error sending message: {}", e);
        }
    }
}

#[instrument(level = "debug")]
async fn try_respond<
    T: twitch_irc::transport::Transport,
    L: twitch_irc::login::LoginCredentials,
    S: governor::state::StateStore<Key = governor::state::NotKeyed> + std::fmt::Debug,
    C: governor::clock::Clock + governor::clock::ReasonablyRealtime + std::fmt::Debug,
>(
    client: &TwitchIRCClient<T, L>,
    channel: &str,
    msg_contents: &str,
    msg_id: &str,
    limiter: Arc<
        RateLimiter<
            governor::state::NotKeyed,
            S,
            C,
            governor::middleware::NoOpMiddleware<C::Instant>,
        >,
    >,
) {
    limiter.until_ready().await;
    if client
        .say_in_response(
            channel.to_owned(),
            msg_contents.to_owned(),
            Some(msg_id.to_owned()),
        )
        .await
        .is_err()
    {
        if let Err(e) = client
            .say_in_response(
                channel.to_owned(),
                msg_contents.to_owned(),
                Some(msg_id.to_owned()),
            )
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
    S: governor::state::StateStore<Key = governor::state::NotKeyed> + std::fmt::Debug,
    C: governor::clock::Clock + governor::clock::ReasonablyRealtime + std::fmt::Debug,
>(
    client: &TwitchIRCClient<T, L>,
    message: &PrivmsgMessage,
    chan: &libghirahim::Channel,
    limiter: Arc<
        RateLimiter<
            governor::state::NotKeyed,
            S,
            C,
            governor::middleware::NoOpMiddleware<C::Instant>,
        >,
    >,
) {
    // Print the list of allowed links in the channel
    let reply = format!(
        "Allowed links in {}: {}",
        chan.name,
        chan.allow_list.join(", ")
    );
    try_respond(
        client,
        message.channel_login.as_str(),
        reply.as_str(),
        message.message_id.as_str(),
        limiter,
    )
    .await;
}

#[instrument(skip(ext), level = "debug")]
async fn handle_command<
    T: twitch_irc::transport::Transport,
    L: twitch_irc::login::LoginCredentials,
    S: governor::state::StateStore<Key = governor::state::NotKeyed> + std::fmt::Debug,
    C: governor::clock::Clock + governor::clock::ReasonablyRealtime + std::fmt::Debug,
>(
    db: &GhirahimDB,
    privmsg: PrivmsgMessage,
    client: TwitchIRCClient<T, L>,
    ext: &TldExtractor,
    limiter: Arc<
        RateLimiter<
            governor::state::NotKeyed,
            S,
            C,
            governor::middleware::NoOpMiddleware<C::Instant>,
        >,
    >,
) {
    let logon_name;
    {
        let r = BOT_CONFIG.read().unwrap();
        logon_name = r.logon_name.clone();
    }
    if let Ok((args, command)) = parse_command(privmsg.message_text.as_str()).await.finish() {
        if privmsg.channel_login != logon_name {
            match command {
                "!links" => {
                    let chan = match db.get_channel(&privmsg.channel_login).await {
                        Some(chan) => chan,
                        None => {
                            client.part(privmsg.channel_login);
                            return;
                        }
                    };
                    if let Ok((args, command)) = parse_command_links(args).await.finish() {
                        match command {
                            "list" => {
                                send_channel_list(&client, &privmsg, &chan, limiter.clone()).await
                            }
                            "allow" | "add" => {
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
                                        try_respond(
                                            &client,
                                            privmsg.channel_login.as_str(),
                                            "Could not update channel allow list! Please report this error.",
                                            privmsg.message_id.as_str(),
                                            limiter.clone(),
                                        ).await;
                                    } else {
                                        send_channel_list(
                                            &client,
                                            &privmsg,
                                            &chan,
                                            limiter.clone(),
                                        )
                                        .await;
                                    }
                                }
                            }
                            "deny" | "del" | "remove" => {
                                if !args.is_empty() {
                                    let domains: Vec<&str> = args.split_whitespace().collect();
                                    let mut chan = chan.clone();
                                    chan.allow_list.retain(|x| !domains.contains(&x.as_str()));
                                    if let Err(e) = db.set_channel(&chan).await {
                                        error!("Error setting channel: {}", e);
                                        try_respond(
                                            &client,
                                            privmsg.channel_login.as_str(),
                                            "Could not update channel allow list! Please report this error.",
                                            privmsg.message_id.as_str(),
                                            limiter.clone(),
                                        ).await;
                                    } else {
                                        send_channel_list(
                                            &client,
                                            &privmsg,
                                            &chan,
                                            limiter.clone(),
                                        )
                                        .await;
                                    }
                                }
                            }
                            "slash" => {
                                let mut enabled =
                                    if chan.slash { "enabled" } else { "not enabled" };
                                if let Some(slash) = parse_bool(args).await {
                                    let mut chan = chan.clone();
                                    chan.slash = slash;
                                    enabled = if slash { "enabled" } else { "not enabled" };
                                    if let Err(e) = db.set_channel(&chan).await {
                                        error!("Error setting channel: {}", e);
                                        try_respond(
                                            &client,
                                            privmsg.channel_login.as_str(),
                                            "Could not update channel slash setting! Please report this error.",
                                            privmsg.message_id.as_str(),
                                            limiter.clone(),
                                        ).await;
                                    }
                                }
                                // Always print the current setting
                                let message = format!(
                                    "Slash matching is currently {} in {}.",
                                    enabled, privmsg.channel_login
                                );
                                try_respond(
                                    &client,
                                    privmsg.channel_login.as_str(),
                                    message.as_str(),
                                    privmsg.message_id.as_str(),
                                    limiter.clone(),
                                )
                                .await;
                            }
                            "dot" => {
                                let mut enabled = if chan.dot { "enabled" } else { "not enabled" };
                                if let Some(dot) = parse_bool(args).await {
                                    let mut chan = chan.clone();
                                    chan.dot = dot;
                                    enabled = if dot { "enabled" } else { "not enabled" };
                                    if let Err(e) = db.set_channel(&chan).await {
                                        error!("Error setting channel: {}", e);
                                        try_respond(
                                            &client,
                                            privmsg.channel_login.as_str(),
                                            "Could not update channel dot setting! Please report this error.",
                                            privmsg.message_id.as_str(),
                                            limiter.clone(),
                                        ).await;
                                    }
                                }
                                let message = format!(
                                    "Dot matching is currently {} in {}.",
                                    enabled, privmsg.channel_login
                                );
                                try_respond(
                                    &client,
                                    privmsg.channel_login.as_str(),
                                    message.as_str(),
                                    privmsg.message_id.as_str(),
                                    limiter.clone(),
                                )
                                .await;
                            }
                            "subdomains" => {
                                let mut enabled = if chan.subdomains {
                                    "enabled"
                                } else {
                                    "not enabled"
                                };
                                if let Some(subdomains) = parse_bool(args).await {
                                    let mut chan = chan.clone();
                                    chan.subdomains = subdomains;
                                    enabled = if subdomains { "enabled" } else { "not enabled" };
                                    if let Err(e) = db.set_channel(&chan).await {
                                        error!("Error setting channel: {}", e);
                                        try_respond(
                                            &client,
                                            privmsg.channel_login.as_str(),
                                            "Could not update channel subdomains setting! Please report this error.",
                                            privmsg.message_id.as_str(),
                                            limiter.clone()).await;
                                    }
                                }
                                let message = format!(
                                    "Subdomain matching is currently {} in {}.",
                                    enabled, privmsg.channel_login
                                );
                                try_respond(
                                    &client,
                                    privmsg.channel_login.as_str(),
                                    message.as_str(),
                                    privmsg.message_id.as_str(),
                                    limiter.clone(),
                                )
                                .await;
                            }
                            "role" => {
                                let mut msg_role = chan.userlevel;
                                if let Ok(role) =
                                    UserRole::from_str(args.trim().to_uppercase().as_str())
                                {
                                    let mut chan = chan.clone();
                                    chan.userlevel = role;
                                    msg_role = role;
                                    if let Err(e) = db.set_channel(&chan).await {
                                        error!("Error setting channel: {}", e);
                                        try_respond(
                                            &client,
                                            privmsg.channel_login.as_str(),
                                            "Could not update channel role setting! Please report this error.",
                                            privmsg.message_id.as_str(),
                                            limiter.clone(),
                                        ).await;
                                    }
                                }
                                let message = format!(
                                    "The current allowed user role in {} is {}",
                                    privmsg.channel_login, msg_role
                                );
                                try_respond(
                                    &client,
                                    privmsg.channel_login.as_str(),
                                    message.as_str(),
                                    privmsg.message_id.as_str(),
                                    limiter.clone(),
                                )
                                .await;
                            }
                            "reply" => {
                                // If no reply is specified, output the current reply; otherwise, set the reply from args
                                if args.is_empty() {
                                    let message = if let Some(reply) =
                                        generate_reply(&chan.reply, privmsg.sender.name.as_str())
                                    {
                                        format!("Current reply in {}: {}", chan.name, reply)
                                    } else {
                                        format!("Replies currently disabled in {}", chan.name)
                                    };
                                    try_respond(
                                        &client,
                                        privmsg.channel_login.as_str(),
                                        message.as_str(),
                                        privmsg.message_id.as_str(),
                                        limiter.clone(),
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
                                            generate_reply(
                                                &chan.reply,
                                                privmsg.sender.name.as_str()
                                            )
                                            .unwrap()
                                        );
                                    } else if !args.trim().to_lowercase().contains("__user__") {
                                        chan.reply = format!("{} __user__", args.trim());
                                        bot_reply = format!(
                                            "Reply set to: {}",
                                            generate_reply(
                                                &chan.reply,
                                                privmsg.sender.name.as_str()
                                            )
                                            .unwrap()
                                        );
                                    } else {
                                        chan.reply = args.trim().to_owned();
                                        bot_reply = format!(
                                            "Reply set to: {}",
                                            generate_reply(
                                                &chan.reply,
                                                privmsg.sender.name.as_str()
                                            )
                                            .unwrap()
                                        );
                                    }
                                    if let Err(e) = db.set_channel(&chan).await {
                                        error!("Error setting channel: {}", e);
                                        try_respond(
                                            &client,
                                            privmsg.channel_login.as_str(),
                                            "Could not update channel reply! Please report this error.",
                                            privmsg.message_id.as_str(), limiter.clone(),
                                        ).await;
                                    } else {
                                        try_respond(
                                            &client,
                                            privmsg.channel_login.as_str(),
                                            bot_reply.as_str(),
                                            privmsg.message_id.as_str(),
                                            limiter.clone(),
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
                                    privmsg.channel_login.as_str(),
                                    message.as_str(),
                                    privmsg.message_id.as_str(),
                                    limiter.clone(),
                                )
                                .await;
                            }
                            _ => (),
                        }
                    }
                }
                "!permit" => {
                    if !args.is_empty() {
                        let chan = match db.get_channel(&privmsg.channel_login).await {
                            Some(chan) => chan,
                            None => {
                                client.part(privmsg.channel_login);
                                return;
                            }
                        };
                        if let Err(e) = db.issue_permit(&chan, args.trim()).await {
                            error!("Error issuing permit: {}", e);
                            try_respond(
                                &client,
                                privmsg.channel_login.as_str(),
                                "Could not issue permit! Please report this error.",
                                privmsg.message_id.as_str(),
                                limiter.clone(),
                            )
                            .await;
                        } else {
                            let reply = format!(
                                "Permit issued! {} will be allowed to send links for the next five minutes.",
                                args
                            );
                            try_respond(
                                &client,
                                privmsg.channel_login.as_str(),
                                reply.as_str(),
                                privmsg.message_id.as_str(),
                                limiter.clone(),
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
                    if let Err(e) = client.join(privmsg.sender.login.clone()) {
                        error!("IRC error joining channel {}: {}", &privmsg.sender.login, e);
                        try_respond(
                            &client,
                            logon_name.as_str(),
                            "Error joining channel! Please report this error.",
                            privmsg.message_id.as_str(),
                            limiter.clone(),
                        )
                        .await;
                        return;
                    }
                    // Don't bother adding the channel to the database if it's already there
                    if db.get_channel(&privmsg.sender.login).await.is_none() {
                        if let Err(e) = db
                            .set_channel(&libghirahim::Channel {
                                name: privmsg.sender.login.to_owned(),
                                ..Default::default()
                            })
                            .await
                        {
                            error!(
                                "Database error joining channel {}: {}",
                                &privmsg.sender.login, e
                            );
                            try_respond(
                                &client,
                                logon_name.as_str(),
                                "Error joining channel! Please report this error.",
                                privmsg.message_id.as_str(),
                                limiter.clone(),
                            )
                            .await;
                        } else {
                            info!("Joined channel {}", &privmsg.sender.login);
                            try_respond(
                                &client,
                                logon_name.as_str(),
                                "Joined channel. Remember to set up your settings and allow list!",
                                privmsg.message_id.as_str(),
                                limiter.clone(),
                            )
                            .await;
                        }
                    }
                }
                "!leave" => {
                    // Leave the channel of the user who sent the message
                    client.part(privmsg.sender.login.clone());
                    info!("Left channel {}", &privmsg.sender.login);
                    if let Some(chan) = db.get_channel(&privmsg.sender.login).await {
                        db.del_channel(&chan).await;
                        try_respond(
                            &client,
                            logon_name.as_str(),
                            "Left channel.",
                            privmsg.message_id.as_str(),
                            limiter.clone(),
                        )
                        .await;
                    }
                }
                "!version" => {
                    // Reply with the version of the bot and the library
                    let reply = format!("Ghirahim_Bot, running ghirahim_rs version {} backed by version {} of libghirahim.", get_ghirahim_rs_version(), libghirahim::get_libghirahim_version());
                    try_respond(
                        &client,
                        logon_name.as_str(),
                        reply.as_str(),
                        privmsg.message_id.as_str(),
                        limiter.clone(),
                    )
                    .await;
                }
                _ => (),
            }
        }
    }
}

#[derive(Debug, Clone)]
struct BotConfig {
    logon_name: String,
    moderator_id: String,
    client_id: String,
    token: String,
}

lazy_static! {
    static ref BOT_CONFIG: std::sync::RwLock<BotConfig> = std::sync::RwLock::new(BotConfig {
        logon_name: "uninitialized".to_owned(),
        moderator_id: "uninitialized".to_owned(),
        client_id: "uninitialized".to_owned(),
        token: "uninitialized".to_owned(),
    });
}

#[tokio::main]
pub async fn main() {
    // Set up logging (based on https://www.lpalmieri.com/posts/2020-09-27-zero-to-production-4-are-we-observable-yet/)
    LogTracer::init().expect("Failed to set logger");
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let formatting_layer = BunyanFormattingLayer::new("ghirahim_bot".into(), std::io::stdout);
    let subscriber = Registry::default()
        .with(env_filter)
        .with(JsonStorageLayer)
        .with(formatting_layer);
    set_global_default(subscriber).expect("Failed to set subscriber");
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

    let logon_name: String;
    let client_id: String;
    let oauth_token: String;
    // Initialize our login name and client ID, for use in other functions
    {
        let mut w = BOT_CONFIG.write().unwrap();
        w.logon_name = config["ghirahim"]["username"].as_str().unwrap().to_owned();
        w.client_id = config["ghirahim"]["client_id"].as_str().unwrap().to_owned();
        w.token = config["ghirahim"]["password"].as_str().unwrap().to_owned();
        logon_name = w.logon_name.clone();
        client_id = w.client_id.clone();
        oauth_token = w.token.clone();
    }

    // set up the TLD list
    let temp_folder = tempfile::tempdir().expect("Couldn't create temporary folder");
    let option = TldOption::default()
        .cache_path(&(temp_folder.path().to_str().unwrap().to_owned() + ".tldcache"))
        .private_domains(false)
        .update_local(true)
        .naive_mode(false);
    let ext = TldExtractor::new(option);

    // Set up the IRC config based on the config file
    let login_name = config["ghirahim"]["username"].as_str().unwrap().to_owned();
    let irc_config = ClientConfig {
        login_credentials: StaticLoginCredentials::new(login_name, Some(oauth_token.clone())),
        metrics_identifier: Some(Cow::from("Ghirahim_Bot")), // Collect metrics; these will be exported with the prometheus exporter we set up above
        connection_rate_limiter: Arc::new(Semaphore::new(2)), // Open two connections at once, if necessary
        ..Default::default()
    };

    // Set up the rate limiter
    // This is set to 200 in 60 seconds, which *will* get us rate limited in the worst case (as long as we're not verified)
    // But it's useful for metrics, and verification practically requires getting rate limited (thanks, Twitch)
    let limiter = Arc::new(RateLimiter::direct(Quota::per_minute(nonzero!(200u32))));

    // Set up the IRC client
    let (mut incoming_messages, client) =
        TwitchIRCClient::<SecureWSTransport, StaticLoginCredentials>::new(irc_config);

    // Set up metrics if GHIRAHIM_METRICS is set
    if std::env::var("GHIRAHIM_METRICS").is_ok() {
        metrics_exporter_prometheus::PrometheusBuilder::new()
            .with_http_listener(
                config["metrics"]["bind_addr"]
                    .as_str()
                    .unwrap()
                    .parse::<std::net::SocketAddr>()
                    .unwrap(),
            )
            .install()
            .expect("Failed to install metrics");
        info!(
            "Metrics set up and bound to {}",
            config["metrics"]["bind_addr"].as_str().unwrap()
        );
    }

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
    channels.insert(logon_name.clone());
    // Set the list of wanted channels to the channels from the DB plus the bot's own channel
    // If this fails, we want to panic; the bot doesn't work if it can't join any channels
    client.set_wanted_channels(channels).unwrap();

    // Get our user ID from helix; also serves as a check to make sure the client ID is correct
    // Limit the scope here so we don't keep too many unnecessary variables around
    let rest_client;
    let moderator_id: String;
    {
        let mut w = BOT_CONFIG.write().unwrap();

        // Set up headers
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(reqwest::header::USER_AGENT, format!("Ghirahim_Bot/{}", get_ghirahim_rs_version()).parse().unwrap());
        headers.insert::<reqwest::header::HeaderName>(
            "Client-Id".parse().unwrap(),
            client_id.parse().unwrap(),
        );

        // Set up the client
        let temp_client = reqwest::Client::builder()
            .default_headers(headers)
            .build()
            .unwrap();
        rest_client = tower::ServiceBuilder::new()
            .rate_limit(600, Duration::from_secs(60))
            .service(temp_client);

        // Set up the params
        let params = vec![("login", logon_name.clone())];

        // Get the response
        let resp = rest_client
            .get_ref()
            .get("https://api.twitch.tv/helix/users")
            .query(&params)
            .bearer_auth(&oauth_token)
            .send()
            .await
            .unwrap();

        if !resp.status().is_success() {
            panic!("Could not get moderator ID! {}", &resp.text().await.unwrap());
        }

        let json_resp: serde_json::Value =
            serde_json::from_str(&resp.text().await.unwrap()).unwrap();

        w.moderator_id = json_resp["data"][0]["id"].as_str().unwrap().to_string();
        moderator_id = w.moderator_id.clone();
    }

    // Set up the actual event loop
    let join_handle = tokio::spawn(async move {
        info!("Started Ghirahim_Bot and connected to Twitch.");
        while let Some(message) = incoming_messages.recv().await {
            match message {
                ServerMessage::Privmsg(message) => {
                    trace!("Received privmsg: {:?}", message);
                    let user_role = libghirahim::parse_badges(message.badges.clone());
                    if (user_role >= UserRole::MODERATOR) || (message.channel_login == logon_name) {
                        if let Some(chan) = db.get_channel(&message.channel_login).await {
                            let cooldown_status = db.check_channel_cooldown(&chan).await;
                            if let Err(e) = cooldown_status {
                                error!("Database error when checking cooldown: {}", e);
                            } else if !cooldown_status.unwrap() {
                                handle_command(&db, message, client.clone(), &ext, limiter.clone())
                                    .await;
                            }
                        } else if message.channel_login == logon_name {
                            handle_command(&db, message, client.clone(), &ext, limiter.clone())
                                .await;
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
                                    } else {
                                        let chat_message = format!(
                                            "Removed the following regexes from {}: {:?}",
                                            chan.name, bad_regexes
                                        );
                                        try_say(
                                            &client,
                                            &message.channel_login,
                                            chat_message.as_str(),
                                            limiter.clone(),
                                        )
                                        .await;
                                    }
                                }
                                if bad_links.is_some() {
                                    trace!(
                                        "Deleting message in {} with ID {}",
                                        &message.channel_login,
                                        &message.message_id
                                    );
                                    
                                    // Delete the message through Helix
                                    let params = vec![("broadcaster_id", &message.channel_id),
                                                                            ("moderator_id", &moderator_id),
                                                                            ("message_id", &message.message_id)];
                                    let resp = rest_client
                                        .get_ref()
                                        .delete("https://api.twitch.tv/helix/moderation/chat")
                                        .query(&params)
                                        .bearer_auth(&oauth_token)
                                        .send()
                                        .await
                                        .unwrap();

                                    debug!("Sent request: {:#?}", resp);

                                    if resp.status().as_u16() == 403 {
                                        error!("Received 403 for {} while trying to delete message", message.channel_login);
                                        if let Some(chan) = db.get_channel(&message.channel_login).await {
                                            if let Err(e) = db.set_channel_cooldown(&chan).await {
                                                error!("Database error setting cooldown: {}", e);
                                            }
                                        } else {
                                            client.part(message.channel_login.clone());
                                        }
                                    }
                                    else if resp.status().is_client_error() {
                                        error!("Client error while deleting message: {:?} ({})", resp.status(), resp.text().await.unwrap());
                                    } else if resp.status().is_server_error() {
                                        warn!("Server error while deleting message: {:?} ({})", resp.status(), resp.text().await.unwrap());
                                    }

                                    let reply = generate_reply(&chan.reply, &message.sender.name);
                                    if let Some(reply) = reply {
                                        try_say(
                                            &client,
                                            message.channel_login.as_str(),
                                            reply.as_str(),
                                            limiter.clone(),
                                        )
                                        .await;
                                    }
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
                        } else if !IGNORE_NOTICES.contains(&message_id.as_str()) {
                            info!("Received unknown notice: {:?}", message);
                        }
                    } else {
                        info!("Received unknown notice: {:?}", message);
                    }
                }
                _ => debug!("Received message: {:?}", message),
            }
        }
    });

    // Start the bot
    join_handle.await.unwrap();
}
