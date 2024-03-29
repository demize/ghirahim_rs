use governor::{Quota, RateLimiter};
use lazy_static::lazy_static;
use libghirahim::{GhirahimDB, UserRole};
use nonzero_ext::*;
use prometheus::Encoder;
use std::fs::File;
use std::io::prelude::*;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use tldextract::{TldExtractor, TldOption};
use tokio::sync::Semaphore;
use twitch_irc::login::{LoginCredentials, RefreshingLoginCredentials};
use twitch_irc::message::{PrivmsgMessage, ServerMessage};
use twitch_irc::ClientConfig;
use twitch_irc::SecureWSTransport;
use twitch_irc::TwitchIRCClient;

use nom::{branch::alt, bytes::complete::tag_no_case, Finish};

use serde_json;

use prometheus::{register_counter_vec, Opts};

use tracing::{debug, error, info, instrument, subscriber::set_global_default, trace, warn};
use tracing_bunyan_formatter::{BunyanFormattingLayer, JsonStorageLayer};
use tracing_log::LogTracer;
use tracing_subscriber::{layer::SubscriberExt, EnvFilter, Registry};

mod tokens;
use tokens::JsonTokenStorage;

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
        .say_in_reply_to(
            &(channel.to_owned(), msg_id.to_owned()),
            msg_contents.to_owned(),
        )
        .await
        .is_err()
    {
        if let Err(e) = client
            .say_in_reply_to(
                &(channel.to_owned(), msg_id.to_owned()),
                msg_contents.to_owned(),
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

        if r.logon_name.is_none() {
            warn!(
                "Received message PRIVMSG before GLOBALUSERSTATE: {:#?}",
                privmsg
            );
            return;
        }
        logon_name = r.logon_name.clone().unwrap();
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
    logon_name: Option<String>,
    moderator_id: Option<String>,
}

lazy_static! {
    static ref BOT_CONFIG: std::sync::RwLock<BotConfig> = std::sync::RwLock::new(BotConfig {
        logon_name: None,
        moderator_id: None,
    });
}

// HTTP server for Prometheus
async fn serve_req(
    _req: hyper::Request<hyper::Body>,
) -> Result<hyper::Response<hyper::Body>, hyper::Error> {
    let encoder = prometheus::TextEncoder::new();
    let metric_families = prometheus::gather();
    let mut buffer = vec![];
    encoder.encode(&metric_families, &mut buffer).unwrap();

    let response = hyper::Response::builder()
        .status(200)
        .header(hyper::header::CONTENT_TYPE, encoder.format_type())
        .body(hyper::Body::from(buffer))
        .unwrap();

    Ok(response)
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

    // set up the TLD list
    let temp_folder = tempfile::tempdir().expect("Couldn't create temporary folder");
    let option = TldOption::default()
        .cache_path(&(temp_folder.path().to_str().unwrap().to_owned() + ".tldcache"))
        .private_domains(false)
        .update_local(true)
        .naive_mode(false);
    let ext = TldExtractor::new(option);

    // Set up the IRC config
    let client_id = config["ghirahim"]["client_id"].as_str().unwrap().to_owned();
    let client_secret = config["ghirahim"]["client_secret"]
        .as_str()
        .unwrap()
        .to_owned();
    let storage = JsonTokenStorage {};
    let creds = RefreshingLoginCredentials::init(client_id.clone(), client_secret, storage);

    // Set up the metrics config
    let metrics_config = twitch_irc::MetricsConfig::Enabled {
        constant_labels: [].into(),
        metrics_registry: None,
    };

    // Pass all that into a config itself
    let mut irc_config = ClientConfig::new_simple(creds.clone());
    irc_config.connection_rate_limiter = Arc::new(Semaphore::new(2));
    irc_config.metrics_config = metrics_config; // Some(Cow::from("Ghirahim_Bot"));

    // Set up the rate limiter
    // This is set to 200 in 60 seconds, which *will* get us rate limited in the worst case (as long as we're not verified)
    // But it's useful for metrics, and verification practically requires getting rate limited (thanks, Twitch)
    let limiter = Arc::new(RateLimiter::direct(Quota::per_minute(nonzero!(200u32))));

    // Set up the IRC client
    let (mut incoming_messages, client) = TwitchIRCClient::<
        SecureWSTransport,
        RefreshingLoginCredentials<JsonTokenStorage>,
    >::new(irc_config);

    // Set up our Helix metric. This needs to be done regardless of whether it'll get used.
    let helix_sent = register_counter_vec!(
        Opts::new(
            "ghirahim_helix_sent",
            "Number of commands sent to the Helix API."
        ),
        &["command"]
    )
    .unwrap();

    // Set up metrics if GHIRAHIM_METRICS is set
    if std::env::var("GHIRAHIM_METRICS").is_ok() {
        let bind_addr = config["metrics"]["bind_addr"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();
        let serve_future =
            hyper::Server::bind(&bind_addr).serve(hyper::service::make_service_fn(|_| async {
                Ok::<_, hyper::Error>(hyper::service::service_fn(serve_req))
            }));
        tokio::spawn(serve_future);
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
    let channels = db.get_all_channels().await.unwrap();
    // Set the list of wanted channels to the channels from the DB plus the bot's own channel
    // If this fails, we want to panic; the bot doesn't work if it can't join any channels
    client.set_wanted_channels(channels).unwrap();

    // Get our user ID from helix; also serves as a check to make sure the client ID is correct
    // Limit the scope here so we don't keep too many unnecessary variables around
    let rest_client;
    {
        let mut w = BOT_CONFIG.write().unwrap();

        // Set up headers
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::USER_AGENT,
            format!("Ghirahim_Bot/{}", get_ghirahim_rs_version())
                .parse()
                .unwrap(),
        );
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

        let mut resp_count = 0;
        let mut resp;
        loop {
            // Get our ID and login by validating our token
            resp = rest_client
                .get_ref()
                .get("https://id.twitch.tv/oauth2/validate")
                .bearer_auth(&creds.get_credentials().await.unwrap().token.unwrap())
                .send()
                .await
                .unwrap();
                
            if resp.status().is_success() {
                break;
            } else if resp.status().is_client_error() {
                panic!("Could not validate token! {}", &resp.text().await.unwrap())
            } else if resp.status().is_server_error() {
                warn!("Received a server error while validating token on initial startup: {}", &resp.text().await.unwrap());
                resp_count += 1;
                if resp_count >= 5 {
                    panic!("Received too many server errors. Panicing.");
                }
            } else {
                panic!("Received an unexpected response from the Twitch API: {}", &resp.text().await.unwrap())
            }
        }

        let json_resp: serde_json::Value =
            serde_json::from_str(&resp.text().await.unwrap()).unwrap();

        if !json_resp["scopes"].as_array().unwrap().iter().any(|s| {
            s == "chat:edit" || s == "chat:moderate" || s == "moderator:manage:chat_messages"
        }) {
            panic!("Token is missing necessary scopes. Scopes are {} but should include [\"chat:edit\", \"chat:read\", \"moderator:manage:chat_messages\"]", json_resp["scopes"]);
        }

        if json_resp["client_id"] != client_id {
            panic!("Token is issued for the wrong client ID");
        }

        w.moderator_id = Some(json_resp["user_id"].as_str().unwrap().to_string());
        w.logon_name = Some(json_resp["login"].as_str().unwrap().to_string());

        // Set up the params
        let params = vec![("user_id", w.moderator_id.clone().unwrap())];

        // Get the response
        let resp = rest_client
            .get_ref()
            .get("https://api.twitch.tv/helix/users")
            .query(&params)
            .bearer_auth(&creds.get_credentials().await.unwrap().token.unwrap())
            .send()
            .await
            .unwrap();

        // Increase the Helix counter
        if std::env::var("GHIRAHIM_METRICS").is_ok() {
            helix_sent.with_label_values(&["users"]).inc();
        }

        if !resp.status().is_success() {
            panic!("Helix check failed! {}", &resp.text().await.unwrap());
        }
    }

    let inner_creds = creds.clone();
    let inner_rest_client = rest_client.get_ref().clone();
    let cred_check_handle = tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(3600));
        loop {
            interval.tick().await;
            trace!("Checking token validity");
            let token = inner_creds
                .get_credentials()
                .await
                .expect("Could not get token")
                .token
                .unwrap();
            let resp = inner_rest_client
                .get("https://id.twitch.tv/oauth2/validate")
                .bearer_auth(&token)
                .send()
                .await
                .unwrap();

            if !resp.status().is_success() {
                if resp.status().is_server_error() {
                    warn!(
                        "Received a server error while validating token: {}",
                        &resp.text().await.unwrap()
                    );
                } else {
                    panic!(
                        "Could not validate token! {}",
                        &resp.text().await.unwrap()
                    );
                }
            }

            trace!("Token is valid");
        }
    });

    // Set up the actual event loop
    let join_handle = tokio::spawn(async move {
        info!("Started Ghirahim_Bot and connected to Twitch.");
        while let Some(message) = incoming_messages.recv().await {
            let logon_name: String;
            let moderator_id: String;
            {
                let r = BOT_CONFIG.read().unwrap();
                logon_name = r.logon_name.clone().unwrap();
                moderator_id = r.moderator_id.clone().unwrap();
            }
            match message {
                ServerMessage::GlobalUserState(message) => {
                    client
                        .join(message.user_name.to_ascii_lowercase())
                        .expect("Could not join own channel");
                }
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
                                    let params = vec![
                                        ("broadcaster_id", &message.channel_id),
                                        ("moderator_id", &moderator_id),
                                        ("message_id", &message.message_id),
                                    ];
                                    let resp = rest_client
                                        .get_ref()
                                        .delete("https://api.twitch.tv/helix/moderation/chat")
                                        .query(&params)
                                        .bearer_auth(
                                            &creds.get_credentials().await.unwrap().token.unwrap(),
                                        )
                                        .send()
                                        .await
                                        .unwrap();

                                    // Increase the Helix counter
                                    if std::env::var("GHIRAHIM_METRICS").is_ok() {
                                        helix_sent.with_label_values(&["delete"]).inc();
                                    }

                                    debug!("Sent request: {:#?}", resp);

                                    if resp.status().as_u16() == 403 {
                                        error!(
                                            "Received 403 for {} while trying to delete message",
                                            message.channel_login
                                        );
                                        if let Some(chan) =
                                            db.get_channel(&message.channel_login).await
                                        {
                                            if let Err(e) = db.set_channel_cooldown(&chan).await {
                                                error!("Database error setting cooldown: {}", e);
                                            }
                                        } else {
                                            client.part(message.channel_login.clone());
                                        }
                                    } else if resp.status().is_client_error() {
                                        error!(
                                            "Client error while deleting message: {:?} ({})",
                                            resp.status(),
                                            resp.text().await.unwrap()
                                        );
                                    } else if resp.status().is_server_error() {
                                        warn!(
                                            "Server error while deleting message: {:?} ({})",
                                            resp.status(),
                                            resp.text().await.unwrap()
                                        );
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

    // Start the handles
    tokio::try_join![join_handle, cred_check_handle].unwrap();
}
