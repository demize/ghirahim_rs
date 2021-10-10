pub mod ghirahim {
    use futures::future::Abortable;
    use mongodb::{Client, Collection, options::ClientOptions};
    use redis;
    use regex::{Error, Regex};
    use serde::{Deserialize, Serialize};
    use std::str::FromStr;
    use std::time::Duration;
    use strum;
    use tldextract::TldExtractor;
    use tokio::time::timeout;
    use twitch_irc::message::Badge;
    use url::Url;

    #[cfg(test)]
    mod tests {
        use super::*;
        use tempfile;
        use tldextract::TldOption;

        const MSG1: &str = "Benign message with no links.";
        const MSG2: &str = "Message with a link to example.org.";
        const MSG3: &str = "Message with a link to www.example.org.";
        const MSG4: &str = "Message with a link to www.example.org/index.html.";
        const MSG5: &str = "Message with a link to https://example.org.";
        const MSG6: &str = "Message with a link to https://example.com. How sneaky!";

        /// Test to ensure messages are detected correctly with the "slash" option.
        #[tokio::main]
        #[test]
        async fn test_with_slash() {
            // Set up the TldExtractor and a channel
            let temp_folder = tempfile::tempdir().expect("Couldn't create temporary folder");
            let option = TldOption {
                cache_path: Some(temp_folder.path().to_str().unwrap().to_owned() + "/.tldcache"),
                private_domains: false,
                update_local: true,
                naive_mode: false,
            };
            let ext = TldExtractor::new(option);
            let chan = Channel {
                name: "n/a".to_owned(),
                slash: true,
                dot: false,
                subdomains: false,
                userlevel: UserRole::MODERATOR,
                reply: "n/a".to_owned(),
                allow_list: Vec::new(),
            };

            // MSG1-3 should not be detected
            assert!(extract_urls(&ext, MSG1, &chan).await.0.is_none());
            assert!(extract_urls(&ext, MSG2, &chan).await.0.is_none());
            assert!(extract_urls(&ext, MSG3, &chan).await.0.is_none());
            // MSG4-6 all have slashes and should be detected
            let msg4_extracts = extract_urls(&ext, MSG4, &chan).await;
            assert!(msg4_extracts.0.is_some());
            assert_eq!(msg4_extracts.0.unwrap().len(), 1);
            let msg5_extracts = extract_urls(&ext, MSG5, &chan).await;
            assert!(msg5_extracts.0.is_some());
            assert_eq!(msg5_extracts.0.unwrap().len(), 1);
            let msg6_extracts = extract_urls(&ext, MSG6, &chan).await;
            assert!(msg6_extracts.0.is_some());
            assert_eq!(msg6_extracts.0.unwrap().len(), 1);
        }

        /// Test to ensure messages are detected correctly with the "dot" option.
        /// This also leaves "slash" enabled, because "dot" is designed to counteract some of
        /// slash and not to use on its own.
        #[tokio::main]
        #[test]
        async fn test_with_dot() {
            let temp_folder = tempfile::tempdir().expect("Couldn't create temporary folder");
            let option = TldOption {
                cache_path: Some(temp_folder.path().to_str().unwrap().to_owned() + "/.tldcache"),
                private_domains: false,
                update_local: true,
                naive_mode: false,
            };
            let ext = TldExtractor::new(option);
            let chan = Channel {
                name: "n/a".to_owned(),
                slash: true,
                dot: true,
                subdomains: false,
                userlevel: UserRole::MODERATOR,
                reply: "n/a".to_owned(),
                allow_list: Vec::new(),
            };

            // MSG1-2 still should not be detected
            assert!(extract_urls(&ext, MSG1, &chan).await.0.is_none());
            assert!(extract_urls(&ext, MSG2, &chan).await.0.is_none());
            // MSG 3-6 should be detected
            let msg3_extracts = extract_urls(&ext, MSG3, &chan).await;
            assert!(msg3_extracts.0.is_some());
            assert_eq!(msg3_extracts.0.unwrap().len(), 1);
            let msg4_extracts = extract_urls(&ext, MSG4, &chan).await;
            assert!(msg4_extracts.0.is_some());
            assert_eq!(msg4_extracts.0.unwrap().len(), 1);
            let msg5_extracts = extract_urls(&ext, MSG5, &chan).await;
            assert!(msg5_extracts.0.is_some());
            assert_eq!(msg5_extracts.0.unwrap().len(), 1);
            let msg6_extracts = extract_urls(&ext, MSG6, &chan).await;
            assert!(msg6_extracts.0.is_some());
            assert_eq!(msg6_extracts.0.unwrap().len(), 1);
        }

        /// Test to ensure messages are detected correctly with the "subdomains" option.
        #[tokio::main]
        #[test]
        async fn test_with_subdomains() {
            let temp_folder = tempfile::tempdir().expect("Couldn't create temporary folder");
            let option = TldOption {
                cache_path: Some(temp_folder.path().to_str().unwrap().to_owned() + "/.tldcache"),
                private_domains: false,
                update_local: true,
                naive_mode: false,
            };
            let ext = TldExtractor::new(option);
            // This channel needs an allow list to test the subdomains functionality properly
            let chan = Channel {
                name: "n/a".to_owned(),
                slash: false,
                dot: false,
                subdomains: true,
                userlevel: UserRole::MODERATOR,
                reply: "n/a".to_owned(),
                allow_list: Vec::from(["example.org".to_owned()]),
            };

            assert!(extract_urls(&ext, MSG1, &chan).await.0.is_none());
            assert!(extract_urls(&ext, MSG2, &chan).await.0.is_none());
            assert!(extract_urls(&ext, MSG3, &chan).await.0.is_none());
            assert!(extract_urls(&ext, MSG4, &chan).await.0.is_none());
            assert!(extract_urls(&ext, MSG5, &chan).await.0.is_none());
            // The only MSG we want to catch is MSG6
            let msg6_extracts = extract_urls(&ext, MSG6, &chan).await;
            assert!(msg6_extracts.0.is_some());
            assert_eq!(msg6_extracts.0.unwrap().len(), 1);
        }

        /// Test to make sure regular expressions work correctly.
        #[tokio::main]
        #[test]
        async fn test_with_regex() {
            let temp_folder = tempfile::tempdir().expect("Couldn't create temporary folder");
            let option = TldOption {
                cache_path: Some(temp_folder.path().to_str().unwrap().to_owned() + "/.tldcache"),
                private_domains: false,
                update_local: true,
                naive_mode: false,
            };
            let ext = TldExtractor::new(option);
            // The allow list here needs to have some regular expressions. The first one is to test
            // with our standard messages, but the second one is more realistic, so makes for an appropriate test case.
            let chan = Channel {
                name: "n/a".to_owned(),
                slash: false,
                dot: false,
                subdomains: true,
                userlevel: UserRole::MODERATOR,
                reply: "n/a".to_owned(),
                allow_list: Vec::from([
                    "/example.org/".to_owned(),
                    r"/(https?://)?(www\.)?youtube\.com/(channel|user)/[\w-]+/".to_owned(),
                ]),
            };

            assert!(extract_urls(&ext, MSG1, &chan).await.0.is_none());
            assert!(extract_urls(&ext, MSG2, &chan).await.0.is_none());
            assert!(extract_urls(&ext, MSG3, &chan).await.0.is_none());
            assert!(extract_urls(&ext, MSG4, &chan).await.0.is_none());
            assert!(extract_urls(&ext, MSG5, &chan).await.0.is_none());
            // We only want MSG6 to fail here
            let msg6_extracts = extract_urls(&ext, MSG6, &chan).await;
            assert!(msg6_extracts.0.is_some());
            assert_eq!(msg6_extracts.0.unwrap().len(), 1);

            // This usecase (and this friend) is actually why this feature exists!
            // So it feels like an appropriate test :)
            let msg7 = "Go check out my friend's youtube channel: https://www.youtube.com/channel/UClLvdEqehMKXtBzo-0ZatlQ";
            assert!(extract_urls(&ext, msg7, &chan).await.0.is_none());
        }

        /// Make sure that we catch URLs when none of the options are enabled.
        #[tokio::main]
        #[test]
        async fn test_with_none() {
            let temp_folder = tempfile::tempdir().expect("Couldn't create temporary folder");
            let option = TldOption {
                cache_path: Some(temp_folder.path().to_str().unwrap().to_owned() + "/.tldcache"),
                private_domains: false,
                update_local: true,
                naive_mode: false,
            };
            let ext = TldExtractor::new(option);
            let chan = Channel {
                name: "n/a".to_owned(),
                slash: false,
                dot: false,
                subdomains: false,
                userlevel: UserRole::MODERATOR,
                reply: "n/a".to_owned(),
                allow_list: Vec::new(),
            };

            // In this case we want them all to have links except for our control (MSG1)
            assert!(extract_urls(&ext, MSG1, &chan).await.0.is_none());
            let msg2_extracts = extract_urls(&ext, MSG2, &chan).await;
            assert!(msg2_extracts.0.is_some());
            assert_eq!(msg2_extracts.0.unwrap().len(), 1);
            let msg3_extracts = extract_urls(&ext, MSG3, &chan).await;
            assert!(msg3_extracts.0.is_some());
            assert_eq!(msg3_extracts.0.unwrap().len(), 1);
            let msg4_extracts = extract_urls(&ext, MSG4, &chan).await;
            assert!(msg4_extracts.0.is_some());
            assert_eq!(msg4_extracts.0.unwrap().len(), 1);
            let msg5_extracts = extract_urls(&ext, MSG5, &chan).await;
            assert!(msg5_extracts.0.is_some());
            assert_eq!(msg5_extracts.0.unwrap().len(), 1);
            let msg6_extracts = extract_urls(&ext, MSG6, &chan).await;
            assert!(msg6_extracts.0.is_some());
            assert_eq!(msg6_extracts.0.unwrap().len(), 1);
        }

        /// Test that we can detect multiple bad links.
        /// The bot doesn't *really* use the list, except in one minor feature, but we should
        /// test this anyway.
        #[tokio::main]
        #[test]
        async fn test_multiple_links() {
            let temp_folder = tempfile::tempdir().expect("Couldn't create temporary folder");
            let option = TldOption {
                cache_path: Some(temp_folder.path().to_str().unwrap().to_owned() + "/.tldcache"),
                private_domains: false,
                update_local: true,
                naive_mode: false,
            };
            let ext = TldExtractor::new(option);
            let chan = Channel {
                name: "n/a".to_owned(),
                slash: false,
                dot: false,
                subdomains: false,
                userlevel: UserRole::MODERATOR,
                reply: "n/a".to_owned(),
                allow_list: Vec::new(),
            };
            let msg = "This message has three whole links in it! http://example.org http://example.com http://example.co.uk";
            // Test once with an empty allow list
            assert_eq!(extract_urls(&ext, msg, &chan).await.0.unwrap().len(), 3);

            // Test once with a non-empty allow list
            let chan = Channel {
                name: "n/a".to_owned(),
                slash: false,
                dot: false,
                subdomains: true,
                userlevel: UserRole::MODERATOR,
                reply: "n/a".to_owned(),
                allow_list: Vec::from(["example.org".to_owned()]),
            };
            assert_eq!(extract_urls(&ext, msg, &chan).await.0.unwrap().len(), 2);
        }

        /// Basic test to make sure the UserRole enum is ordered correctly and can be
        /// built properly.
        #[test]
        fn test_enum_logic() {
            assert!(UserRole::BROADCASTER > UserRole::MODERATOR);
            assert!(UserRole::USER < UserRole::SUBSCRIBER);
            assert!(UserRole::VIP > UserRole::SUBSCRIBER);
            assert_eq!(UserRole::VIP.to_string(), "VIP");
            assert_eq!(
                UserRole::MODERATOR,
                UserRole::from_str("MODERATOR")
                    .expect("Could not convert to UserRole from a string")
            );
        }

        /// Test extracting roles from badges.
        #[test]
        fn test_badge_parsing() {
            let broadcaster_badges = [
                Badge {
                    name: "broadcaster".to_owned(),
                    version: "1".to_owned(),
                },
                Badge {
                    name: "subscriber".to_owned(),
                    version: "3000".to_owned(),
                },
                Badge {
                    name: "glitchcon2020".to_owned(),
                    version: "1".to_owned(),
                },
            ];
            let mod_badges = [
                Badge {
                    name: "moderator".to_owned(),
                    version: "1".to_owned(),
                },
                Badge {
                    name: "glitchcon2020".to_owned(),
                    version: "1".to_owned(),
                },
            ];
            let vip_badges = [Badge {
                name: "vip".to_owned(),
                version: "1".to_owned(),
            }];
            let subscriber_badges = [
                Badge {
                    name: "subscriber".to_owned(),
                    version: "3000".to_owned(),
                },
                Badge {
                    name: "glitchcon2020".to_owned(),
                    version: "1".to_owned(),
                },
            ];
            let user_badges = [Badge {
                name: "glitchcon2020".to_owned(),
                version: "1".to_owned(),
            }];
            assert_eq!(parse_badges(broadcaster_badges), UserRole::BROADCASTER);
            assert_eq!(parse_badges(mod_badges), UserRole::MODERATOR);
            assert_eq!(parse_badges(vip_badges), UserRole::VIP);
            assert_eq!(parse_badges(subscriber_badges), UserRole::SUBSCRIBER);
            assert_eq!(parse_badges(user_badges), UserRole::USER);
        }
    }

    /// Represents a user's role in chat.
    #[derive(
        PartialEq, PartialOrd, Debug, strum::EnumString, strum::Display, Serialize, Deserialize,
    )]
    pub enum UserRole {
        USER,
        SUBSCRIBER,
        VIP,
        MODERATOR,
        BROADCASTER,
    }

    /// Represents a Twitch channel the bot has joined.
    #[derive(Serialize, Deserialize)]
    pub struct Channel {
        pub name: String,
        pub slash: bool,
        pub dot: bool,
        pub subdomains: bool,
        pub userlevel: UserRole,
        pub reply: String,
        pub allow_list: Vec<String>,
    }

    /// Given the list of a user's Badges, return the highest role they represent.
    pub fn parse_badges(badges: impl IntoIterator<Item = Badge>) -> UserRole {
        let mut role = UserRole::USER;

        for badge in badges {
            let new_role = match badge.name.to_lowercase().as_str() {
                "broadcaster" => UserRole::BROADCASTER,
                "moderator" => UserRole::MODERATOR,
                "vip" => UserRole::VIP,
                "subscriber" => UserRole::SUBSCRIBER,
                _ => UserRole::USER,
            };
            if new_role > role {
                role = new_role;
            }
        }

        role
    }

    /// A helper function to match a regular expression. This is marked as async, but it's actually
    /// blocking, so to use it properly it needs to be spawned as a task.
    async fn match_regex(message: String, regex: String) -> Result<bool, Error> {
        // Strip the slashes off the front and back of the allow list entry
        let mut regex_inner = regex.chars();
        regex_inner.next();
        regex_inner.next_back();
        // Compile the regex and return whether it matches the string
        let re = match Regex::new(regex_inner.as_str()) {
            Ok(re) => re,
            Err(e) => return Err(e),
        };
        Ok(re.is_match(message.as_str()))
    }

    /// Extract all of the "bad" URLs from a given message. Returns a tuple of Options containing
    /// Vecs, (bad_links, bad_regexes), where bad_links are links not on the allow list in the
    /// given channel and bad_regexes are regex entries that failed to run (timed out or excepted).
    pub async fn extract_urls(
        ext: &TldExtractor,
        message: &str,
        channel: &Channel,
    ) -> (Option<Vec<String>>, Option<Vec<String>>) {
        // We need to extract every link from the message. The most reliable way to do that is
        // with this regex.
        let linkregex =
            Regex::new(r"([\w+]+://)?([\w\d-]+\.)*[\w-]+[\.:]\w+([/\?=&#\.]?[\w-]+)*/?")
                .expect("Couldn't parse known-good regex");
        // Set up an additional regex to identify links that are missing a scheme.
        // The url crate needs a scheme to function, and the url crate give us some good info.
        let urlregex = Regex::new(r"^[a-zA-Z0-9]+://").expect("Couldn't parse known-good regex");

        // Set up the Vecs we need to return
        let mut bad_links = vec![];
        let mut bad_regexes = vec![];
        // Loop through all the identified links
        'outer: for link in linkregex.captures_iter(message) {
            // Take the whole capture
            let mut link = link[0].to_owned();

            // Determine if the link had a scheme originally; this is necessary for
            // the "slash" option
            let link_had_scheme: bool;
            if !urlregex.is_match(link.as_str()) {
                link = "http://".to_owned() + &link;
                link_had_scheme = false;
            } else {
                link_had_scheme = true;
            }

            // Turn the link into a Url
            let link = match Url::from_str(link.as_str()) {
                Ok(url) => url,
                Err(_) => {
                    println!("Couldn't convert {} to URL", link.as_str()); // TODO: log this
                    continue;
                }
            };

            // Urls that cannot be a base are not Urls you can click on in a Twitch chat
            if link.cannot_be_a_base() {
                continue;
            }

            // Use tldextract to validate the TLD is legitimate per the PSL
            let tld = ext.extract(link.as_str());
            if let Ok(tld) = tld {
                // First, apply any regexes in the allow list
                for regex in &channel.allow_list {
                    if regex.starts_with('/') && regex.ends_with('/') {
                        // Set up an abort handle so we can kill the task if it times out
                        let (abort_handle, abort_reg) = futures::future::AbortHandle::new_pair();
                        let re_future = Abortable::new(
                            match_regex(link.as_str().to_owned(), regex.clone()),
                            abort_reg,
                        );
                        // Spawn a task to run the user-supplied regex
                        let timeout =
                            timeout(Duration::from_millis(10), tokio::spawn(re_future)).await;
                        if timeout.is_err() {
                            // The regex took too long and timed out, abort the task and report the regex
                            println!("Regex timed out: {}", regex);
                            bad_regexes.push(regex.clone());
                            abort_handle.abort();
                            continue;
                        }
                        // This should not be reachable if we abort the handle, so unwrap the timeout
                        // Three unwraps handle: Elapsed, JoinError, Aborted,
                        // but those should only happen if we timed out and aborted the handle.
                        let timeout = timeout.unwrap().unwrap().unwrap();
                        match timeout {
                            Ok(matches) => {
                                if matches {
                                    // If the regex matched, the link is allowed, and we continue
                                    // the outer loop
                                    continue 'outer;
                                }
                            }
                            Err(e) => {
                                // TODO: Logging
                                println!("Regex failed: {}", e);
                                bad_regexes.push(regex.clone());
                                continue;
                            }
                        }
                    }
                }
                // Extract the host from the URL for matching against the allow list
                let host = link
                    .host_str()
                    .expect("Encountered a non-host URL")
                    .to_owned()
                    .to_lowercase();
                // If none of the channel options short-circuit, we need to check the link
                if !channel.slash
                    || link.path() != "/"
                    || link_had_scheme
                    || (channel.dot && host.matches('.').count() > 1)
                {
                    // tldhost is used for subdomain matching; it gets the TLD, plus the base domain
                    let tldhost = tld.domain.unwrap() + "." + &tld.suffix.unwrap();
                    // If there are no matches between the allow list and the domain, the link is bad
                    if !channel.allow_list.iter().any(|s| {
                        s.to_lowercase() == host
                            || (channel.subdomains && s.to_lowercase() == tldhost.to_lowercase())
                    }) {
                        bad_links.push(link.as_str().to_owned());
                    }
                }
            }
        }

        // Set up our return values
        let links_ret = match bad_links.len() {
            0 => None,
            _ => Some(bad_links),
        };

        let regexes_ret = match bad_regexes.len() {
            0 => None,
            _ => Some(bad_regexes),
        };

        // And we're done
        (links_ret, regexes_ret)
    }

    pub struct GhirahimDB {
        mongo_client: Collection<Channel>,
        redis_client: redis::Client
    }

    // impl GhirahimDB {
    //     pub fn new(mongo_connect: &str, redis_connect: &str) -> GhirahimDB {

    //     }
    // }
}
