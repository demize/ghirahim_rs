use async_trait::async_trait;
use serde_json;

use std::fs::File;

use twitch_irc::login::UserAccessToken;

#[derive(Clone, Debug)]
pub struct JsonTokenStorage {}

#[async_trait]
impl twitch_irc::login::TokenStorage for JsonTokenStorage {
    // IO Errors are fine here, that's all we're doing
    type LoadError = std::io::Error;
    type UpdateError = std::io::Error;

    async fn load_token(&mut self) -> Result<UserAccessToken, Self::LoadError> {
        // Load the currently stored token from the storage.
        let secrets_file = File::open("secrets.json").expect("Unable to read secrets.json");
        let secrets: UserAccessToken = serde_json::from_reader(secrets_file)?;

        Ok(secrets)
    }

    async fn update_token(&mut self, token: &UserAccessToken) -> Result<(), Self::UpdateError> {
        // Called after the token was updated successfully, to save the new token.
        // After `update_token()` completes, the `load_token()` method should then return
        // that token for future invocations
        let secrets_file = File::create("secrets.json").expect("Unable to create secrets.json");
        serde_json::to_writer_pretty(secrets_file, token)?;
        Ok(())
    }
}
