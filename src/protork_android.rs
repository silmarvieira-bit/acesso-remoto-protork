//! Company server defaults only; Android consent and access passwords are unchanged.
use hbb_common::config::Config;

pub fn initialize() {
    if Config::get_option("protork-android-server-v1") == "Y" { return; }
    // Never overwrite an explicitly selected server on an existing installation.
    if !Config::get_option("custom-rendezvous-server").is_empty() { return; }
    if let (Some(id), Some(relay), Some(key)) = (
        option_env!("PROTORK_ID_SERVER"), option_env!("PROTORK_RELAY_SERVER"),
        option_env!("PROTORK_SERVER_KEY"),
    ) {
        if id.is_empty() || relay.is_empty() || key.is_empty() { return; }
        Config::set_option("custom-rendezvous-server".to_owned(), id.to_owned());
        Config::set_option("relay-server".to_owned(), relay.to_owned());
        Config::set_option("key".to_owned(), key.to_owned());
        Config::set_option("protork-android-server-v1".to_owned(), "Y".to_owned());
    }
}
