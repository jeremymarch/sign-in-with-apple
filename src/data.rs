use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;

pub const APPLE_PUB_KEYS: &str =
	"https://appleid.apple.com/auth/keys";
pub const APPLE_ISSUER: &str = "https://appleid.apple.com";

pub const GOOGLE_PUB_KEYS: &str =
	"https://www.googleapis.com/oauth2/v3/certs";
pub const GOOGLE_ISSUER: &str = "https://accounts.google.com";

#[derive(Debug, Serialize, Deserialize)]
pub struct KeyComponents {
	pub kty: String,   // "RSA"
	pub kid: String,   // "eXaunmL"
	pub r#use: String, // "sig"
	pub alg: String,   // "RS256"
	pub n: String,     // "4dGQ7bQK8LgILOdL..."
	pub e: String,     // "AQAB"
}

pub trait TokenType {
	fn iss(&self) -> &str;
	fn aud(&self) -> &str;
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct AppleOrGoogleClaims {
	pub iss: String,
	pub aud: String,
	pub exp: i32,
	pub iat: i32,
	pub sub: String,
	pub c_hash: String,
	pub email: Option<String>,
	#[serde(deserialize_with = "deserialize_bool_or_string")]
	pub email_verified: Option<bool>,
	pub nonce: Option<String>,
	pub nonce_supported: Option<bool>,
}

impl TokenType for AppleOrGoogleClaims {
	fn iss(&self) -> &str {
		&self.iss
	}
	fn aud(&self) -> &str {
		&self.aud
	}
}
/*
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct GoogleClaims {
	pub iss: String,
	pub aud: String,
	pub exp: i32,
	pub iat: i32,
	pub sub: String,
	pub c_hash: String,
	pub email: Option<String>,
	#[serde(deserialize_with = "deserialize_bool_or_string")]
	pub email_verified: Option<bool>,
	pub nonce: Option<String>,
}

impl TokenType for GoogleClaims {
	fn iss(&self) -> &str {
		&self.iss
	}
	fn aud(&self) -> &str {
		&self.aud
	}
}
*/
/// see <https://developer.apple.com/documentation/sign_in_with_apple/processing_changes_for_sign_in_with_apple_accounts>
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct ClaimsServer2Server {
	pub iss: String,
	pub aud: String,
	pub exp: i32,
	pub iat: i32,
	pub jti: String,
	/// Note that this is documented different to how it is sent.
	/// see https://developer.apple.com/forums/thread/655485
	#[serde(deserialize_with = "deserialize_events")]
	pub events: ClaimsServer2ServerEvent,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct ClaimsServer2ServerEvent {
	#[serde(rename = "type")]
	pub event_type: String,
	pub sub: String,
	pub event_time: i64,
	pub email: Option<String>,
	pub is_private_email: Option<String>,
}

// The signature of a deserialize_with function must follow the pattern:
//
//    fn deserialize<'de, D>(D) -> Result<T, D::Error>
//    where
//        D: Deserializer<'de>
//
// although it may also be generic over the output types T.
pub fn deserialize_events<'de, D>(
	deserializer: D,
) -> Result<ClaimsServer2ServerEvent, D::Error>
where
	D: Deserializer<'de>,
{
	let s = String::deserialize(deserializer)?;
	let events: ClaimsServer2ServerEvent =
		serde_json::from_str(s.as_str())
			.map_err(serde::de::Error::custom)?;
	Ok(events)
}

fn deserialize_bool_or_string<'de, D>(deserializer: D) -> Result<Option<bool>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value: Value = Deserialize::deserialize(deserializer)?;

    match value {
        Value::Bool(b) => Ok(Some(b)),
        Value::String(s) => match s.as_str() {
            "true" => Ok(Some(true)),
            "false" => Ok(Some(false)),
            _ => Ok(None),
        },
        _ => Ok(None),
    }
}