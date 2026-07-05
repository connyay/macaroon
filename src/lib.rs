//! Implementation of [Macaroons](http://research.google.com/pubs/pub41892.html) for Rust, which are
//! flexible authorization tokens for distributed systems. They are similar to cookies, but allow for
//! more narrowly-focused authorization based on contextual caveats.
//!
//! # What Are Macaroons?
//!
//! Macaroons are bearer tokens (similar to cookies) which encode within them criteria within which the
//! authorization is allowed to take place (referred to as "caveats"). For instance, authorization could
//! be restricted to a particular user, account, time of day, really anything. These criteria can be either
//! evaluated locally (a "first-party caveat"), or using special macaroons ("discharge macaroons") generated
//! by a third party (a "third-party caveat").
//!
//! A first-party caveat consists simply of a predicate which, when evaluated as true, authorizes the caveat.
//! The predicate is a string which is either evaluated using strict string comparison (`satisfy_exact`),
//! or interpreted using a provided function (`satisfy_general`).
//!
//! A third-party caveat consists of a location string, an identifier, and a specially-generated signing key
//! to authenticate the generated discharge macaroons. The key and identifier is passed to the third-party
//! who generates the discharge macaroons. The receiver then binds each discharge macaroon to the original
//! macaroon.
//!
//! During verification of a third-party caveat, a discharge macaroon is found from those received whose identifier
//! matches that of the caveat. The binding signature is verified, and the discharge macaroon's caveats are verified
//! using the same process as the original macaroon.
//!
//! The macaroon is considered authorized only if all its caveats are authorized by the above process.
//!
//! # Example
//!
//! ```rust
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use libmacaroon::{Macaroon, Verifier, MacaroonKey};
//!
//! // Create our key.
//! let key = MacaroonKey::generate(b"key");
//!
//! // Create our macaroon. A location is optional.
//! let mut macaroon = Macaroon::create(Some("location"), &key, "id")?;
//!
//! // Add a first-party caveat: only someone identified as account 12345678
//! // is authorized to use this macaroon. Multiple caveats with different
//! // predicates can be layered on.
//! macaroon.add_first_party_caveat("account = 12345678")?;
//!
//! // Build a verifier with the predicates we're willing to accept.
//! let mut verifier = Verifier::default();
//! verifier.satisfy_exact("account = 12345678");
//!
//! // Verify. Returns Ok(()) on success.
//! verifier.verify(&macaroon, &key, &[])?;
//!
//! // Now a third-party caveat: verification requires a discharge macaroon
//! // issued by a third party under a separate key.
//! let other_key = MacaroonKey::generate(b"different key");
//! macaroon.add_third_party_caveat("https://auth.mybank", &other_key, "caveat id")?;
//!
//! // The third party creates the discharge using the same caveat id and key.
//! let mut discharge = Macaroon::create(
//!     Some("http://auth.mybank/"),
//!     &other_key,
//!     "caveat id",
//! )?;
//! discharge.add_first_party_caveat("account = 12345678")?;
//!
//! // Bind the discharge to the original macaroon so it cannot be reused
//! // against a different authorizing macaroon.
//! macaroon.bind(&mut discharge);
//!
//! // Same verifier, now with the discharge supplied.
//! verifier.verify(&macaroon, &key, &[discharge])?;
//! # Ok(())
//! # }
//! ```
//!
//! # Supported Features
//!
//! This crate supports all the following features:
//!
//! - verification of first-party caveats either via exact string match or passed-in function
//! - verification of third-party caveats using discharge macaroons (including ones that themselves have embedded third-party caveats)
//! - serialization and deserialization of caveats via version 1, 2 or 2J serialization formats (fully compatible with libmacaroons)

use base64::{
    alphabet,
    engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig},
    Engine as _,
};
use log::debug;

/// Base64 engines that tolerate both padded and unpadded input when decoding,
/// matching the lenient behavior of the `base64 0.13` `STANDARD` / `URL_SAFE`
/// configs. Needed so that macaroons serialized by other libraries — which may
/// omit or include `=` padding — round-trip correctly.
pub(crate) const STANDARD: GeneralPurpose = GeneralPurpose::new(
    &alphabet::STANDARD,
    GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent),
);
pub(crate) const URL_SAFE: GeneralPurpose = GeneralPurpose::new(
    &alphabet::URL_SAFE,
    GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent),
);
/// Used on the emit side for V2JSON fields (`i64`, `v64`, `s64`) so our
/// output matches what libmacaroons/pymacaroons produce: URL-safe alphabet,
/// no `=` padding. The decode side tolerates both padded and unpadded.
pub(crate) const URL_SAFE_NO_PAD: GeneralPurpose = GeneralPurpose::new(
    &alphabet::URL_SAFE,
    GeneralPurposeConfig::new()
        .with_encode_padding(false)
        .with_decode_padding_mode(DecodePaddingMode::Indifferent),
);

mod caveat;
mod crypto;
mod error;
mod serialization;
mod verifier;

pub use caveat::{Caveat, FirstParty, ThirdParty};
pub use crypto::MacaroonKey;
pub use error::MacaroonError;
pub use serialization::Format;
pub use verifier::Verifier;

#[cfg(feature = "v2json")]
use serde::de::Visitor;
#[cfg(feature = "v2json")]
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

pub type Result<T> = std::result::Result<T, MacaroonError>;

/// Maximum number of caveats allowed on a single macaroon. Applied on both
/// construction (`add_first_party_caveat`, `add_third_party_caveat`) and
/// deserialization to bound memory and verification work.
pub const MAX_CAVEATS: usize = 1000;

/// Maximum byte length accepted for any single field (identifier, location,
/// predicate, VID, signature) during construction and deserialization.
///
/// Bounds memory and parsing work on untrusted input. All three formats
/// enforce it when deserializing, and V2/V2JSON can serialize any field up
/// to the cap. The V1 packet format is slightly tighter: a packet is
/// `4 (hex size header) + tag + 1 (space) + value + 1 (newline)` bytes with
/// a `0xFFFF` maximum, so a field within `tag length + 6` bytes of this cap
/// (e.g. an identifier over 65519 bytes, or a predicate over 65526 —
/// the most any V1 implementation can represent) fails V1 serialization
/// with [`MacaroonError::FieldTooLarge`] rather than being silently
/// truncated.
pub const MAX_FIELD_SIZE_BYTES: usize = 65535;

pub(crate) fn check_field_size(field: &'static str, size: usize) -> Result<()> {
    if size > MAX_FIELD_SIZE_BYTES {
        return Err(MacaroonError::FieldTooLarge { field, size });
    }
    Ok(())
}

// Internal type representing binary data. By spec, most fields in a macaroon
// support binary encoded as base64.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub(crate) struct ByteString(pub(crate) Vec<u8>);

impl AsRef<[u8]> for ByteString {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl std::borrow::Borrow<[u8]> for ByteString {
    fn borrow(&self) -> &[u8] {
        &self.0
    }
}

impl From<Vec<u8>> for ByteString {
    fn from(v: Vec<u8>) -> ByteString {
        ByteString(v)
    }
}

impl From<&[u8]> for ByteString {
    fn from(s: &[u8]) -> ByteString {
        ByteString(s.to_vec())
    }
}

impl From<&str> for ByteString {
    fn from(s: &str) -> ByteString {
        ByteString(s.as_bytes().to_vec())
    }
}

impl From<String> for ByteString {
    fn from(s: String) -> ByteString {
        ByteString(s.as_bytes().to_vec())
    }
}

impl From<[u8; 32]> for ByteString {
    fn from(b: [u8; 32]) -> ByteString {
        ByteString(b.to_vec())
    }
}

impl fmt::Display for ByteString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Emit URL-safe base64 without padding — matches libmacaroons /
        // pymacaroons V2JSON output, which is the wire format these fields
        // (`i64`, `v64`) travel in.
        write!(f, "{}", URL_SAFE_NO_PAD.encode(&self.0))
    }
}

#[cfg(feature = "v2json")]
impl Serialize for ByteString {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

#[cfg(feature = "v2json")]
struct ByteStringVisitor;

#[cfg(feature = "v2json")]
impl<'de> Visitor<'de> for ByteStringVisitor {
    type Value = ByteString;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("base64 encoded string of bytes")
    }

    fn visit_str<E>(self, value: &str) -> std::result::Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        // Tolerate both standard and URL-safe alphabets, padded or unpadded:
        // libmacaroons and pymacaroons emit URL-safe no-pad, but some clients
        // use the standard alphabet. Accepting both here fixes a real interop
        // break on V2JSON `i64` / `v64` fields.
        let raw = base64_decode_flexible(value.as_bytes())
            .map_err(|_| E::custom("unable to base64 decode value"))?;
        Ok(ByteString(raw))
    }
}

#[cfg(feature = "v2json")]
impl<'de> Deserialize<'de> for ByteString {
    fn deserialize<D>(deserializer: D) -> std::result::Result<ByteString, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(ByteStringVisitor)
    }
}

/// Internal helper to decode base64 tokens in either URL-safe or non-URL-safe format, with or
/// without padding. The macaroons format specifies that macaroons should be accepted in any of
/// these variations.
///
/// Logic is based on pymacaroons helper:
/// https://github.com/ecordell/pymacaroons/blob/master/pymacaroons/utils.py#L109
fn base64_decode_flexible(b: &[u8]) -> Result<Vec<u8>> {
    if b.is_empty() {
        return Err(MacaroonError::DeserializationError(
            "empty token to deserialize".to_string(),
        ));
    }
    if b.contains(&b'_') || b.contains(&b'-') {
        Ok(URL_SAFE.decode(b)?)
    } else {
        Ok(STANDARD.decode(b)?)
    }
}

// https://github.com/rescrv/libmacaroons/blob/master/doc/format.txt#L87
#[test]
fn test_base64_decode_flexible() {
    let val = b"Ou?T".to_vec();
    assert_eq!(val, base64_decode_flexible(b"T3U/VA==").unwrap());
    assert_eq!(val, base64_decode_flexible(b"T3U_VA==").unwrap());
    assert_eq!(val, base64_decode_flexible(b"T3U/VA").unwrap());
    assert_eq!(val, base64_decode_flexible(b"T3U_VA").unwrap());

    assert!(base64_decode_flexible(b"...").is_err());
    assert!(base64_decode_flexible(b"").is_err());
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Macaroon {
    identifier: ByteString,
    location: Option<String>,
    signature: MacaroonKey,
    caveats: Vec<Caveat>,
}

impl Macaroon {
    /// Construct a macaroon, given a location and identifier, and a key to sign
    /// it with. You can use a bare str or &[u8] containing arbitrary data with
    /// `into` to automatically generate a suitable key.
    ///
    /// # Errors
    ///
    /// - [`MacaroonError::IncompleteMacaroon`] if the identifier is empty.
    /// - [`MacaroonError::FieldTooLarge`] if the identifier or location
    ///   exceeds [`MAX_FIELD_SIZE_BYTES`].
    pub fn create(
        location: Option<&str>,
        key: &MacaroonKey,
        identifier: impl AsRef<[u8]>,
    ) -> Result<Macaroon> {
        let identifier_bytes = identifier.as_ref();
        check_field_size("identifier", identifier_bytes.len())?;
        if let Some(loc) = location {
            check_field_size("location", loc.len())?;
        }
        let identifier = ByteString(identifier_bytes.to_vec());
        let signature = crypto::hmac(key, &identifier);
        let macaroon = Macaroon {
            location: location.map(str::to_string),
            identifier,
            signature,
            caveats: Vec::new(),
        };
        debug!("Macaroon::create: {:?}", macaroon);
        macaroon.validate()
    }

    /// Returns the identifier for the macaroon as a byte slice
    pub fn identifier(&self) -> &[u8] {
        &self.identifier.0
    }

    /// Returns a reference to the location for the macaroon
    pub fn location(&self) -> Option<&str> {
        self.location.as_deref()
    }

    /// Returns the macaroon's signature
    ///
    /// The [MacaroonKey] type is used because it is the same size and format as a signature, but
    /// the signature is not and should not be used as a cryptographic key.
    pub fn signature(&self) -> &MacaroonKey {
        &self.signature
    }

    /// Returns a reference to the list of caveats
    pub fn caveats(&self) -> &[Caveat] {
        &self.caveats
    }

    /// Retrieve a list of references to the first-party caveats
    pub fn first_party_caveats(&self) -> Vec<&Caveat> {
        self.caveats
            .iter()
            .filter(|c| matches!(c, caveat::Caveat::FirstParty(_)))
            .collect()
    }

    /// Retrieve a list of references to the third-party caveats
    pub fn third_party_caveats(&self) -> Vec<&Caveat> {
        self.caveats
            .iter()
            .filter(|c| matches!(c, caveat::Caveat::ThirdParty(_)))
            .collect()
    }

    /// Validate that a Macaroon has all the expected fields
    ///
    /// This is a low-level function to confirm that a macaroon was constructured correctly. It
    /// does *not* verify the signature, caveats, or in any way confirm that a macaroon is
    /// authentic from a security standpoint.
    fn validate(self) -> Result<Self> {
        if self.identifier.0.is_empty() {
            return Err(MacaroonError::IncompleteMacaroon("no identifier found"));
        }
        // The `signature` field is required by the struct definition and is
        // always produced by `crypto::hmac` during construction or set from a
        // validated 32-byte field during deserialization, so there is no
        // "missing signature" state to guard against here.
        Ok(self)
    }

    /// Add a first-party caveat to the macaroon
    ///
    /// A first-party caveat is just a string predicate in some
    /// DSL which can be verified either by exact string match,
    /// or by using a function to parse the string and validate it
    /// (see Verifier for more info).
    ///
    /// # Errors
    ///
    /// - [`MacaroonError::TooManyCaveats`] if adding this caveat would exceed
    ///   the [`MAX_CAVEATS`] limit.
    /// - [`MacaroonError::FieldTooLarge`] if the predicate exceeds
    ///   [`MAX_FIELD_SIZE_BYTES`].
    ///
    /// ```
    /// # use libmacaroon::{Macaroon, MacaroonKey};
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let key = MacaroonKey::generate(b"k");
    /// let mut m = Macaroon::create(Some("loc"), &key, "id")?;
    /// m.add_first_party_caveat("account = 12345")?
    ///     .add_first_party_caveat("user = alice")?;
    /// # Ok(()) }
    /// ```
    pub fn add_first_party_caveat(&mut self, predicate: impl AsRef<[u8]>) -> Result<&mut Self> {
        let predicate_bytes = predicate.as_ref();
        check_field_size("predicate", predicate_bytes.len())?;
        self.check_caveat_capacity()?;
        let caveat: caveat::Caveat = caveat::new_first_party(ByteString(predicate_bytes.to_vec()));
        self.signature = caveat.sign(&self.signature);
        self.caveats.push(caveat);
        debug!("Macaroon::add_first_party_caveat: {:?}", self);
        Ok(self)
    }

    /// Add a third-party caveat to the macaroon
    ///
    /// A third-party caveat is a caveat which must be verified by a third party
    /// using macaroons provided by them (referred to as "discharge macaroons").
    ///
    /// # Errors
    ///
    /// - [`MacaroonError::TooManyCaveats`] if adding this caveat would exceed
    ///   the [`MAX_CAVEATS`] limit.
    /// - [`MacaroonError::FieldTooLarge`] if the location or id exceeds
    ///   [`MAX_FIELD_SIZE_BYTES`].
    /// - [`MacaroonError::RngError`] if the OS RNG fails while generating the
    ///   nonce used to encrypt the caveat key (can happen in WASM environments
    ///   without `crypto.getRandomValues`).
    pub fn add_third_party_caveat(
        &mut self,
        location: &str,
        key: &MacaroonKey,
        id: impl AsRef<[u8]>,
    ) -> Result<&mut Self> {
        let id_bytes = id.as_ref();
        check_field_size("caveat id", id_bytes.len())?;
        check_field_size("caveat location", location.len())?;
        self.check_caveat_capacity()?;
        let vid: Vec<u8> = crypto::encrypt_key(&self.signature, key)?;
        let caveat: caveat::Caveat =
            caveat::new_third_party(ByteString(id_bytes.to_vec()), ByteString(vid), location);
        self.signature = caveat.sign(&self.signature);
        self.caveats.push(caveat);
        debug!("Macaroon::add_third_party_caveat: {:?}", self);
        Ok(self)
    }

    fn check_caveat_capacity(&self) -> Result<()> {
        if self.caveats.len() >= MAX_CAVEATS {
            return Err(MacaroonError::TooManyCaveats);
        }
        Ok(())
    }

    /// Bind a discharge macaroon to the original macaroon
    ///
    /// When a macaroon with third-party caveats must be authorized, you send off to the various
    /// locations specified in the caveats, sending the caveat ID and key, and receive a set
    /// of one or more "discharge macaroons" which are used to verify the caveat. In order to ensure
    /// that the discharge macaroons aren't re-used in some other context, we bind them to the original
    /// macaroon so that they can't be used in a different context.
    pub fn bind(&self, discharge: &mut Macaroon) {
        let zero_key = MacaroonKey::from([0; 32]);
        discharge.signature = crypto::hmac2(&zero_key, &self.signature, &discharge.signature);
        debug!(
            "Macaroon::bind: original: {:?}, discharge: {:?}",
            self, discharge
        );
    }

    /// Serialize the macaroon using the serialization [Format] provided
    ///
    /// For V1 and V2, the binary format will be encoded as URL-safe base64 with padding
    /// (`base64::URL_SAFE`). For V2JSON, the output will be JSON.
    pub fn serialize(&self, format: serialization::Format) -> Result<String> {
        match format {
            serialization::Format::V1 => serialization::v1::serialize(self),
            serialization::Format::V2 => serialization::v2::serialize(self),
            #[cfg(feature = "v2json")]
            serialization::Format::V2JSON => serialization::v2json::serialize(self),
        }
    }

    /// Deserialize an encoded macaroon token, inferring the [Format].
    ///
    /// For V1 and V2 tokens, this assumes base64 encoding, in either "standard" or URL-safe
    /// encoding, with or without padding.
    ///
    /// For V2JSON tokens, the token must begin with the `{` character with no preceeding whitespace.
    ///
    /// ## Usage
    ///
    /// ```rust
    /// use libmacaroon::Macaroon;
    /// # use std::error::Error;
    /// # fn main() -> Result<(), Box<dyn Error>> {
    ///
    /// // '&str' gets automatically de-referenced to bytes ('&[u8]').
    /// // 'b"byte-string"' or slice of 'u8' would also work.
    /// let mac = Macaroon::deserialize("MDAxY2xvY2F0aW9uIGh0dHA6Ly9teWJhbmsvCjAwMjZpZGVudGlmaWVyIHdlIHVzZWQgb3VyIHNlY3JldCBrZXkKMDAxNmNpZCB0ZXN0ID0gY2F2ZWF0CjAwMmZzaWduYXR1cmUgGXusegRK8zMyhluSZuJtSTvdZopmDkTYjOGpmMI9vWcK")?;
    ///
    /// # #[cfg(feature = "v2json")] {
    /// let mac_v2json = Macaroon::deserialize(r#"{"v":2,"l":"http://example.org/","i":"keyid", "c":[{"i":"account = 3735928559"},{"i":"user = alice"}],"s64": "S-lnzR6gxrJrr2pKlO6bBbFYhtoLqF6MQqk8jQ4SXvw"}"#)?;
    ///
    /// // expect this to fail; leading whitespace is not allowed
    /// Macaroon::deserialize(r#"   {"v":2,"l":"http://example.org/","i":"keyid", "c":[{"i":"account = 3735928559"},{"i":"user = alice"}],"s64": "S-lnzR6gxrJrr2pKlO6bBbFYhtoLqF6MQqk8jQ4SXvw"}"#).unwrap_err();
    /// # }
    /// # Ok(()) }
    /// ```
    pub fn deserialize<T: AsRef<[u8]>>(token: T) -> Result<Macaroon> {
        if token.as_ref().is_empty() {
            return Err(MacaroonError::DeserializationError(
                "empty token provided".to_string(),
            ));
        }
        let mac: Macaroon = match token.as_ref()[0] as char {
            #[cfg(feature = "v2json")]
            '{' => serialization::v2json::deserialize(token.as_ref())?,
            #[cfg(not(feature = "v2json"))]
            '{' => {
                return Err(MacaroonError::DeserializationError(
                    "V2JSON support is disabled (the `v2json` feature is not enabled)".to_string(),
                ))
            }
            _ => {
                let binary = base64_decode_flexible(token.as_ref())?;
                Macaroon::deserialize_binary(&binary)?
            }
        };
        mac.validate()
    }

    /// Deserialize a binary macaroon token in binary, inferring the [Format]
    ///
    /// This works with V1 and V2 tokens, with no base64 encoding. It does not make sense to use
    /// this with V2JSON tokens.
    pub fn deserialize_binary(token: &[u8]) -> Result<Macaroon> {
        if token.is_empty() {
            return Err(MacaroonError::DeserializationError(
                "empty macaroon token".to_string(),
            ));
        }
        // V2 binary starts with the literal version byte 0x02. V1 binary
        // starts with a four-hex-digit packet length, so the first byte must
        // be a hex digit (the previous `'A'..='Z'` range accidentally
        // accepted non-hex letters, which the parser would then reject with
        // a less informative error).
        let mac: Macaroon = match token[0] as char {
            '\x02' => serialization::v2::deserialize(token)?,
            '0'..='9' | 'a'..='f' | 'A'..='F' => serialization::v1::deserialize(token)?,
            _ => {
                return Err(MacaroonError::DeserializationError(
                    "unknown macaroon serialization format".to_string(),
                ))
            }
        };
        mac.validate()
    }
}

#[cfg(test)]
mod tests {
    use crate::{Caveat, Macaroon, MacaroonError, MacaroonKey, Result, Verifier};

    #[test]
    fn create_macaroon() {
        let signature: MacaroonKey = [
            20, 248, 23, 46, 70, 227, 253, 33, 123, 35, 116, 236, 130, 131, 211, 16, 41, 184, 51,
            65, 213, 46, 109, 76, 49, 201, 186, 92, 114, 163, 214, 231,
        ]
        .into();
        // NOTE: using byte string directly, not generating with HMAC
        let key = MacaroonKey::from(b"this is a super duper secret key");
        let macaroon_res = Macaroon::create(Some("location"), &key, "identifier");
        assert!(macaroon_res.is_ok());
        let macaroon = macaroon_res.unwrap();
        assert!(macaroon.location.is_some());
        assert_eq!("location", macaroon.location.as_deref().unwrap());
        assert_eq!(macaroon.identifier(), b"identifier");
        assert_eq!(signature, macaroon.signature);
        assert_eq!(0, macaroon.caveats.len());
    }

    #[test]
    fn create_invalid_macaroon() {
        // NOTE: using byte string directly, not generating with HMAC
        let key = MacaroonKey::from(b"this is a super duper secret key");
        let macaroon_res: Result<Macaroon> = Macaroon::create(Some("location"), &key, "");
        assert!(macaroon_res.is_err());
        assert!(matches!(
            macaroon_res,
            Err(MacaroonError::IncompleteMacaroon(_))
        ));
        println!("{}", macaroon_res.unwrap_err());
    }

    #[test]
    fn create_macaroon_errors() {
        let deser_err = Macaroon::deserialize(b"\0");
        assert!(matches!(
            deser_err,
            Err(MacaroonError::DeserializationError(_))
        ));
        println!("{}", deser_err.unwrap_err());

        let key = MacaroonKey::generate(b"this is a super duper secret key");
        let mut mac = Macaroon::create(Some("http://mybank"), &key, "identifier").unwrap();

        let mut ver = Verifier::default();
        let wrong_key = MacaroonKey::generate(b"not what was expected");
        let sig_err = ver.verify(&mac, &wrong_key, &[]);
        assert!(matches!(sig_err, Err(MacaroonError::InvalidSignature)));
        println!("{}", sig_err.unwrap_err());
        assert!(ver.verify(&mac, &key, &[]).is_ok());

        mac.add_first_party_caveat("account = 3735928559").unwrap();
        let cav_err = ver.verify(&mac, &key, &[]);
        assert!(matches!(cav_err, Err(MacaroonError::CaveatNotSatisfied(_))));
        println!("{}", cav_err.unwrap_err());
        ver.satisfy_exact("account = 3735928559");
        assert!(ver.verify(&mac, &key, &[]).is_ok());

        let mut mac2 = mac.clone();
        let cav_key = MacaroonKey::generate(b"My key");
        mac2.add_third_party_caveat("other location", &cav_key, "other ident")
            .unwrap();
        let cav_err = ver.verify(&mac2, &key, &[]);
        assert!(matches!(cav_err, Err(MacaroonError::CaveatNotSatisfied(_))));
        println!("{}", cav_err.unwrap_err());

        let discharge =
            Macaroon::create(Some("http://auth.mybank/"), &cav_key, "other keyid").unwrap();
        let disch_err = ver.verify(&mac, &key, &[discharge]);
        assert!(matches!(disch_err, Err(MacaroonError::DischargeNotUsed)));
        println!("{}", disch_err.unwrap_err());
    }

    #[test]
    fn create_macaroon_with_first_party_caveat() {
        let signature: MacaroonKey = [
            14, 23, 21, 148, 48, 224, 4, 143, 81, 137, 60, 25, 201, 198, 245, 250, 249, 62, 233,
            94, 93, 65, 247, 88, 25, 39, 170, 203, 8, 4, 167, 187,
        ]
        .into();
        // NOTE: using byte string directly, not generating with HMAC
        let key = MacaroonKey::from(b"this is a super duper secret key");
        let mut macaroon = Macaroon::create(Some("location"), &key, "identifier").unwrap();
        macaroon.add_first_party_caveat("predicate").unwrap();
        assert_eq!(1, macaroon.caveats.len());
        let predicate = match &macaroon.caveats[0] {
            Caveat::FirstParty(fp) => fp.predicate().to_vec(),
            _ => Vec::new(),
        };
        assert_eq!(b"predicate".to_vec(), predicate);
        assert_eq!(signature, macaroon.signature);
        assert_eq!(&macaroon.caveats[0], macaroon.first_party_caveats()[0]);
    }

    #[test]
    fn create_macaroon_with_third_party_caveat() {
        // NOTE: using byte string directly, not generating with HMAC
        let key = MacaroonKey::from(b"this is a super duper secret key");
        let mut macaroon = Macaroon::create(Some("location"), &key, "identifier").unwrap();
        let location = "https://auth.mybank.com";
        let cav_key = MacaroonKey::generate(b"My key");
        let id = "My Caveat";
        macaroon
            .add_third_party_caveat(location, &cav_key, id)
            .unwrap();
        assert_eq!(1, macaroon.caveats.len());
        let cav_id = match &macaroon.caveats[0] {
            Caveat::ThirdParty(tp) => tp.id().to_vec(),
            _ => Vec::new(),
        };
        let cav_location = match &macaroon.caveats[0] {
            Caveat::ThirdParty(tp) => tp.location().to_string(),
            _ => String::default(),
        };
        assert_eq!(location, cav_location);
        assert_eq!(id.as_bytes().to_vec(), cav_id);
        assert_eq!(&macaroon.caveats[0], macaroon.third_party_caveats()[0]);
    }

    #[test]
    fn test_deserialize_bad_data() {
        // these are all expected to fail... but not panic!
        assert!(Macaroon::deserialize(b"").is_err());
        assert!(Macaroon::deserialize(b"12345").is_err());
        assert!(Macaroon::deserialize(b"\0").is_err());
        assert!(Macaroon::deserialize(b"NDhJe_A==").is_err());

        // examples that fail from fuzzing for the top-level deserialize function
        assert!(Macaroon::deserialize(vec![10]).is_err());
        assert!(Macaroon::deserialize(vec![70, 70, 102, 70]).is_err());
        assert!(Macaroon::deserialize(vec![2, 2, 212, 212, 212, 212]).is_err());
    }
}

// This will run rust code in the README as a test. Copied from:
// https://github.com/rust-lang/cargo/issues/383#issuecomment-720873790
#[cfg(doctest)]
mod test_readme {
    macro_rules! external_doc_test {
        ($x:expr) => {
            #[doc = $x]
            extern "C" {}
        };
    }

    external_doc_test!(include_str!("../README.md"));
}
