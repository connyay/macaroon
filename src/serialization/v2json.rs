use crate::caveat;
use crate::caveat::CaveatBuilder;
use crate::error::MacaroonError;
use crate::serialization::macaroon_builder::MacaroonBuilder;
use crate::{
    base64_decode_flexible, check_field_size, ByteString, Macaroon, Result, URL_SAFE_NO_PAD,
};
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_json;
use std::str;

// `deny_unknown_fields` keeps V2JSON as canonical as the binary formats:
// without it, arbitrary (and unbounded — the field caps only apply to
// fields we model) junk rides along in a token, giving one macaroon many
// byte representations. Serde already rejects duplicate keys.
#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Caveat {
    i: Option<String>,
    i64: Option<ByteString>,
    l: Option<String>,
    l64: Option<String>,
    v: Option<String>,
    v64: Option<ByteString>,
}

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Serialization {
    v: u8,
    i: Option<String>,
    i64: Option<ByteString>,
    l: Option<String>,
    l64: Option<String>,
    c: Vec<Caveat>,
    s: Option<Vec<u8>>,
    s64: Option<String>,
}

impl Serialization {
    fn from_macaroon(macaroon: &Macaroon) -> Result<Serialization> {
        let mut serialized: Serialization = Serialization {
            v: 2,
            i: None,
            i64: Some(ByteString(macaroon.identifier().to_vec())),
            l: macaroon.location().map(|s| s.to_string()),
            l64: None,
            c: Vec::new(),
            s: None,
            // URL-safe, no padding — matches libmacaroons / pymacaroons
            // wire format for `s64`.
            s64: Some(URL_SAFE_NO_PAD.encode(macaroon.signature())),
        };
        for c in macaroon.caveats() {
            match c {
                caveat::Caveat::FirstParty(fp) => {
                    let serialized_caveat: Caveat = Caveat {
                        i: None,
                        i64: Some(ByteString(fp.predicate().to_vec())),
                        l: None,
                        l64: None,
                        v: None,
                        v64: None,
                    };
                    serialized.c.push(serialized_caveat);
                }
                caveat::Caveat::ThirdParty(tp) => {
                    let serialized_caveat: Caveat = Caveat {
                        i: None,
                        i64: Some(ByteString(tp.id().to_vec())),
                        l: Some(tp.location().to_string()),
                        l64: None,
                        v: None,
                        v64: Some(ByteString(tp.verifier_id().to_vec())),
                    };
                    serialized.c.push(serialized_caveat);
                }
            }
        }

        Ok(serialized)
    }
}

fn reject_both<A, B>(a: &Option<A>, b: &Option<B>, pair: &str) -> Result<()> {
    if a.is_some() && b.is_some() {
        return Err(MacaroonError::DeserializationError(format!(
            "Found {} fields",
            pair
        )));
    }
    Ok(())
}

impl Macaroon {
    fn from_json(ser: Serialization) -> Result<Macaroon> {
        if ser.v != 2 {
            return Err(MacaroonError::DeserializationError(format!(
                "Unsupported V2JSON version field: {} (expected 2)",
                ser.v
            )));
        }
        reject_both(&ser.i, &ser.i64, "i and i64")?;
        reject_both(&ser.l, &ser.l64, "l and l64")?;
        reject_both(&ser.s, &ser.s64, "s and s64")?;

        let mut builder: MacaroonBuilder = MacaroonBuilder::new();
        // V1/V2 enforce the field size cap while parsing; mirror it here so
        // the cap holds regardless of which format a token arrives in.
        let identifier: ByteString = match ser.i {
            Some(id) => id.into(),
            None => match ser.i64 {
                Some(id) => id,
                None => {
                    return Err(MacaroonError::DeserializationError(String::from(
                        "No identifier \
                         found",
                    )))
                }
            },
        };
        check_field_size("identifier", identifier.0.len())?;
        builder.set_identifier(identifier);

        let location: Option<String> = match ser.l {
            Some(loc) => Some(loc),
            None => match ser.l64 {
                Some(loc) => Some(String::from_utf8(base64_decode_flexible(loc.as_bytes())?)?),
                None => None,
            },
        };
        if let Some(loc) = location {
            check_field_size("location", loc.len())?;
            builder.set_location(&loc);
        }

        let raw_sig = match ser.s {
            Some(sig) => sig,
            None => match ser.s64 {
                Some(sig) => base64_decode_flexible(sig.as_bytes())?,
                None => {
                    return Err(MacaroonError::DeserializationError(
                        "No signature found".into(),
                    ))
                }
            },
        };
        if raw_sig.len() != 32 {
            return Err(MacaroonError::DeserializationError(
                "Illegal signature length".into(),
            ));
        }

        builder.set_signature(&raw_sig);

        let mut caveat_builder: CaveatBuilder = CaveatBuilder::new();
        for c in ser.c {
            // Mirror the top-level exclusion checks at the caveat level so a
            // token cannot silently prefer one encoding over another. Two
            // serializers that read different fields must not see different
            // content.
            reject_both(&c.i, &c.i64, "caveat i and i64")?;
            reject_both(&c.l, &c.l64, "caveat l and l64")?;
            reject_both(&c.v, &c.v64, "caveat v and v64")?;

            let caveat_id: ByteString = match c.i {
                Some(id) => id.into(),
                None => match c.i64 {
                    Some(id64) => id64,
                    None => {
                        return Err(MacaroonError::DeserializationError(String::from(
                            "No caveat ID found",
                        )))
                    }
                },
            };
            check_field_size("caveat id", caveat_id.0.len())?;
            caveat_builder.add_id(caveat_id);

            let caveat_location: Option<String> = match c.l {
                Some(loc) => Some(loc),
                None => match c.l64 {
                    Some(loc64) => Some(String::from_utf8(base64_decode_flexible(
                        loc64.as_bytes(),
                    )?)?),
                    None => None,
                },
            };
            if let Some(loc) = caveat_location {
                check_field_size("caveat location", loc.len())?;
                caveat_builder.add_location(loc);
            }

            let verifier_id: Option<ByteString> = match c.v {
                Some(vid) => Some(vid.into()),
                None => c.v64,
            };
            if let Some(vid) = verifier_id {
                check_field_size("caveat vid", vid.0.len())?;
                caveat_builder.add_verifier_id(vid);
            }
            builder.add_caveat(caveat_builder.build()?)?;
            caveat_builder = CaveatBuilder::new();
        }

        builder.build()
    }
}

pub fn serialize(macaroon: &Macaroon) -> Result<String> {
    let serialized: String = serde_json::to_string(&Serialization::from_macaroon(macaroon)?)?;
    Ok(serialized)
}

pub fn deserialize(data: &[u8]) -> Result<Macaroon> {
    let v2j: Serialization = serde_json::from_slice(data)?;
    Macaroon::from_json(v2j)
}

#[cfg(test)]
mod tests {
    use super::super::Format;
    use crate::{Caveat, Macaroon, MacaroonKey};

    const SERIALIZED_JSON: &str = "{\"v\":2,\"l\":\"http://example.org/\",\"i\":\"keyid\",\
                                   \"c\":[{\"i\":\"account = 3735928559\"},{\"i\":\"user = \
                                   alice\"}],\"s64\":\
                                   \"S-lnzR6gxrJrr2pKlO6bBbFYhtoLqF6MQqk8jQ4SXvw\"}";
    const SIGNATURE: [u8; 32] = [
        75, 233, 103, 205, 30, 160, 198, 178, 107, 175, 106, 74, 148, 238, 155, 5, 177, 88, 134,
        218, 11, 168, 94, 140, 66, 169, 60, 141, 14, 18, 94, 252,
    ];

    #[test]
    fn test_deserialize() {
        let serialized_json: Vec<u8> = SERIALIZED_JSON.as_bytes().to_vec();
        let macaroon = super::deserialize(&serialized_json).unwrap();
        assert_eq!("http://example.org/", macaroon.location().unwrap());
        assert_eq!(b"keyid", macaroon.identifier());
        assert_eq!(2, macaroon.caveats().len());
        let predicate = match &macaroon.caveats()[0] {
            Caveat::FirstParty(fp) => fp.predicate().to_vec(),
            _ => vec![],
        };
        assert_eq!(b"account = 3735928559".to_vec(), predicate);
        let predicate = match &macaroon.caveats()[1] {
            Caveat::FirstParty(fp) => fp.predicate().to_vec(),
            _ => vec![],
        };
        assert_eq!(b"user = alice".to_vec(), predicate);
        assert_eq!(&MacaroonKey::from(SIGNATURE), macaroon.signature());
    }

    #[test]
    fn test_serialize_deserialize() {
        let mut macaroon =
            Macaroon::create(Some("http://example.org/"), &SIGNATURE.into(), "keyid").unwrap();
        macaroon.add_first_party_caveat("user = alice").unwrap();
        macaroon
            .add_third_party_caveat(
                "https://auth.mybank.com/",
                &MacaroonKey::generate(b"my key"),
                "keyid",
            )
            .unwrap();
        let serialized = macaroon.serialize(Format::V2JSON).unwrap();
        let other = Macaroon::deserialize(&serialized).unwrap();
        assert_eq!(macaroon, other);
    }

    #[test]
    fn test_reject_wrong_version() {
        let bad =
            r#"{"v":1,"i":"keyid","c":[],"s64":"S-lnzR6gxrJrr2pKlO6bBbFYhtoLqF6MQqk8jQ4SXvw"}"#;
        let err = Macaroon::deserialize(bad).unwrap_err();
        assert!(matches!(err, crate::MacaroonError::DeserializationError(_)));
    }

    #[test]
    fn test_reject_unknown_fields() {
        // Unknown keys are unbounded payload the field caps never see, and
        // they let one macaroon have many byte representations.
        let sig64 = "S-lnzR6gxrJrr2pKlO6bBbFYhtoLqF6MQqk8jQ4SXvw";

        let top_level = format!(
            r#"{{"v":2,"i":"keyid","zzz":"junk","c":[],"s64":"{}"}}"#,
            sig64
        );
        let err = Macaroon::deserialize(&top_level).unwrap_err();
        assert!(err.to_string().contains("unknown field"), "{}", err);

        let in_caveat = format!(
            r#"{{"v":2,"i":"keyid","c":[{{"i":"a = b","zzz":"junk"}}],"s64":"{}"}}"#,
            sig64
        );
        let err = Macaroon::deserialize(&in_caveat).unwrap_err();
        assert!(err.to_string().contains("unknown field"), "{}", err);

        // duplicate keys are rejected too (serde, not `deny_unknown_fields`)
        let dup = format!(
            r#"{{"v":2,"i":"first","i":"second","c":[],"s64":"{}"}}"#,
            sig64
        );
        let err = Macaroon::deserialize(&dup).unwrap_err();
        assert!(err.to_string().contains("duplicate field"), "{}", err);
    }

    #[test]
    fn test_reject_oversized_fields() {
        // V2JSON must enforce MAX_FIELD_SIZE_BYTES like the binary formats.
        let sig64 = "S-lnzR6gxrJrr2pKlO6bBbFYhtoLqF6MQqk8jQ4SXvw";
        let huge = "A".repeat(crate::MAX_FIELD_SIZE_BYTES + 1);

        let bad_id = format!(r#"{{"v":2,"i":"{}","c":[],"s64":"{}"}}"#, huge, sig64);
        assert!(matches!(
            Macaroon::deserialize(&bad_id).unwrap_err(),
            crate::MacaroonError::FieldTooLarge {
                field: "identifier",
                ..
            }
        ));

        let bad_loc = format!(
            r#"{{"v":2,"i":"keyid","l":"{}","c":[],"s64":"{}"}}"#,
            huge, sig64
        );
        assert!(matches!(
            Macaroon::deserialize(&bad_loc).unwrap_err(),
            crate::MacaroonError::FieldTooLarge {
                field: "location",
                ..
            }
        ));

        let bad_cav = format!(
            r#"{{"v":2,"i":"keyid","c":[{{"i":"{}"}}],"s64":"{}"}}"#,
            huge, sig64
        );
        assert!(matches!(
            Macaroon::deserialize(&bad_cav).unwrap_err(),
            crate::MacaroonError::FieldTooLarge {
                field: "caveat id",
                ..
            }
        ));

        // at exactly the cap, the token parses
        let ok_id = format!(
            r#"{{"v":2,"i":"{}","c":[],"s64":"{}"}}"#,
            "A".repeat(crate::MAX_FIELD_SIZE_BYTES),
            sig64
        );
        assert!(Macaroon::deserialize(&ok_id).is_ok());
    }

    #[test]
    fn test_reject_caveat_with_both_i_and_i64() {
        let bad = r#"{"v":2,"i":"keyid","c":[{"i":"x","i64":"eA"}],"s64":"S-lnzR6gxrJrr2pKlO6bBbFYhtoLqF6MQqk8jQ4SXvw"}"#;
        let err = Macaroon::deserialize(bad).unwrap_err();
        match err {
            crate::MacaroonError::DeserializationError(s) => {
                assert!(s.contains("i and i64"), "unexpected error: {}", s);
            }
            other => panic!("expected DeserializationError, got {:?}", other),
        }
    }
}
