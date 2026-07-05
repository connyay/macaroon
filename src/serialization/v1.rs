use crate::caveat::{Caveat, CaveatBuilder};
use crate::error::MacaroonError;
use crate::serialization::macaroon_builder::MacaroonBuilder;
use crate::{ByteString, Macaroon, Result, URL_SAFE, check_field_size};
use base64::Engine as _;
use log::error;
use std::str;

// Version 1 fields
const LOCATION: &str = "location";
const IDENTIFIER: &str = "identifier";
const SIGNATURE: &str = "signature";
const CID: &str = "cid";
const VID: &str = "vid";
const CL: &str = "cl";

const HEADER_SIZE: usize = 4;
// The four-hex-digit size header covers the whole packet, including itself.
const MAX_PACKET_SIZE: usize = 0xFFFF;

fn serialize_as_packet<'r>(tag: &'r str, value: &'r [u8]) -> Result<Vec<u8>> {
    let size = HEADER_SIZE + 2 + tag.len() + value.len();
    // The size header would otherwise wrap silently past 0xFFFF and emit a
    // corrupt token. Reachable only for fields within `tag.len() + 6` bytes
    // of MAX_FIELD_SIZE_BYTES, which V2/V2JSON can serialize but V1 cannot.
    if size > MAX_PACKET_SIZE {
        return Err(MacaroonError::FieldTooLarge {
            field: "v1 packet",
            size,
        });
    }
    let mut packet: Vec<u8> = Vec::new();
    packet.extend(packet_header(size));
    packet.extend_from_slice(tag.as_bytes());
    packet.extend_from_slice(b" ");
    packet.extend_from_slice(value);
    packet.extend_from_slice(b"\n");

    Ok(packet)
}

fn packet_header(size: usize) -> [u8; 4] {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    [
        HEX[(size >> 12) & 15],
        HEX[(size >> 8) & 15],
        HEX[(size >> 4) & 15],
        HEX[size & 15],
    ]
}

pub fn serialize_binary(macaroon: &Macaroon) -> Result<Vec<u8>> {
    let mut serialized: Vec<u8> = Vec::new();
    if let Some(location) = macaroon.location() {
        serialized.extend(serialize_as_packet(LOCATION, location.as_bytes())?);
    };
    serialized.extend(serialize_as_packet(IDENTIFIER, macaroon.identifier())?);
    for c in macaroon.caveats() {
        match c {
            Caveat::FirstParty(fp) => {
                serialized.extend(serialize_as_packet(CID, fp.predicate())?);
            }
            Caveat::ThirdParty(tp) => {
                serialized.extend(serialize_as_packet(CID, tp.id())?);
                serialized.extend(serialize_as_packet(VID, tp.verifier_id())?);
                serialized.extend(serialize_as_packet(CL, tp.location().as_bytes())?)
            }
        }
    }
    serialized.extend(serialize_as_packet(
        SIGNATURE,
        macaroon.signature().as_ref(),
    )?);
    Ok(serialized)
}

pub fn serialize(macaroon: &Macaroon) -> Result<String> {
    let buf = serialize_binary(macaroon)?;
    Ok(URL_SAFE.encode(&buf))
}

struct Packet {
    key: String,
    value: Vec<u8>,
}

fn deserialize_as_packets(data: &[u8]) -> Result<Vec<Packet>> {
    let mut packets = Vec::new();
    let mut remaining = data;
    while !remaining.is_empty() {
        if remaining.len() < 4 {
            return Err(MacaroonError::DeserializationError(
                "packet chunk too small to decode".to_string(),
            ));
        }
        let hex: &str = str::from_utf8(&remaining[..4])?;
        let size: usize = usize::from_str_radix(hex, 16)?;
        if size > remaining.len() {
            return Err(MacaroonError::DeserializationError(
                "packet chunk size larger than token".to_string(),
            ));
        }
        if size <= 4 {
            return Err(MacaroonError::DeserializationError(
                "packet chunk size too small".to_string(),
            ));
        }
        let packet_data = &remaining[4..size];
        let index = split_index(packet_data)?;
        let (key_slice, value_slice) = packet_data.split_at(index);
        if value_slice.len() < 2 {
            return Err(MacaroonError::DeserializationError(
                "packet value size too small".to_string(),
            ));
        }
        // skip beginning space and terminating \n
        let value_len = value_slice.len() - 2;
        check_field_size("v1 packet", value_len)?;
        packets.push(Packet {
            key: str::from_utf8(key_slice)?.to_owned(),
            value: value_slice[1..value_slice.len() - 1].to_vec(),
        });
        remaining = &remaining[size..];
    }
    Ok(packets)
}

fn split_index(packet: &[u8]) -> Result<usize> {
    match packet.iter().position(|&r| r == b' ') {
        Some(index) => Ok(index),
        None => Err(MacaroonError::DeserializationError(String::from(
            "Key/value error",
        ))),
    }
}

/// Takes a binary token (not base64-encoded)
pub fn deserialize(data: &[u8]) -> Result<Macaroon> {
    let mut builder: MacaroonBuilder = MacaroonBuilder::new();
    let mut caveat_builder: CaveatBuilder = CaveatBuilder::new();
    let mut seen_location = false;
    let mut seen_identifier = false;
    let mut seen_signature = false;
    for packet in deserialize_as_packets(data)? {
        // The signature must be the last packet: anything after it would be
        // silently dropped otherwise, letting one token have several byte
        // representations (and other implementations parse it differently).
        if seen_signature {
            return Err(MacaroonError::DeserializationError(String::from(
                "packet found after signature",
            )));
        }
        match packet.key.as_str() {
            LOCATION => {
                if seen_location {
                    return Err(MacaroonError::DeserializationError(String::from(
                        "duplicate location packet",
                    )));
                }
                seen_location = true;
                builder.set_location(&String::from_utf8(packet.value)?);
            }
            IDENTIFIER => {
                if seen_identifier {
                    return Err(MacaroonError::DeserializationError(String::from(
                        "duplicate identifier packet",
                    )));
                }
                seen_identifier = true;
                builder.set_identifier(ByteString(packet.value));
            }
            SIGNATURE => {
                seen_signature = true;
                if caveat_builder.has_id() {
                    builder.add_caveat(caveat_builder.build()?)?;
                    caveat_builder = CaveatBuilder::new();
                }
                if packet.value.len() != 32 {
                    error!(
                        "deserialize_v1: Deserialization error - signature length is {}",
                        packet.value.len()
                    );
                    return Err(MacaroonError::DeserializationError(String::from(
                        "Illegal signature \
                         length in \
                         packet",
                    )));
                }
                builder.set_signature(&packet.value);
            }
            CID => {
                if caveat_builder.has_id() {
                    builder.add_caveat(caveat_builder.build()?)?;
                    caveat_builder = CaveatBuilder::new();
                    caveat_builder.add_id(ByteString(packet.value));
                } else {
                    caveat_builder.add_id(ByteString(packet.value));
                }
            }
            VID => {
                if caveat_builder.has_verifier_id() {
                    return Err(MacaroonError::DeserializationError(String::from(
                        "duplicate vid packet in caveat",
                    )));
                }
                caveat_builder.add_verifier_id(ByteString(packet.value));
            }
            CL => {
                if caveat_builder.has_location() {
                    return Err(MacaroonError::DeserializationError(String::from(
                        "duplicate cl packet in caveat",
                    )));
                }
                caveat_builder.add_location(String::from_utf8(packet.value)?)
            }
            _ => {
                return Err(MacaroonError::DeserializationError(String::from(
                    "Unknown key",
                )));
            }
        };
    }
    builder.build()
}

#[cfg(test)]
mod tests {
    use super::URL_SAFE;
    use crate::{Caveat, Macaroon, MacaroonKey, STANDARD};
    use base64::Engine as _;

    #[test]
    fn test_deserialize() {
        let mut serialized = "MDAyMWxvY2F0aW9uIGh0dHA6Ly9leGFtcGxlLm9yZy8KMDAxNWlkZW50aWZpZXIga2V5aWQKMDAyZnNpZ25hdHVyZSB83ueSURxbxvUoSFgF3-myTnheKOKpkwH51xHGCeOO9wo";
        let mut signature: MacaroonKey = [
            124, 222, 231, 146, 81, 28, 91, 198, 245, 40, 72, 88, 5, 223, 233, 178, 78, 120, 94,
            40, 226, 169, 147, 1, 249, 215, 17, 198, 9, 227, 142, 247,
        ]
        .into();
        let data = URL_SAFE.decode(serialized).unwrap();
        let macaroon = super::deserialize(&data).unwrap();
        let macaroon_lib = Macaroon::deserialize(serialized).unwrap();
        assert_eq!(macaroon, macaroon_lib);
        assert!(macaroon.location().is_some());
        assert_eq!("http://example.org/", macaroon.location().unwrap());
        assert_eq!(b"keyid", macaroon.identifier());
        assert_eq!(&signature, macaroon.signature());
        serialized = "MDAyMWxvY2F0aW9uIGh0dHA6Ly9leGFtcGxlLm9yZy8KMDAxNWlkZW50aWZpZXIga2V5aWQKMDAxZGNpZCBhY2NvdW50ID0gMzczNTkyODU1OQowMDJmc2lnbmF0dXJlIPVIB_bcbt-Ivw9zBrOCJWKjYlM9v3M5umF2XaS9JZ2HCg";
        signature = [
            245, 72, 7, 246, 220, 110, 223, 136, 191, 15, 115, 6, 179, 130, 37, 98, 163, 98, 83,
            61, 191, 115, 57, 186, 97, 118, 93, 164, 189, 37, 157, 135,
        ]
        .into();
        let data = URL_SAFE.decode(serialized).unwrap();
        let macaroon = super::deserialize(&data).unwrap();
        assert!(macaroon.location().is_some());
        assert_eq!("http://example.org/", macaroon.location().unwrap());
        assert_eq!(b"keyid", macaroon.identifier());
        assert_eq!(1, macaroon.caveats().len());
        let predicate = match &macaroon.caveats()[0] {
            Caveat::FirstParty(fp) => fp.predicate().to_vec(),
            _ => vec![],
        };
        assert_eq!(b"account = 3735928559".to_vec(), predicate);
        assert_eq!(&signature, macaroon.signature());
    }

    #[test]
    fn test_deserialize_two_caveats() {
        let serialized = "MDAyMWxvY2F0aW9uIGh0dHA6Ly9leGFtcGxlLm9yZy8KMDAxNWlkZW50aWZpZXIga2V5aWQKMDAxZGNpZCBhY2NvdW50ID0gMzczNTkyODU1OQowMDE1Y2lkIHVzZXIgPSBhbGljZQowMDJmc2lnbmF0dXJlIEvpZ80eoMaya69qSpTumwWxWIbaC6hejEKpPI0OEl78Cg";
        let signature: MacaroonKey = [
            75, 233, 103, 205, 30, 160, 198, 178, 107, 175, 106, 74, 148, 238, 155, 5, 177, 88,
            134, 218, 11, 168, 94, 140, 66, 169, 60, 141, 14, 18, 94, 252,
        ]
        .into();
        let data = STANDARD.decode(serialized).unwrap();
        let macaroon = super::deserialize(&data).unwrap();
        let macaroon_lib = Macaroon::deserialize(serialized).unwrap();
        assert_eq!(macaroon, macaroon_lib);
        assert!(macaroon.location().is_some());
        assert_eq!("http://example.org/", macaroon.location().unwrap());
        assert_eq!(b"keyid", macaroon.identifier());
        assert_eq!(&signature, macaroon.signature());
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
    }

    #[test]
    fn test_serialize_deserialize() {
        let mut macaroon: Macaroon = Macaroon::create(
            Some("http://example.org/"),
            &MacaroonKey::generate(b"my key"),
            "keyid",
        )
        .unwrap();
        macaroon
            .add_first_party_caveat("account = 3735928559")
            .unwrap();
        macaroon.add_first_party_caveat("user = alice").unwrap();
        macaroon
            .add_third_party_caveat(
                "https://auth.mybank.com",
                &MacaroonKey::generate(b"caveat key"),
                "caveat",
            )
            .unwrap();
        let serialized = macaroon.serialize(super::super::Format::V1).unwrap();
        let deserialized = Macaroon::deserialize(&serialized).unwrap();
        assert_eq!(macaroon, deserialized);
    }

    #[test]
    fn test_max_field_size_roundtrips() {
        // The packet header caps a packet at 0xFFFF bytes, so the largest
        // predicate a V1 `cid` packet can carry is 0xFFFF - 4 - "cid" - 2
        // = 65526 bytes (this matches pymacaroons' maximum). That must
        // round-trip; one byte more must fail loudly at serialize time
        // instead of emitting a corrupt token.
        const MAX_V1_PREDICATE: usize = 0xFFFF - super::HEADER_SIZE - 2 - 3;
        let key = MacaroonKey::generate(b"key");
        let mut macaroon = Macaroon::create(Some("http://example.org/"), &key, "keyid").unwrap();
        let predicate = "x".repeat(MAX_V1_PREDICATE);
        macaroon.add_first_party_caveat(predicate.as_str()).unwrap();
        let serialized = macaroon.serialize(crate::Format::V1).unwrap();
        let deserialized = Macaroon::deserialize(&serialized).unwrap();
        assert_eq!(macaroon, deserialized);

        let mut oversized = Macaroon::create(Some("http://example.org/"), &key, "keyid").unwrap();
        oversized
            .add_first_party_caveat("x".repeat(MAX_V1_PREDICATE + 1).as_str())
            .unwrap();
        let err = oversized.serialize(crate::Format::V1).unwrap_err();
        assert!(matches!(err, crate::MacaroonError::FieldTooLarge { .. }));
        // ...while V2 serializes it fine
        assert!(oversized.serialize(crate::Format::V2).is_ok());
    }

    #[test]
    fn test_packet_after_signature_rejected() {
        let key = MacaroonKey::generate(b"key");
        let mut macaroon = Macaroon::create(Some("http://example.org/"), &key, "keyid").unwrap();
        macaroon.add_first_party_caveat("a = b").unwrap();
        let mut binary = super::serialize_binary(&macaroon).unwrap();
        assert!(super::deserialize(&binary).is_ok());
        binary.extend(super::serialize_as_packet(super::CID, b"dropped = caveat").unwrap());
        let err = super::deserialize(&binary).unwrap_err();
        assert!(err.to_string().contains("after signature"), "{}", err);
    }

    #[test]
    fn test_duplicate_packets_rejected() {
        let key = MacaroonKey::generate(b"key");
        let macaroon = Macaroon::create(Some("http://example.org/"), &key, "keyid").unwrap();
        let binary = super::serialize_binary(&macaroon).unwrap();

        // duplicate location / identifier before the rest of the token
        for tag in [super::LOCATION, super::IDENTIFIER] {
            let mut dup = super::serialize_as_packet(tag, b"http://example.org/").unwrap();
            dup.extend(&binary);
            let err = super::deserialize(&dup).unwrap_err();
            assert!(err.to_string().contains("duplicate"), "{}", err);
        }

        // duplicate vid / cl within a caveat
        for tag in [super::VID, super::CL] {
            let mut dup: Vec<u8> = Vec::new();
            dup.extend(super::serialize_as_packet(super::IDENTIFIER, b"keyid").unwrap());
            dup.extend(super::serialize_as_packet(super::CID, b"third-party-id").unwrap());
            dup.extend(super::serialize_as_packet(super::VID, b"vid-bytes").unwrap());
            dup.extend(super::serialize_as_packet(super::CL, b"http://auth/").unwrap());
            dup.extend(super::serialize_as_packet(tag, b"second-copy").unwrap());
            dup.extend(super::serialize_as_packet(super::SIGNATURE, &[7u8; 32]).unwrap());
            let err = super::deserialize(&dup).unwrap_err();
            assert!(err.to_string().contains("duplicate"), "{}", err);
        }
    }

    #[test]
    fn test_deserialize_bad_data() {
        // these are all expected to fail... but not panic!
        assert!(super::deserialize(b"").is_err());
        assert!(super::deserialize(b"12345").is_err());
        assert!(super::deserialize(b"\0").is_err());
        assert!(super::deserialize(b"NDhJe_A==").is_err());

        // these failed fuzz testing for this deserializer (V1)
        assert!(Macaroon::deserialize(vec![70, 70, 102, 70]).is_err());
        let tok = URL_SAFE.encode([97, 97, 97, 97, 97, 97, 97, 97, 97, 97, 10]);
        assert!(Macaroon::deserialize(tok.as_bytes()).is_err());
        let tok = URL_SAFE.encode([
            48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48,
            48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48,
            48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48,
            48, 48, 48, 48, 48, 48, 48, 44, 125, 59, 64,
        ]);
        assert!(Macaroon::deserialize(tok.as_bytes()).is_err());
        let tok = URL_SAFE.encode([
            48, 48, 49, 48, 49, 48, 52, 48, 48, 48, 48, 48, 48, 48, 48, 32, 126, 10,
        ]);
        assert!(Macaroon::deserialize(tok.as_bytes()).is_err());
    }
}
