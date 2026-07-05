use crate::caveat::{Caveat, CaveatBuilder};
use crate::error::MacaroonError;
use crate::serialization::macaroon_builder::MacaroonBuilder;
use crate::{check_field_size, ByteString, Macaroon, Result, URL_SAFE};
use base64::Engine as _;

// Version 2 fields
const EOS: u8 = 0;
const LOCATION: u8 = 1;
const IDENTIFIER: u8 = 2;
const VID: u8 = 4;
const SIGNATURE: u8 = 6;

const VARINT_PACK_SIZE: usize = 128;

fn varint_size(size: usize) -> Vec<u8> {
    let mut buffer: Vec<u8> = Vec::new();
    let mut my_size: usize = size;
    while my_size >= VARINT_PACK_SIZE {
        buffer.push(((my_size & (VARINT_PACK_SIZE - 1)) | VARINT_PACK_SIZE) as u8);
        my_size >>= 7;
    }
    buffer.push(my_size as u8);

    buffer
}

fn serialize_field(tag: u8, value: &[u8], buffer: &mut Vec<u8>) {
    buffer.push(tag);
    buffer.extend(varint_size(value.len()));
    buffer.extend(value);
}

pub fn serialize_binary(macaroon: &Macaroon) -> Result<Vec<u8>> {
    let mut buffer: Vec<u8> = vec![2 /* version */];
    if let Some(location) = macaroon.location() {
        serialize_field(LOCATION, location.as_bytes(), &mut buffer);
    };
    serialize_field(IDENTIFIER, macaroon.identifier(), &mut buffer);
    buffer.push(EOS);
    for c in macaroon.caveats() {
        match c {
            Caveat::FirstParty(fp) => {
                serialize_field(IDENTIFIER, fp.predicate(), &mut buffer);
                buffer.push(EOS);
            }
            Caveat::ThirdParty(tp) => {
                serialize_field(LOCATION, tp.location().as_bytes(), &mut buffer);
                serialize_field(IDENTIFIER, tp.id(), &mut buffer);
                serialize_field(VID, tp.verifier_id(), &mut buffer);
                buffer.push(EOS);
            }
        }
    }
    buffer.push(EOS);
    serialize_field(SIGNATURE, macaroon.signature().as_ref(), &mut buffer);
    Ok(buffer)
}

pub fn serialize(macaroon: &Macaroon) -> Result<String> {
    let buf = serialize_binary(macaroon)?;
    Ok(URL_SAFE.encode(&buf))
}

struct Deserializer<'r> {
    data: &'r [u8],
    index: usize,
}

impl<'r> Deserializer<'r> {
    pub fn new(data: &[u8]) -> Deserializer<'_> {
        Deserializer { data, index: 0 }
    }

    fn get_byte(&mut self) -> Result<u8> {
        if self.data.is_empty() || self.index > self.data.len() - 1 {
            return Err(MacaroonError::DeserializationError(String::from(
                "Buffer overrun",
            )));
        }
        let byte = self.data[self.index];
        self.index += 1;
        Ok(byte)
    }

    pub fn get_tag(&mut self) -> Result<u8> {
        self.get_byte()
    }

    pub fn get_eos(&mut self) -> Result<u8> {
        let eos = self.get_byte()?;
        match eos {
            EOS => Ok(eos),
            _ => Err(MacaroonError::DeserializationError(String::from(
                "Expected EOS",
            ))),
        }
    }

    pub fn get_field(&mut self) -> Result<Vec<u8>> {
        let size: usize = self.get_field_size()?;
        if size + self.index > self.data.len() {
            return Err(MacaroonError::DeserializationError(String::from(
                "Unexpected end of \
                 field",
            )));
        }

        let field: Vec<u8> = self.data[self.index..self.index + size].to_vec();
        self.index += size;
        Ok(field)
    }

    fn get_field_size(&mut self) -> Result<usize> {
        let mut size: usize = 0;
        let mut shift: usize = 0;
        let mut byte: u8;
        while shift <= (usize::BITS - 8) as usize {
            byte = self.get_byte()?;
            if byte & 128 != 0 {
                size |= ((byte & 127) as usize) << shift;
            } else {
                // A zero terminal byte after a continuation byte encodes the
                // same value in more bytes (e.g. `80 00` for 0). Reject it so
                // every field size has exactly one encoding.
                if byte == 0 && shift > 0 {
                    return Err(MacaroonError::DeserializationError(String::from(
                        "non-canonical field size",
                    )));
                }
                size |= (byte as usize) << shift;
                check_field_size("v2 field", size)?;
                return Ok(size);
            }
            shift += 7;
        }
        Err(MacaroonError::DeserializationError(String::from(
            "Error in field size",
        )))
    }

    fn is_exhausted(&self) -> bool {
        self.index >= self.data.len()
    }
}

/// Takes a binary token (not base64-encoded)
pub fn deserialize(data: &[u8]) -> Result<Macaroon> {
    let mut builder: MacaroonBuilder = MacaroonBuilder::new();
    let mut deserializer: Deserializer = Deserializer::new(data);
    if deserializer.get_byte()? != 2 {
        return Err(MacaroonError::DeserializationError(String::from(
            "Wrong version number",
        )));
    }
    let mut tag: u8 = deserializer.get_tag()?;
    match tag {
        LOCATION => builder.set_location(&String::from_utf8(deserializer.get_field()?)?),
        IDENTIFIER => builder.set_identifier(ByteString(deserializer.get_field()?)),
        _ => {
            return Err(MacaroonError::DeserializationError(String::from(
                "Identifier not found",
            )))
        }
    }
    if builder.has_location() {
        tag = deserializer.get_tag()?;
        match tag {
            IDENTIFIER => {
                builder.set_identifier(ByteString(deserializer.get_field()?));
            }
            _ => {
                return Err(MacaroonError::DeserializationError(String::from(
                    "Identifier not \
                     found",
                )))
            }
        }
    }
    deserializer.get_eos()?;
    tag = deserializer.get_tag()?;
    while tag != EOS {
        let mut caveat_builder: CaveatBuilder = CaveatBuilder::new();
        match tag {
            LOCATION => {
                let field: Vec<u8> = deserializer.get_field()?;
                caveat_builder.add_location(String::from_utf8(field)?);
            }
            IDENTIFIER => caveat_builder.add_id(ByteString(deserializer.get_field()?)),
            _ => {
                return Err(MacaroonError::DeserializationError(String::from(
                    "Caveat identifier \
                     not found",
                )))
            }
        }
        if caveat_builder.has_location() {
            tag = deserializer.get_tag()?;
            match tag {
                IDENTIFIER => {
                    let field: Vec<u8> = deserializer.get_field()?;
                    caveat_builder.add_id(ByteString(field));
                }
                _ => {
                    return Err(MacaroonError::DeserializationError(String::from(
                        "Caveat identifier \
                         not found",
                    )))
                }
            }
        }
        tag = deserializer.get_tag()?;
        match tag {
            VID => {
                let field: Vec<u8> = deserializer.get_field()?;
                caveat_builder.add_verifier_id(ByteString(field));
                builder.add_caveat(caveat_builder.build()?)?;
                deserializer.get_eos()?;
                tag = deserializer.get_tag()?;
            }
            EOS => {
                builder.add_caveat(caveat_builder.build()?)?;
                tag = deserializer.get_tag()?;
            }
            _ => {
                return Err(MacaroonError::DeserializationError(
                    "Unexpected caveat tag found".into(),
                ))
            }
        }
    }
    tag = deserializer.get_tag()?;
    if tag == SIGNATURE {
        let sig: Vec<u8> = deserializer.get_field()?;
        if sig.len() != 32 {
            return Err(MacaroonError::DeserializationError(
                "Bad signature length".into(),
            ));
        }
        builder.set_signature(&sig);
    } else {
        return Err(MacaroonError::DeserializationError(
            "Unexpected tag found".into(),
        ));
    }
    // The signature is the final field; trailing bytes would be silently
    // ignored otherwise, letting one token have many byte representations.
    if !deserializer.is_exhausted() {
        return Err(MacaroonError::DeserializationError(
            "trailing data after signature".into(),
        ));
    }
    builder.build()
}

#[cfg(test)]
mod tests {
    use crate::caveat;
    use crate::caveat::Caveat;
    use crate::serialization::macaroon_builder::MacaroonBuilder;
    use crate::{Macaroon, MacaroonKey, URL_SAFE};
    use base64::Engine as _;

    #[test]
    fn test_deserialize() {
        const SERIALIZED: &str = "AgETaHR0cDovL2V4YW1wbGUub3JnLwIFa2V5aWQAAhRhY2NvdW50ID0gMzczNTkyODU1OQACDHVzZXIgPSBhbGljZQAABiBL6WfNHqDGsmuvakqU7psFsViG2guoXoxCqTyNDhJe_A==";
        const SIGNATURE: [u8; 32] = [
            75, 233, 103, 205, 30, 160, 198, 178, 107, 175, 106, 74, 148, 238, 155, 5, 177, 88,
            134, 218, 11, 168, 94, 140, 66, 169, 60, 141, 14, 18, 94, 252,
        ];
        let serialized: Vec<u8> = URL_SAFE.decode(SERIALIZED).unwrap();
        let macaroon = super::deserialize(&serialized).unwrap();
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
    fn test_serialize() {
        const SERIALIZED: &str = "AgETaHR0cDovL2V4YW1wbGUub3JnLwIFa2V5aWQAAhRhY2NvdW50ID0gMzczNTkyODU1OQACDHVzZXIgPSBhbGljZQAABiBL6WfNHqDGsmuvakqU7psFsViG2guoXoxCqTyNDhJe_A==";
        const SIGNATURE: [u8; 32] = [
            75, 233, 103, 205, 30, 160, 198, 178, 107, 175, 106, 74, 148, 238, 155, 5, 177, 88,
            134, 218, 11, 168, 94, 140, 66, 169, 60, 141, 14, 18, 94, 252,
        ];
        let mut builder = MacaroonBuilder::new();
        builder
            .add_caveat(caveat::new_first_party("account = 3735928559".into()))
            .unwrap();
        builder
            .add_caveat(caveat::new_first_party("user = alice".into()))
            .unwrap();
        builder.set_location("http://example.org/");
        builder.set_identifier("keyid".into());
        builder.set_signature(&SIGNATURE);
        let serialized = super::serialize(&builder.build().unwrap()).unwrap();
        assert_eq!(SERIALIZED, serialized);
    }

    #[test]
    fn test_serialize_deserialize() {
        let mut macaroon = Macaroon::create(
            Some("http://example.org/"),
            &MacaroonKey::generate(b"key"),
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
        let serialized = super::serialize_binary(&macaroon).unwrap();
        macaroon = super::deserialize(&serialized).unwrap();
        assert_eq!("http://example.org/", macaroon.location().unwrap());
        assert_eq!(b"keyid", macaroon.identifier());
        assert_eq!(3, macaroon.caveats().len());
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
        let id = match &macaroon.caveats()[2] {
            Caveat::ThirdParty(tp) => tp.id().to_vec(),
            _ => vec![],
        };
        assert_eq!(b"caveat".to_vec(), id);
        let location = match &macaroon.caveats()[2] {
            Caveat::ThirdParty(tp) => tp.location().to_string(),
            _ => String::default(),
        };
        assert_eq!("https://auth.mybank.com", location);
    }

    #[test]
    fn test_trailing_data_rejected() {
        let key = MacaroonKey::generate(b"key");
        let mut macaroon = Macaroon::create(Some("http://example.org/"), &key, "keyid").unwrap();
        macaroon.add_first_party_caveat("a = b").unwrap();
        let mut binary = super::serialize_binary(&macaroon).unwrap();
        assert!(super::deserialize(&binary).is_ok());
        binary.push(0);
        let err = super::deserialize(&binary).unwrap_err();
        assert!(err.to_string().contains("trailing data"), "{}", err);
    }

    #[test]
    fn test_non_canonical_varint_rejected() {
        // version, identifier tag, varint(5), "keyid", EOS, EOS,
        // signature tag, varint(32), 32 signature bytes
        let mut canonical: Vec<u8> = vec![2, 2, 0x05];
        canonical.extend(b"keyid");
        canonical.extend([0, 0, 6, 0x20]);
        canonical.extend([7u8; 32]);
        assert!(super::deserialize(&canonical).is_ok());

        // same token with the identifier length encoded as `85 00`
        // (5 | continuation bit, then a zero terminal byte)
        let mut padded: Vec<u8> = vec![2, 2, 0x85, 0x00];
        padded.extend(b"keyid");
        padded.extend([0, 0, 6, 0x20]);
        padded.extend([7u8; 32]);
        let err = super::deserialize(&padded).unwrap_err();
        assert!(err.to_string().contains("non-canonical"), "{}", err);
    }

    #[test]
    fn test_deserialize_bad_data() {
        // these are all expected to fail... but not panic!
        assert!(super::deserialize(b"").is_err());
        assert!(super::deserialize(b"12345").is_err());
        assert!(super::deserialize(b"\0").is_err());

        // these failed fuzz testing for this deserializer (V2)
        assert!(Macaroon::deserialize(vec![2, 2, 212, 212, 212, 212]).is_err());
    }
}
