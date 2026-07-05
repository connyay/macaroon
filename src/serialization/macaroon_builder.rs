use crate::caveat::Caveat;
use crate::error::MacaroonError;
use crate::{ByteString, MAX_CAVEATS, Macaroon, MacaroonKey, Result};

pub(crate) struct MacaroonBuilder {
    identifier: ByteString,
    location: Option<String>,
    signature: Option<MacaroonKey>,
    caveats: Vec<Caveat>,
}

impl MacaroonBuilder {
    pub(crate) fn new() -> MacaroonBuilder {
        MacaroonBuilder {
            identifier: Default::default(),
            location: None,
            signature: None,
            caveats: Default::default(),
        }
    }

    pub(crate) fn set_identifier(&mut self, identifier: ByteString) {
        self.identifier = identifier;
    }

    pub(crate) fn set_location(&mut self, location: &str) {
        self.location = Some((*location).to_string());
    }

    pub(crate) fn has_location(&self) -> bool {
        self.location.is_some()
    }

    /// Sets the signature from a 32-byte slice. Callers (the V1/V2/V2JSON
    /// deserializers) are responsible for length-checking before calling —
    /// panics if `signature.len() != 32`.
    pub(crate) fn set_signature(&mut self, signature: &[u8]) {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(signature);
        self.signature = Some(MacaroonKey::from(arr));
    }

    pub(crate) fn add_caveat(&mut self, caveat: Caveat) -> Result<()> {
        if self.caveats.len() >= MAX_CAVEATS {
            return Err(MacaroonError::TooManyCaveats);
        }
        self.caveats.push(caveat);
        Ok(())
    }

    pub(crate) fn build(&self) -> Result<Macaroon> {
        if self.identifier.0.is_empty() {
            return Err(MacaroonError::IncompleteMacaroon("no identifier found"));
        }
        let signature = self
            .signature
            .clone()
            .ok_or(MacaroonError::IncompleteMacaroon("no signature found"))?;

        Ok(Macaroon {
            identifier: self.identifier.clone(),
            location: self.location.clone(),
            signature,
            caveats: self.caveats.clone(),
        })
    }
}
