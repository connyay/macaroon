use crate::ByteString;
use crate::Result;
use crate::crypto;
use crate::error::MacaroonError;
use crypto::MacaroonKey;
use std::fmt::Debug;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Caveat {
    FirstParty(FirstParty),
    ThirdParty(ThirdParty),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FirstParty {
    predicate: ByteString,
}

impl FirstParty {
    pub fn predicate(&self) -> &[u8] {
        &self.predicate.0
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ThirdParty {
    id: ByteString,
    verifier_id: ByteString,
    location: String,
}

impl ThirdParty {
    pub fn id(&self) -> &[u8] {
        &self.id.0
    }
    pub fn verifier_id(&self) -> &[u8] {
        &self.verifier_id.0
    }
    pub fn location(&self) -> &str {
        &self.location
    }
}

impl Caveat {
    pub(crate) fn sign(&self, key: &MacaroonKey) -> MacaroonKey {
        match self {
            Self::FirstParty(fp) => crypto::hmac(key, &fp.predicate),
            Self::ThirdParty(tp) => crypto::hmac2(key, &tp.verifier_id, &tp.id),
        }
    }

    /// Returns the inner [`FirstParty`] if this is a first-party caveat.
    ///
    /// Lets callers skip an explicit `match` when they already know (or want
    /// to filter for) the caveat kind.
    pub fn as_first_party(&self) -> Option<&FirstParty> {
        match self {
            Self::FirstParty(fp) => Some(fp),
            Self::ThirdParty(_) => None,
        }
    }

    /// Returns the inner [`ThirdParty`] if this is a third-party caveat.
    pub fn as_third_party(&self) -> Option<&ThirdParty> {
        match self {
            Self::ThirdParty(tp) => Some(tp),
            Self::FirstParty(_) => None,
        }
    }
}

pub(crate) fn new_first_party(predicate: ByteString) -> Caveat {
    Caveat::FirstParty(FirstParty { predicate })
}

pub(crate) fn new_third_party(id: ByteString, verifier_id: ByteString, location: &str) -> Caveat {
    Caveat::ThirdParty(ThirdParty {
        id,
        verifier_id,
        location: String::from(location),
    })
}

#[derive(Default)]
pub(crate) struct CaveatBuilder {
    id: Option<ByteString>,
    verifier_id: Option<ByteString>,
    location: Option<String>,
}

impl CaveatBuilder {
    pub(crate) fn new() -> Self {
        Default::default()
    }

    pub(crate) fn add_id(&mut self, id: ByteString) {
        self.id = Some(id);
    }

    pub(crate) fn has_id(&self) -> bool {
        self.id.is_some()
    }

    pub(crate) fn add_verifier_id(&mut self, vid: ByteString) {
        self.verifier_id = Some(vid);
    }

    pub(crate) fn has_verifier_id(&self) -> bool {
        self.verifier_id.is_some()
    }

    pub(crate) fn add_location(&mut self, location: String) {
        self.location = Some(location);
    }

    pub(crate) fn has_location(&self) -> bool {
        self.location.is_some()
    }

    pub(crate) fn build(self) -> Result<Caveat> {
        let id = self
            .id
            .ok_or(MacaroonError::IncompleteCaveat("no identifier found"))?;
        match (self.verifier_id, self.location) {
            (None, None) => Ok(new_first_party(id)),
            (Some(vid), Some(location)) => Ok(new_third_party(id, vid, &location)),
            (None, Some(_)) => Err(MacaroonError::IncompleteCaveat("no verifier ID found")),
            (Some(_), None) => Err(MacaroonError::IncompleteCaveat("no location found")),
        }
    }
}
