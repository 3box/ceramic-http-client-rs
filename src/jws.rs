use std::{collections::BTreeMap, str::FromStr};

use ceramic_event::{
    ssi, unvalidated::signed::Signer, Base64String, Base64UrlString, Cid, MultiBase32String,
};
use serde::{Deserialize, Serialize};

/// The fields associated with the signature used to sign a JWS
#[derive(Debug, Serialize, Deserialize)]
pub struct JwsSignature {
    /// Protected header
    pub protected: Option<Base64String>,
    /// Signature
    pub signature: Base64UrlString,
}

/// Builder used to create JWS
pub struct JwsBuilder<S> {
    signer: S,
    additional: BTreeMap<String, serde_json::Value>,
}

impl<S: Signer> JwsBuilder<S> {
    /// Create a new JwsBuilder with a signer
    pub fn new(signer: S) -> Self {
        Self {
            signer,
            additional: BTreeMap::new(),
        }
    }

    /// Add additional information to the JWS
    pub fn with_additional(mut self, key: String, value: serde_json::Value) -> Self {
        self.additional.insert(key, value);
        self
    }

    /// Replace the additional information in the JWS
    pub fn replace_additional(mut self, additional: BTreeMap<String, serde_json::Value>) -> Self {
        self.additional = additional;
        self
    }

    /// Build a JWS for a CID. This is used to define a link to other data.
    pub fn build_for_cid(self, cid: &Cid) -> anyhow::Result<Jws> {
        let cid_str = Base64UrlString::from_cid(cid);
        let link = MultiBase32String::try_from(cid)?;
        Jws::new(&self.signer, cid_str, Some(link), self.additional)
    }

    /// Build a JWS for with data as the payload.
    pub fn build_for_data<T: Serialize>(self, input: &T) -> anyhow::Result<Jws> {
        let input = serde_json::to_vec(input)?;
        let input = Base64UrlString::from(input);
        Jws::new(&self.signer, input, None, self.additional)
    }
}

/// A JWS object
#[derive(Debug, Serialize, Deserialize)]
pub struct Jws {
    /// Link to CID that contains encoded data
    #[serde(skip_serializing_if = "Option::is_none")]
    pub link: Option<MultiBase32String>,
    /// Encoded data
    pub payload: Base64UrlString,
    /// The signatures of the JWS
    pub signatures: Vec<JwsSignature>,
}

impl Jws {
    /// Create a builder for Jws objects
    pub fn builder<S: Signer>(signer: S) -> JwsBuilder<S> {
        JwsBuilder::new(signer)
    }

    /// Creates a new JWS from a payload that has already been serialized to Base64UrlString
    pub fn new(
        signer: &impl Signer,
        input: Base64UrlString,
        link: Option<MultiBase32String>,
        additional_parameters: BTreeMap<String, serde_json::Value>,
    ) -> anyhow::Result<Self> {
        let alg = signer.algorithm();
        let header = ssi::jws::Header {
            algorithm: alg,
            type_: Some("JWT".to_string()),
            key_id: Some(signer.id().id.clone()),
            additional_parameters,
            ..Default::default()
        };
        // creates compact signature of protected.signature
        let header_str = Base64String::from(serde_json::to_vec(&header)?);
        let signing_input = format!("{}.{}", header_str.as_ref(), input.as_ref());
        let signed = signer.sign(signing_input.as_bytes())?;
        Ok(Self {
            link,
            payload: input,
            signatures: vec![JwsSignature {
                protected: Some(header_str),
                signature: signed.into(),
            }],
        })
    }

    /// Get the payload of this jws
    pub fn payload(&self) -> &Base64UrlString {
        &self.payload
    }

    /// Get the additional parameters of the jws signature
    pub fn additional(&self) -> anyhow::Result<BTreeMap<String, serde_json::Value>> {
        let first = self
            .signatures
            .first()
            .ok_or_else(|| anyhow::anyhow!("No signatures"))?;
        let protected = first
            .protected
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("No protected header"))?;
        let protected = serde_json::from_slice::<ssi::jws::Header>(&protected.to_vec()?)?;
        Ok(protected.additional_parameters)
    }

    /// Get the capability field for this jws
    pub fn capability(&self) -> anyhow::Result<Cid> {
        let additional = self.additional()?;
        let cap = additional
            .get("cap")
            .ok_or_else(|| anyhow::anyhow!("No cap"))?
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("cap is not a string"))?;
        let cid = Cid::from_str(cap)?;
        Ok(cid)
    }
}
