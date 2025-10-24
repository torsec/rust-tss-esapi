// TORSEC
// TPMI_ALG_MLDSA_SCHEME taken from crate, but not used until now
// I took it bcs is the only definition, 
// together with TPM2_MLDSA_PUBLIC_KEY_BYTES, TPM2_MLDSA_SECRET_KEY_BYTES, TPM2_MLDSA_SIGNATURE_BYTES,
// defined in the file "tss_esapi_bindings.rs", generated at compile time inside "out-br/".
use crate::{
    tss2_esys::{TPM2_MLDSA_PUBLIC_KEY_BYTES, TPMI_ALG_MLDSA_SCHEME},
    Error, Result, WrapperErrorKind,
};
use std::convert::TryFrom;
/// MLDSA interface type
///
/// # Details
/// This corresponds to MLDSA-87
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub enum Mldsa {
    Mldsa87,
}

impl From<Mldsa> for TPMI_ALG_MLDSA_SCHEME {
    fn from(mldsa_pub_key_bytes: Mldsa) -> TPMI_ALG_MLDSA_SCHEME {
        match mldsa_pub_key_bytes {
            Mldsa::Mldsa87 => 2592,
        }
    }
}

// use public here? not sure ..
impl TryFrom<TPMI_ALG_MLDSA_SCHEME> for Mldsa {
    type Error = Error;
    fn try_from(tpm2_mldsa_pub_key_bytes: TPMI_ALG_MLDSA_SCHEME) -> Result<Mldsa> {
        match tpm2_mldsa_pub_key_bytes {
            2592 => Ok(Mldsa::Mldsa87),
            _ => Err(Error::local_error(WrapperErrorKind::InvalidParam)),
        }
    }
}
