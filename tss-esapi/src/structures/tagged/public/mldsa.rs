use crate::{
    interface_types::{algorithm::MldsaSchemeAlgorithm, mldsa::Mldsa},
    structures::{MldsaScheme, SymmetricDefinitionObject},
    tss2_esys::{TPMS_MLDSA_PARMS, UINT32},
    Error, Result, WrapperErrorKind,
};
use log::error;
use std::convert::{TryFrom, TryInto};

/// Builder for `TPMS_RSA_PARMS` values.
#[derive(Copy, Clone, Default, Debug)]
pub struct PublicMldsaParametersBuilder {
    symmetric: Option<SymmetricDefinitionObject>,
    mldsa_scheme: Option<MldsaScheme>,
    mldsa: Option<Mldsa>,
    // In RSA there was also the "exponent" parameters
    is_signing_key: bool,
    is_decryption_key: bool,
    restricted: bool,
}

impl PublicMldsaParametersBuilder {
    /// Creates a new [PublicMldsaParametersBuilder]
    pub fn new() -> Self {
        PublicMldsaParametersBuilder { 
            symmetric: None, 
            mldsa_scheme: None, 
            mldsa: None, 
            is_signing_key: false, 
            is_decryption_key: false, 
            restricted: false, 
        }
    }

    /// Creates a [PublicMldsaParametersBuilder] that is setup
    /// to build a restricted decryption key.
    pub const fn new_restricted_decryption_key(
        symmetric: SymmetricDefinitionObject,
        mldsa: Mldsa,
    ) -> Self {
        PublicMldsaParametersBuilder { 
            symmetric: Some(symmetric), 
            mldsa_scheme: Some(MldsaScheme::Null), 
            mldsa: Some(mldsa), 
            is_signing_key: false, 
            is_decryption_key: true, 
            restricted: true, 
        }
    }

    /// Creates a [PublicMldsaParametersBuilder] that is setup
    /// to build an unrestricted signing key.
    pub const fn new_unrestricted_signing_key(
        mldsa_scheme: MldsaScheme,
        mldsa: Mldsa,
    ) -> Self {
        PublicMldsaParametersBuilder { 
            symmetric: None, 
            mldsa_scheme: Some(mldsa_scheme), 
            mldsa: Some(mldsa), 
            is_signing_key: true, 
            is_decryption_key: false, 
            restricted: false, 
        }
    }

    /// Adds a [SymmetricDefinitionObject] to the [PublicMldsaParametersBuilder].
    pub const fn with_symmetric(mut self, symmetric: SymmetricDefinitionObject) -> Self {
        self.symmetric = Some(symmetric);
        self
    }

    /// Adds a [MldsaScheme] to the [PublicMldsaParametersBuilder].
    pub fn with_scheme(mut self, mldsa_scheme: MldsaScheme) -> Self {
        self.mldsa_scheme = Some(mldsa_scheme);
        self
    }

    /// Adds [Mldsa] to the [PublicMldsaParameters].
    pub const fn with_mlsda(mut self, mldsa: Mldsa) -> Self {
        self.mldsa = Some(mldsa);
        self
    }

    /// Adds a flag that indicates if the key is going to be used
    /// for signing to the [PublicMldsaParametersBuilder].
    ///
    /// # Arguments
    /// * `set` - `true` inidcates that the key is going to be used for signing operations.
    ///           `false` indicates that the key is not going to be used for signing operations.
    pub const fn with_is_signing_key(mut self, set: bool) -> Self {
        self.is_signing_key = set;
        self
    }

    /// Adds a flag that indicates if the key is going to be used for
    /// decryption to the [PublicMldsaParametersBuilder].
    ///
    /// # Arguments
    /// * `set` - `true` indicates that the key is going to be used for decryption operations.
    ///           `false` indicates that the key is not going to be used for decryption operations.
    pub const fn with_is_decryption_key(mut self, set: bool) -> Self {
        self.is_decryption_key = set;
        self
    }

    /// Adds a flag that inidcates if the key is going to be restrictied to
    /// the [PublicMldsaParametersBuilder].
    ///
    /// # Arguments
    /// * `set` - `true` indicates that it is going to be a restricted key.
    ///           `false` indicates that it is going to be a non restricted key.
    pub const fn with_restricted(mut self, set: bool) -> Self {
        self.restricted = set;
        self
    }

    /// Build an object given the previously provided parameters.
    ///
    /// The only mandatory parameter is the asymmetric scheme.
    ///
    /// # Errors
    /// * if no asymmetric scheme is set, `ParamsMissing` wrapper error is returned.
    /// * if the `for_signing`, `for_decryption` and `restricted` parameters are
    ///   inconsistent with the rest of the parameters, `InconsistentParams` wrapper
    ///   error is returned
    pub fn build(self) -> Result<PublicMldsaParameters> {
        let mldsa_scheme = self.mldsa_scheme.ok_or_else(|| {
            error!("Scheme parameter is required and has not been set in the PublicMldsaParametersBuilder");
            Error::local_error(WrapperErrorKind::ParamsMissing)
        })?;

        // let mldsa = self.mldsa.ok_or_else(|| {
        //     error!("Mldsa parameter is required and has not been set in the PublicMldsaParametersBuilder");
        //     Error::local_error(WrapperErrorKind::ParamsMissing)
        // })?;


        // Some checks Copied from rsa.rs
        if self.restricted && self.is_decryption_key {
            if let Some(symmetric) = self.symmetric {
                if symmetric.is_null() {
                    error!("Found symmetric parameter but it was Null but 'restricted' and 'is_decrypt_key' are set to true");
                    return Err(Error::local_error(WrapperErrorKind::InconsistentParams));
                }
            } else {
                error!("Found symmetric parameter, expected it to be Null nor not set at all because 'restricted' and 'is_decrypt_key' are set to false");
                return Err(Error::local_error(WrapperErrorKind::ParamsMissing));
            }
        } else if let Some(symmetric) = self.symmetric {
            if !symmetric.is_null() {
                error!("Found symmetric parameter, expected it to be Null nor not set at all because 'restricted' and 'is_decrypt_key' are set to false");
                return Err(Error::local_error(WrapperErrorKind::InconsistentParams));
            }
        }

        // let symmetric_definition_object = self.symmetric.unwrap_or(SymmetricDefinitionObject::Null);
        // Other checks that seemed related just to rsa not included

        Ok(PublicMldsaParameters { 
            // symmetric_definition_object, 
            mldsa_scheme, 
            // mldsa, 
        })
    }
}

/// Structure holding the MLDSA specific parameters.
///
/// # Details
/// This corresponds to TPMS_MLDSA_PARMS
///
/// These mldsa parameters are specific to the [`crate::structures::Public`] type.
#[derive(Clone, Debug, Copy, PartialEq, Eq)]
pub struct PublicMldsaParameters {
    // symmetric_definition_object: SymmetricDefinitionObject,
    mldsa_scheme: MldsaScheme,
    // mldsa: Mldsa,
}

impl PublicMldsaParameters {
    /// Function for creating new [PublicMldsaParameters] structure
    pub const fn new(
        // symmetric_definition_object: SymmetricDefinitionObject,
        mldsa_scheme: MldsaScheme,
        // mldsa: Mldsa,
    ) -> Self {
        PublicMldsaParameters { 
            // symmetric_definition_object, 
            mldsa_scheme, 
            // mldsa, 
        }
    }

    // /// Returns the [SymmetricDefinitionObject].
    // pub const fn symmetric_definition_object(&self) -> SymmetricDefinitionObject {
    //     self.symmetric_definition_object
    // }

    /// Returns the [MldsaScheme]
    pub const fn mldsa_scheme(&self) -> MldsaScheme {
        self.mldsa_scheme
    }

    // /// Returns the [Mldsa]
    // pub const fn mldsa(&self) -> Mldsa {
    //     self.mldsa
    // }

    /// Get a builder for this structure
    pub fn builder() -> PublicMldsaParametersBuilder {
        PublicMldsaParametersBuilder::new()
    }
}

impl From<PublicMldsaParameters> for TPMS_MLDSA_PARMS {
    fn from(public_mldsa_parameters: PublicMldsaParameters) -> Self {
        TPMS_MLDSA_PARMS {
            // symmetric: public_mldsa_parameters.symmetric_definition_object.into(),
            scheme: public_mldsa_parameters.mldsa_scheme.into(),
            // mldsa: public_mldsa_parameters.mldsa.into(),
        }
    }
}

impl TryFrom<TPMS_MLDSA_PARMS> for PublicMldsaParameters {
    type Error = Error;

    fn try_from(tpms_mldsa_parms: TPMS_MLDSA_PARMS) -> Result<Self> {
        Ok(PublicMldsaParameters {
            // symmetric_definition_object: tpms_mldsa_parms.symmetric.try_into()?,
            mldsa_scheme: tpms_mldsa_parms.scheme.try_into()?,
            // mldsa: tpms_mldsa_parms.mldsa.try_into()?,
        })
    }
}