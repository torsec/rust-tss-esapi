
use crate::{
    interface_types::{algorithm::AsymmetricAlgorithm, mldsa::Mldsa},
    //structures::{MldsaScheme, SymmetricDefinitionObject},
    Error, Result, WrapperErrorKind,
};

use log::error;
use std::convert::{TryFrom, TryInto};