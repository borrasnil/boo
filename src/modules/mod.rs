use clap::ValueEnum;

use crate::core::engine::{OS, Obfuscate, ObfuscatorType};
use evasion::base64::Base64Obfuscator;
use evasion::exec_mask::ExecMaskObfuscator;
use evasion::heredoc::HeredocObfuscator;
use evasion::varindir::VarIndirObfuscator;
use string::hex::HexObfuscator;
use string::param::ParamObfuscator;
use string::quotes::QuotesObfuscator;

pub mod evasion;
pub mod interpreter;
pub mod string;
pub mod tokenize;

pub use tokenize::{TransformFilter, safe_char, tokenize};

/// All functional obfuscation modules in one dispatchable enum.
/// EDR evasion modules (Base64, VarIndir, ExecMask, Heredoc) are opt-in only;
/// they do NOT appear in `all()`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
#[value(rename_all = "kebab-case")]
pub enum AllModules {
    // Default modules (included in `all()`)
    Quotes,
    Hex,
    Param,
    // EDR evasion modules (opt-in only, excluded from `all()`)
    #[value(alias = "b64")]
    Base64,
    #[value(alias = "varindir")]
    VarIndir,
    #[value(alias = "exec")]
    ExecMask,
    Heredoc,
}

impl AllModules {
    /// Returns the default functional modules (no evasion).
    pub fn all() -> Vec<Self> {
        vec![Self::Quotes, Self::Hex, Self::Param]
    }
}

impl Obfuscate for AllModules {
    fn apply(&self, command: &str, os: OS) -> String {
        match self {
            Self::Quotes => QuotesObfuscator.apply(command, os),
            Self::Hex => HexObfuscator.apply(command, os),
            Self::Param => ParamObfuscator.apply(command, os),
            Self::Base64 => Base64Obfuscator.apply(command, os),
            Self::VarIndir => VarIndirObfuscator.apply(command, os),
            Self::ExecMask => ExecMaskObfuscator.apply(command, os),
            Self::Heredoc => HeredocObfuscator.apply(command, os),
        }
    }

    fn module_type(&self) -> ObfuscatorType {
        match self {
            Self::Quotes => QuotesObfuscator.module_type(),
            Self::Hex => HexObfuscator.module_type(),
            Self::Param => ParamObfuscator.module_type(),
            Self::Base64 => Base64Obfuscator.module_type(),
            Self::VarIndir => VarIndirObfuscator.module_type(),
            Self::ExecMask => ExecMaskObfuscator.module_type(),
            Self::Heredoc => HeredocObfuscator.module_type(),
        }
    }
}
