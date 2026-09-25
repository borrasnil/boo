use super::{OS, ObfuscatorType};

pub trait Obfuscate {
    fn apply(&self, command: &str, os: OS) -> String;
    fn module_type(&self) -> ObfuscatorType;
}
