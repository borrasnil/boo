use crate::core::engine::{OS, Obfuscate, ObfuscatorType};

pub struct ExecMaskObfuscator;

impl Obfuscate for ExecMaskObfuscator {
    fn apply(&self, command: &str, _os: OS) -> String {
        if command.is_empty() {
            return String::new();
        }
        let escaped = command.replace('\'', "'\\''");
        format!("exec bash -c '{}'", escaped)
    }

    fn module_type(&self) -> ObfuscatorType {
        ObfuscatorType::EvasionModule
    }
}
