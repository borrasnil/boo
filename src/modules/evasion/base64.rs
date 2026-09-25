use base64::Engine;

use crate::core::engine::{OS, Obfuscate, ObfuscatorType};

pub struct Base64Obfuscator;

impl Obfuscate for Base64Obfuscator {
    fn apply(&self, command: &str, _os: OS) -> String {
        if command.is_empty() {
            return String::new();
        }
        let encoded = base64::engine::general_purpose::STANDARD.encode(command.as_bytes());
        format!("echo '{}' | base64 -d | bash", encoded)
    }

    fn module_type(&self) -> ObfuscatorType {
        ObfuscatorType::EvasionModule
    }
}
