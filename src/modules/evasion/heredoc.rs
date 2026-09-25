use rand::Rng;

use crate::core::engine::{OS, Obfuscate, ObfuscatorType};

pub struct HeredocObfuscator;

impl Obfuscate for HeredocObfuscator {
    fn apply(&self, command: &str, _os: OS) -> String {
        if command.is_empty() {
            return String::new();
        }
        let mut rng = rand::thread_rng();
        let delimiter = generate_delimiter(&mut rng);
        format!("bash <<{}\n{}\n{}", delimiter, command, delimiter)
    }

    fn module_type(&self) -> ObfuscatorType {
        ObfuscatorType::EvasionModule
    }
}

fn generate_delimiter(rng: &mut impl Rng) -> String {
    const HEX: &[u8] = b"0123456789abcdef";
    let suffix: String = (0..8)
        .map(|_| HEX[rng.gen_range(0..HEX.len())] as char)
        .collect();
    format!("__evasion_{}", suffix)
}
