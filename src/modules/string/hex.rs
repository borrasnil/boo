use rand::Rng;

use crate::core::engine::{OS, Obfuscate, ObfuscatorType};
use crate::modules::tokenize;

pub struct HexObfuscator;

impl Obfuscate for HexObfuscator {
    fn apply(&self, command: &str, _os: OS) -> String {
        let mut rng = rand::thread_rng();
        let mut filter = tokenize::TransformFilter::new();
        tokenize::tokenize(command)
            .into_iter()
            .map(|tok| {
                if filter.should_transform(&tok) {
                    // Safe bare word: nothing bash can re-interpret, so each ASCII
                    // char may be stochastically escaped to $'\xHH'.
                    tok.chars()
                        .map(|c| {
                            if c.is_ascii() && rng.gen_bool(0.4) {
                                format!("$'\\x{:02x}'", c as u8)
                            } else {
                                c.to_string()
                            }
                        })
                        .collect::<String>()
                } else {
                    // Whitespace, operators, quoted/expansion regions, reserved
                    // words, assignments, loop vars — pass through untouched.
                    tok
                }
            })
            .collect()
    }

    fn module_type(&self) -> ObfuscatorType {
        ObfuscatorType::Encoder
    }
}
