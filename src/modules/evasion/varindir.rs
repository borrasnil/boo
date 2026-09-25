use rand::Rng;

use crate::core::engine::{OS, Obfuscate, ObfuscatorType};

pub struct VarIndirObfuscator;

impl Obfuscate for VarIndirObfuscator {
    fn apply(&self, command: &str, _os: OS) -> String {
        if command.is_empty() {
            return String::new();
        }
        let mut rng = rand::thread_rng();

        let chars: Vec<char> = command.chars().collect();
        let len = chars.len();

        // Split into 3-7 segments at random positions
        let num_vars: usize = rng.gen_range(3..=7);
        let mut splits: Vec<usize> = Vec::new();
        for _ in 0..num_vars - 1 {
            splits.push(rng.gen_range(1..len));
        }
        splits.sort();
        splits.dedup();

        // Build segments from split points
        let mut segments: Vec<String> = Vec::new();
        let mut prev = 0;
        for &s in &splits {
            segments.push(chars[prev..s].iter().collect());
            prev = s;
        }
        segments.push(chars[prev..].iter().collect());

        // Generate variable assignments
        let mut assignments = Vec::new();
        let mut names = Vec::new();
        for seg in &segments {
            let name = random_var_name(&mut rng);
            let escaped = seg.replace('\'', "'\\''");
            assignments.push(format!("{}='{}'", name, escaped));
            names.push(name);
        }

        // Build eval concatenation: eval "${_a}${_b}${_c}..."
        let concat_expr: String = names
            .iter()
            .map(|n| format!("${{{}}}", n))
            .collect::<Vec<_>>()
            .join("");

        format!("{}; eval \"{}\"", assignments.join("; "), concat_expr)
    }

    fn module_type(&self) -> ObfuscatorType {
        ObfuscatorType::EvasionModule
    }
}

fn random_var_name(rng: &mut impl Rng) -> String {
    const CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let len = rng.gen_range(2..=4);
    let suffix: String = (0..len)
        .map(|_| CHARS[rng.gen_range(0..CHARS.len())] as char)
        .collect();
    format!("_{}", suffix)
}
