use rand::Rng;

use crate::core::engine::{OS, Obfuscate, ObfuscatorType};
use crate::modules::tokenize;

pub struct QuotesObfuscator;

impl Obfuscate for QuotesObfuscator {
    fn apply(&self, command: &str, _os: OS) -> String {
        let mut rng = rand::thread_rng();
        let mut filter = tokenize::TransformFilter::new();
        tokenize::tokenize(command)
            .into_iter()
            .map(|tok| {
                if filter.should_transform(&tok) {
                    // Safe bare word: no shell operator, quote, expansion, glob,
                    // or reserved word — safe to quote-chop each char.
                    quote_word(&tok, &mut rng)
                } else {
                    // Whitespace, operators (`; | & > < ( )`), quoted regions,
                    // expansions, reserved words, assignments, loop vars must
                    // stay intact.
                    tok
                }
            })
            .collect()
    }

    fn module_type(&self) -> ObfuscatorType {
        ObfuscatorType::StringObfuscator
    }
}

fn quote_word(word: &str, rng: &mut impl Rng) -> String {
    #[derive(Clone, Copy)]
    enum QuoteStyle {
        Single, // 'c'
        Double, // "c"
        Bare,   // c
    }

    // Safe to leave unquoted in bash.
    let can_be_bare = |c: char| -> bool { tokenize::safe_char(c) };

    // These chars are special inside double quotes and must not be double-quoted.
    fn can_be_double_quoted(c: char) -> bool {
        !matches!(c, '"' | '$' | '`' | '\\' | '!')
    }

    // Single quotes cannot contain a literal single quote.
    fn can_be_single_quoted(c: char) -> bool {
        c != '\''
    }

    let mut result = String::new();
    for c in word.chars() {
        // Inject 0-2 random empty quote pairs as noise.
        for _ in 0..rng.gen_range(0u8..=2) {
            result.push_str(if rng.gen_bool(0.5) { "''" } else { "\"\"" });
        }

        let mut options = Vec::new();
        if can_be_bare(c) {
            options.push(QuoteStyle::Bare);
        }
        if can_be_single_quoted(c) {
            options.push(QuoteStyle::Single);
        }
        if can_be_double_quoted(c) {
            options.push(QuoteStyle::Double);
        }

        match options[rng.gen_range(0..options.len())] {
            QuoteStyle::Bare => result.push(c),
            QuoteStyle::Single => {
                result.push('\'');
                result.push(c);
                result.push('\'');
            }
            QuoteStyle::Double => {
                result.push('"');
                result.push(c);
                result.push('"');
            }
        }
    }
    result
}
