use rand::Rng;

use crate::core::engine::{OS, Obfuscate, ObfuscatorType};
use crate::modules::tokenize;
use crate::utils;

pub struct ParamObfuscator;

// # ## % %% (prefix/suffix stripping) are valid since bash 2 and zsh.
// ^^ ,, ^ , (case modifiers) require bash 4+ — not available on macOS default bash 3.2.
const MODIFIERS: &[&str] = &["#", "##", "%", "%%"];

impl Obfuscate for ParamObfuscator {
    fn apply(&self, command: &str, _os: OS) -> String {
        let mut rng = rand::thread_rng();
        let toks = tokenize::tokenize(command);
        let mut out = String::new();
        let mut prev: Option<&str> = None;
        let mut pending_loop_var = false;
        // Whether the upcoming non-whitespace token starts a new word. An
        // operator token (`;`, `|`, `&&`, ...) or whitespace resets the flag so
        // the next token is a boundary; tokens glued to the previous one (e.g.
        // the adjacent quote/hex segments `'e''c''h''o'`) are not, so junk never
        // splices open their existing quoting.
        let mut at_boundary = false;
        for tok in &toks {
            if tok.chars().all(char::is_whitespace) {
                out.push_str(tok);
                prev = None;
                at_boundary = true;
                continue;
            }
            // Feed reserved-word / loop-var state regardless of boundary: `for`
            // and `select` put the next word under protection even if the junk
            // gate (boundary/probability) keeps us from reaching should_inject.
            let is_loop_var = pending_loop_var;
            pending_loop_var = false;
            if tok == "for" || tok == "select" {
                pending_loop_var = true;
            } else if is_loop_var {
                out.push_str(tok);
                prev = Some(tok);
                continue;
            }
            let is_op = is_operator(tok);
            if at_boundary && should_inject(&mut rng, prev, tok) {
                // ${@...} evaluates to the empty string when $@ is unset, so a
                // standalone, space-separated block is invisible at runtime yet
                // splices dense random junk throughout the obfuscated command.
                out.push_str(&random_param_junk(&mut rng));
                out.push(' ');
            }
            out.push_str(tok);
            prev = Some(tok);
            // After an operator the following token is a fresh word boundary;
            // otherwise a token directly glued to this one is not.
            at_boundary = is_op;
        }
        out
    }

    fn module_type(&self) -> ObfuscatorType {
        ObfuscatorType::NoiseInjector
    }
}

// True if `tok` is a shell operator that begins a new word after it, so the
// next token is a safe place to drop junk (an empty word there is harmless).
fn is_operator(tok: &str) -> bool {
    matches!(
        tok,
        ";" | "&" | "|" | "&&" | "||" | "(" | ")" | ">" | "<" | ">>" | "<<" | "|&" | ";;"
    ) || tok.ends_with(';')
}

// Decide whether to splatter an empty ${@...} word before `tok`. This restores
// the original dense-junk look: noise appears at many positions — before
// operators, expansions, and arguments alike — instead of only being pinned to
// safe bare words. Because every block is emitted as a standalone,
// space-separated word that evaluates to empty, it cannot corrupt the tokens
// around it, except for the few constructs that are sensitive to an extra word
// landing between them:
//   1. `for`/`select` when the word lands between the keyword and its loop var
//      (`for <junk> i ...` is a syntax error).
//   2. a variable assignment whose value follows on the next word
//      (`x= <junk> 5` becomes `x=` then a stray `5` command).
fn should_inject(rng: &mut impl Rng, prev: Option<&str>, tok: &str) -> bool {
    if !rng.gen_bool(0.4) {
        return false;
    }
    if tokenize::is_reserved_word(tok) {
        return false; // never wedge a word in front of a reserved word
    }
    if tokenize::is_assignment(tok) {
        return false; // keep `foo=...` as a single word
    }
    if let Some(p) = prev
        && tokenize::is_assignment(p)
    {
        return false; // `x= <junk> value` splits the assignment
    }
    true
}

fn random_param_junk(rng: &mut impl Rng) -> String {
    let modifier = MODIFIERS[rng.gen_range(0..MODIFIERS.len())];
    format!("${{@{}{}}}", modifier, utils::junk())
}
