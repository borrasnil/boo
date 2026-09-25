/// Shell-aware tokenizer shared by string obfuscators (Hex, Quotes).
///
/// Splits a bash command into atomic tokens that must never be re-written:
/// - whitespace runs
/// - `'...'` single-quoted
/// - `"..."` double-quoted
/// - `$'...'` ANSI-C quoted
/// - `` `...` `` backquoted
/// - `$VAR`, `${...}`, `$(...)` expansions
/// - bare runs (may include shell operators like `; | & > < ( )`)
///
/// Re-writing any character inside these tokens would change bash's lexical
/// meaning (quoting `;` makes it a literal, escaping `$` disables expansion,
/// etc.), so obfuscators only touch fully-safe bare words and pass everything
/// else through untouched.
pub fn tokenize(s: &str) -> Vec<String> {
    let chars: Vec<char> = s.chars().collect();
    let mut tokens = Vec::new();
    let mut i = 0;
    let n = chars.len();

    let is_bare = |c: char| -> bool { !c.is_whitespace() && !starts_special(c) };

    while i < n {
        let c = chars[i];

        if c.is_whitespace() {
            let start = i;
            while i < n && chars[i].is_whitespace() {
                i += 1;
            }
            tokens.push(chars[start..i].iter().collect());
            continue;
        }

        if c == '\'' {
            let start = i;
            i += 1;
            while i < n && chars[i] != '\'' {
                i += 1;
            }
            i += 1;
            tokens.push(chars[start..i.min(n)].iter().collect());
            continue;
        }

        if c == '"' {
            let start = i;
            i += 1;
            while i < n {
                if chars[i] == '\\' {
                    i += 2;
                    continue;
                }
                if chars[i] == '"' {
                    i += 1;
                    break;
                }
                i += 1;
            }
            tokens.push(chars[start..i.min(n)].iter().collect());
            continue;
        }

        if c == '$' {
            // $'...' (ANSI-C quoted)
            if i + 1 < n && chars[i + 1] == '\'' {
                let start = i;
                i += 2;
                while i < n {
                    if chars[i] == '\\' {
                        i += 2;
                        continue;
                    }
                    if chars[i] == '\'' {
                        i += 1;
                        break;
                    }
                    i += 1;
                }
                tokens.push(chars[start..i.min(n)].iter().collect());
                continue;
            }
            // $(...) or $((...)) — balance parens
            if i + 1 < n && chars[i + 1] == '(' {
                let start = i;
                i += 1;
                let mut depth = 0;
                while i < n {
                    if chars[i] == '(' {
                        depth += 1;
                    } else if chars[i] == ')' {
                        depth -= 1;
                        if depth == 0 {
                            i += 1;
                            break;
                        }
                    }
                    i += 1;
                }
                tokens.push(chars[start..i.min(n)].iter().collect());
                continue;
            }
            // ${...} — balance braces
            if i + 1 < n && chars[i + 1] == '{' {
                let start = i;
                i += 1;
                let mut depth = 0;
                while i < n {
                    if chars[i] == '{' {
                        depth += 1;
                    } else if chars[i] == '}' {
                        depth -= 1;
                        if depth == 0 {
                            i += 1;
                            break;
                        }
                    }
                    i += 1;
                }
                tokens.push(chars[start..i.min(n)].iter().collect());
                continue;
            }
            // $VAR / $1 /
            if i + 1 < n && (chars[i + 1].is_alphanumeric() || matches!(chars[i + 1], '_')) {
                let start = i;
                i += 1;
                while i < n && (chars[i].is_alphanumeric() || chars[i] == '_') {
                    i += 1;
                }
                tokens.push(chars[start..i.min(n)].iter().collect());
                continue;
            }
            // Lone `$` or special parameter ($? $$ $! $# $* $@ $-)
            let start = i;
            i += 1;
            if i < n && matches!(chars[i], '?' | '$' | '!' | '#' | '*' | '@' | '-') {
                i += 1;
            }
            tokens.push(chars[start..i.min(n)].iter().collect());
            continue;
        }

        if c == '`' {
            let start = i;
            i += 1;
            while i < n && chars[i] != '`' {
                i += 1;
            }
            i += 1;
            tokens.push(chars[start..i.min(n)].iter().collect());
            continue;
        }

        // Bare run (operators like `; | & > < ( )` are absorbed).
        let start = i;
        while i < n && is_bare(chars[i]) {
            i += 1;
        }
        tokens.push(chars[start..i].iter().collect());
    }
    tokens
}

/// Whether a char is bare-safe: alphumeric or conservative punctuation that
/// bash treats literally (never an operator, glob, expansion, or quote).
pub fn safe_char(c: char) -> bool {
    c.is_alphanumeric() || matches!(c, '_' | '-' | '.' | '/' | '=' | ',' | ':' | '@' | '%' | '+')
}

/// Bash reserved words. The shell recognises these lexically from the raw
/// source spelling, so re-writing them (even into equivalent text) breaks
/// compound commands (`for/do/done`, `if/then/fi`, `case/esac`, ...).
pub fn is_reserved_word(word: &str) -> bool {
    matches!(
        word,
        "if" | "then"
            | "elif"
            | "else"
            | "fi"
            | "time"
            | "for"
            | "in"
            | "while"
            | "until"
            | "do"
            | "done"
            | "case"
            | "esac"
            | "coproc"
            | "select"
            | "function"
            | "{"
            | "}"
            | "[["
            | "]]"
            | "!"
    )
}

/// True when `tok` is a variable assignment target like `foo=`, `x=5`,
/// `NAME=value`. Assignment names must stay literal identifiers.
pub fn is_assignment(tok: &str) -> bool {
    let b = tok.as_bytes();
    if b.is_empty() {
        return false;
    }
    // identifier(start) then '=' somewhere with a valid-then-= prefix
    let mut i = 0;
    if !(b[0].is_ascii_alphabetic() || b[0] == b'_') {
        return false;
    }
    i += 1;
    while i < b.len() && (b[i].is_ascii_alphanumeric() || b[i] == b'_') {
        i += 1;
    }
    i < b.len() && b[i] == b'='
}

/// Tracks whether a given token may be transformed by a string/encoder module.
/// Hands out "safe to touch" decisions, exempting whitespace, shell operators,
/// quoted regions, expansions, reserved words, assignment targets, and loop
/// variable names (the bare word immediately after `for`/`select`).
pub struct TransformFilter {
    pending_loop_var: bool,
}

impl Default for TransformFilter {
    fn default() -> Self {
        Self::new()
    }
}

impl TransformFilter {
    pub fn new() -> Self {
        TransformFilter {
            pending_loop_var: false,
        }
    }

    pub fn should_transform(&mut self, tok: &str) -> bool {
        if tok.chars().all(char::is_whitespace) {
            return false; // whitespace never transformed; don't consume the loop-var flag
        }
        // Consume the loop-var flag on the first real token after for/select.
        let loop_var = self.pending_loop_var;
        self.pending_loop_var = false;

        if tok == "for" || tok == "select" {
            self.pending_loop_var = true;
            return false;
        }
        if loop_var {
            return false; // loop variable name stays a literal identifier
        }
        if is_reserved_word(tok) {
            return false;
        }
        if is_assignment(tok) {
            return false;
        }
        !tok.is_empty() && tok.chars().all(safe_char)
    }
}

fn starts_special(c: char) -> bool {
    matches!(c, '\'' | '"' | '`') || c == '$'
}
