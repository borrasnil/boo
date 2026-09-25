use rand::Rng;

// Safe noise chars for arbitrary blobs.
// No } (closes ${@...}), no $ ` (expansions), no ' " (handled separately)
// No \ — backslashes only enter junk through escape_seq (\X pairs) and escaped_brace (\}).
// No ! — zsh fires history expansion on ! even inside ${...} in interactive mode.
// No [ ] — in bash glob patterns (used by ${@^^pattern}) an unclosed [ is a hard parse
//           error ("bad substitution"). [ ] only enter junk via bracket_class() which
//           always emits a complete valid [inner] pair.
const NOISE: &[u8] =
    b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/()|><~^%#@*+=.,:_-?{";

// Letters only — for identifier-like fragments
const LETTERS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

// Targets for fake escape sequences: \v \r \n \t \4 \x etc. Never } or \.
const ESC_TARGETS: &[u8] = b"rntvx0123456789abcdef";

// Safe inside "..." — no \ and no ! (zsh history expansion).
// [ ] are fine here because inside "..." they are not glob-special.
const QUOTED_INNER: &[u8] =
    b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/()[]|><~^%#@*+=.,:_-? {";

// Final chars — alphanumeric only so the last char before } is never \
const SAFE_TAIL: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

/// Builds a multi-segment junk string safe to embed in ${@modifier<JUNK>}.
/// Combines noise blobs, spaces, "..." pairs, \} escapes, {{{ clusters,
/// fake escape sequences (\v \r \4), bracket classes [abc], and word fragments.
pub fn junk() -> String {
    let mut rng = rand::thread_rng();
    let mut segments: Vec<String> = Vec::new();

    let n = rng.gen_range(5usize..=13);
    for _ in 0..n {
        let seg = match rng.gen_range(0u8..7) {
            0 => noise_blob(&mut rng),
            1 => spaces(&mut rng),
            2 => double_quoted(&mut rng),
            3 => escaped_brace(),
            4 => open_braces(&mut rng),
            5 => escape_seq(&mut rng),
            _ => bracket_class(&mut rng),
        };
        segments.push(seg);
    }

    // Inject 1-2 identifier-like words at random positions
    for _ in 0..rng.gen_range(1usize..=2) {
        let pos = rng.gen_range(0..=segments.len());
        segments.insert(pos, format!(" {} ", word_like(&mut rng)));
    }

    // Alphanumeric tail — guarantees the last char before } is never \
    segments.push(safe_tail(&mut rng));

    segments.concat()
}

// --- segment builders ---

fn noise_blob(rng: &mut impl Rng) -> String {
    let len = rng.gen_range(2usize..=8);
    (0..len)
        .map(|_| NOISE[rng.gen_range(0..NOISE.len())] as char)
        .collect()
}

fn spaces(rng: &mut impl Rng) -> String {
    " ".repeat(rng.gen_range(1..=4))
}

fn double_quoted(rng: &mut impl Rng) -> String {
    let len = rng.gen_range(0usize..=5);
    let inner: String = (0..len)
        .map(|_| QUOTED_INNER[rng.gen_range(0..QUOTED_INNER.len())] as char)
        .collect();
    format!("\"{}\"", inner)
}

// \} is the correct way to include a literal } in a bash ${@...} pattern without
// closing the expansion. Verified to work in bash 4+.
fn escaped_brace() -> String {
    "\\}".to_string()
}

fn open_braces(rng: &mut impl Rng) -> String {
    "{".repeat(rng.gen_range(1..=3))
}

// Always emits a complete valid bracket expression — never a bare [ or ].
// No - in BC: a random pick like [9-0] or [Z-A] is an invalid range → bad substitution.
// Literal char sets only.
fn bracket_class(rng: &mut impl Rng) -> String {
    const BC: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ09_.*";
    let len = rng.gen_range(1usize..=5);
    let inner: String = (0..len)
        .map(|_| BC[rng.gen_range(0..BC.len())] as char)
        .collect();
    format!("[{}]", inner)
}

fn escape_seq(rng: &mut impl Rng) -> String {
    let c = ESC_TARGETS[rng.gen_range(0..ESC_TARGETS.len())] as char;
    format!("\\{}", c)
}

fn word_like(rng: &mut impl Rng) -> String {
    let len = rng.gen_range(3usize..=7);
    (0..len)
        .map(|_| LETTERS[rng.gen_range(0..LETTERS.len())] as char)
        .collect()
}

fn safe_tail(rng: &mut impl Rng) -> String {
    let len = rng.gen_range(2usize..=4);
    (0..len)
        .map(|_| SAFE_TAIL[rng.gen_range(0..SAFE_TAIL.len())] as char)
        .collect()
}
