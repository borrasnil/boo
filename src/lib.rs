pub mod core;
pub mod modules;
pub mod utils;

pub use core::engine::{OS, Obfuscate, ObfuscatorModule, ObfuscatorType, Pipeline};
pub use modules::AllModules;

#[cfg(test)]
mod tests {
    use super::*;
    use modules::evasion::base64::Base64Obfuscator;
    use modules::evasion::exec_mask::ExecMaskObfuscator;
    use modules::evasion::heredoc::HeredocObfuscator;
    use modules::evasion::varindir::VarIndirObfuscator;
    use modules::string::hex::HexObfuscator;
    use modules::string::param::ParamObfuscator;
    use modules::string::quotes::QuotesObfuscator;

    // Strips all ${@...} param modifier injections — they evaluate to empty when $@ is unset.
    // Handles \} inside the expression so the scanner doesn't close early.
    fn strip_param_modifiers(s: &str) -> Option<String> {
        let mut result = String::new();
        let mut chars = s.chars().peekable();
        while let Some(c) = chars.next() {
            if c == '$' && chars.peek() == Some(&'{') {
                chars.next(); // consume {
                if chars.peek() == Some(&'@') {
                    chars.next(); // consume @
                    loop {
                        match chars.next()? {
                            '\\' => {
                                chars.next();
                            } // skip escaped char (e.g. \})
                            '}' => break,
                            _ => {}
                        }
                    }
                    // ${@...} = empty when no positional params — nothing added
                } else {
                    result.push_str("${");
                }
            } else {
                result.push(c);
            }
        }
        Some(result)
    }

    // Collapses runs of whitespace into single spaces and trims the ends. The
    // dense param junk is emitted as standalone, whitespace-delimited empty
    // ${@...} words, so after they are stripped only harmless extra whitespace
    // remains (including at the very start, where a junk block may precede the
    // first word).
    fn collapse_ws(s: &str) -> String {
        let mut out = String::new();
        let mut prev_ws = false;
        for c in s.chars() {
            if c.is_whitespace() {
                if !prev_ws {
                    out.push(' ');
                }
                prev_ws = true;
            } else {
                out.push(c);
                prev_ws = false;
            }
        }
        out.trim().to_string()
    }

    // Evaluates $'\xHH' hex escape sequences as bash ANSI-C quoting does.
    fn eval_hex_escapes(s: &str) -> Option<String> {
        let mut result = String::new();
        let mut chars = s.chars().peekable();
        while let Some(c) = chars.next() {
            if c == '$' && chars.peek() == Some(&'\'') {
                chars.next(); // consume '
                let backslash = chars.next()?;
                let x = chars.next()?;
                if backslash != '\\' || x != 'x' {
                    return None;
                }
                let h1 = chars.next()?;
                let h2 = chars.next()?;
                let close = chars.next()?;
                if close != '\'' {
                    return None;
                }
                let byte = u8::from_str_radix(&format!("{h1}{h2}"), 16).ok()?;
                result.push(byte as char);
            } else {
                result.push(c);
            }
        }
        Some(result)
    }

    // Simulates how bash evaluates adjacent quoted strings.
    // Does not handle escape sequences — our obfuscator never emits them.
    fn eval_bash_quotes(s: &str) -> Option<String> {
        let mut result = String::new();
        let mut chars = s.chars();
        while let Some(c) = chars.next() {
            match c {
                '\'' => {
                    let mut closed = false;
                    for inner in chars.by_ref() {
                        if inner == '\'' {
                            closed = true;
                            break;
                        }
                        result.push(inner);
                    }
                    if !closed {
                        return None;
                    }
                }
                '"' => {
                    let mut closed = false;
                    for inner in chars.by_ref() {
                        if inner == '"' {
                            closed = true;
                            break;
                        }
                        result.push(inner);
                    }
                    if !closed {
                        return None;
                    }
                }
                c => result.push(c),
            }
        }
        Some(result)
    }

    #[test]
    fn pipeline_no_modules_returns_original() {
        let result = Pipeline::new(OS::Linux).run("cat /etc/passwd");
        assert_eq!(result, "cat /etc/passwd");
    }

    #[test]
    fn pipeline_hex_roundtrip_metachars() {
        let inputs = [
            "echo $HOME",
            "echo it's",
            "echo hi; ls",
            "echo \"hi there\"",
            "a=$(ls)",
            "cat /etc/passwd",
        ];
        for &input in &inputs {
            for _ in 0..200 {
                let result = Pipeline::new(OS::Linux).add(HexObfuscator).run(input);
                let decoded = eval_hex_escapes(&result)
                    .unwrap_or_else(|| panic!("malformed hex output for `{input}`: {result}"));
                assert_eq!(decoded, input, "hex round-trip failed for: {result}");
            }
        }
    }

    #[test]
    fn pipeline_quotes_roundtrip() {
        let input = "cat /etc/passwd";
        for _ in 0..50 {
            let result = Pipeline::new(OS::Linux).add(QuotesObfuscator).run(input);
            assert_eq!(eval_bash_quotes(&result), Some(input.to_string()));
        }
    }

    #[test]
    fn pipeline_quotes_single_quote_roundtrip() {
        // A literal apostrophe is only valid inside a quoted region; a bare
        // `it's` is a bash syntax error, so use a double-quoted apostrophe and
        // verify real bash output matches.
        let input = "echo \"it's\"";
        let expected = match bash_output(input) {
            None => return, // bash unavailable
            Some(e) => e,
        };
        for _ in 0..50 {
            let result = Pipeline::new(OS::Linux).add(QuotesObfuscator).run(input);
            let actual = bash_output(&result)
                .unwrap_or_else(|| panic!("failed to run obfuscated: {result}"));
            assert_eq!(
                actual, expected,
                "round-trip failed for: {result} (input `{input}`)"
            );
        }
    }

    #[test]
    fn pipeline_quotes_special_chars_roundtrip() {
        let input = "echo $HOME";
        for _ in 0..50 {
            let result = Pipeline::new(OS::Linux).add(QuotesObfuscator).run(input);
            assert_eq!(eval_bash_quotes(&result), Some(input.to_string()));
        }
    }

    #[test]
    fn pipeline_quotes_empty() {
        let result = Pipeline::new(OS::Linux).add(QuotesObfuscator).run("");
        assert_eq!(result, "");
    }

    #[test]
    fn pipeline_hex_roundtrip() {
        let input = "echo test";
        for _ in 0..50 {
            let result = Pipeline::new(OS::Linux).add(HexObfuscator).run(input);
            assert_eq!(eval_hex_escapes(&result), Some(input.to_string()));
        }
    }

    #[test]
    fn pipeline_hex_empty() {
        let result = Pipeline::new(OS::Linux).add(HexObfuscator).run("");
        assert_eq!(result, "");
    }

    #[test]
    fn pipeline_param_roundtrip() {
        let input = "echo test";
        for _ in 0..50 {
            let result = Pipeline::new(OS::Linux).add(ParamObfuscator).run(input);
            assert_eq!(collapse_ws(&strip_param_modifiers(&result).unwrap()), input);
        }
    }

    #[test]
    fn pipeline_param_empty() {
        let result = Pipeline::new(OS::Linux).add(ParamObfuscator).run("");
        assert_eq!(result, "");
    }

    #[test]
    fn pipeline_param_no_junk_in_injections() {
        let input = "cat /etc/passwd";
        for _ in 0..50 {
            let result = Pipeline::new(OS::Linux).add(ParamObfuscator).run(input);
            assert!(strip_param_modifiers(&result).is_some());
        }
    }

    // --- param modifier structural tests ---

    // Parses every ${@modifier junk} block from a string.
    // Returns None if any block is malformed (bad modifier, unclosed, etc.).
    fn extract_param_blocks(s: &str) -> Option<Vec<(String, String)>> {
        let mut blocks = Vec::new();
        let mut chars = s.chars().peekable();

        while let Some(c) = chars.next() {
            if c != '$' {
                continue;
            }
            if chars.peek() != Some(&'{') {
                continue;
            }
            chars.next(); // {
            if chars.peek() != Some(&'@') {
                continue;
            }
            chars.next(); // @

            // Must start with a valid modifier: # ## % %%
            let first = chars.next()?;
            let modifier = match first {
                '#' => {
                    if chars.peek() == Some(&'#') {
                        chars.next();
                        "##"
                    } else {
                        "#"
                    }
                }
                '%' => {
                    if chars.peek() == Some(&'%') {
                        chars.next();
                        "%%"
                    } else {
                        "%"
                    }
                }
                _ => return None,
            };

            // Collect junk until the first unescaped }
            let mut junk = String::new();
            loop {
                match chars.next()? {
                    '\\' => {
                        junk.push('\\');
                        junk.push(chars.next()?);
                    }
                    '}' => break,
                    c => junk.push(c),
                }
            }

            blocks.push((modifier.to_string(), junk));
        }
        Some(blocks)
    }

    const VALID_MODIFIERS: &[&str] = &["#", "##", "%", "%%"];

    #[test]
    fn param_blocks_have_valid_modifiers() {
        for _ in 0..100 {
            let result = Pipeline::new(OS::Linux)
                .add(ParamObfuscator)
                .run("echo test");
            let blocks = extract_param_blocks(&result)
                .unwrap_or_else(|| panic!("malformed param block in: {result}"));
            for (modifier, _) in &blocks {
                assert!(
                    VALID_MODIFIERS.contains(&modifier.as_str()),
                    "invalid modifier `{modifier}` in: {result}"
                );
            }
        }
    }

    #[test]
    fn param_blocks_are_properly_closed() {
        for _ in 0..100 {
            let result = Pipeline::new(OS::Linux)
                .add(ParamObfuscator)
                .run("echo test");
            assert!(
                extract_param_blocks(&result).is_some(),
                "unclosed param block in: {result}"
            );
        }
    }

    #[test]
    fn param_blocks_junk_has_no_bare_close_brace() {
        for _ in 0..100 {
            let result = Pipeline::new(OS::Linux)
                .add(ParamObfuscator)
                .run("echo test");
            let blocks = extract_param_blocks(&result).unwrap();
            for (_, junk) in &blocks {
                // \} is a legitimately escaped brace — strip it, then check for bare }
                let without_escaped = junk.replace("\\}", "");
                assert!(!without_escaped.contains('}'), "bare }} in junk `{junk}`");
            }
        }
    }

    #[test]
    fn param_blocks_junk_contains_brackets() {
        // [ and ] are valid in glob patterns — verify they appear across runs
        let mut found = false;
        for _ in 0..500 {
            let result = Pipeline::new(OS::Linux)
                .add(ParamObfuscator)
                .run("echo test");
            let blocks = extract_param_blocks(&result).unwrap();
            if blocks
                .iter()
                .any(|(_, j)| j.contains('[') || j.contains(']'))
            {
                found = true;
                break;
            }
        }
        assert!(
            found,
            "expected [ or ] in junk at least once across 500 runs"
        );
    }

    #[test]
    fn pipeline_quotes_then_param_roundtrip() {
        let input = "echo test";
        for _ in 0..100 {
            let result = Pipeline::new(OS::Linux)
                .add(QuotesObfuscator)
                .add(ParamObfuscator)
                .run(input);
            let stripped = strip_param_modifiers(&result)
                .unwrap_or_else(|| panic!("malformed param block in: {result}"));
            assert_eq!(
                eval_bash_quotes(&collapse_ws(&stripped)),
                Some(input.to_string()),
                "round-trip failed for: {result}"
            );
        }
    }

    #[test]
    fn pipeline_hex_then_param_roundtrip() {
        let input = "echo test";
        for _ in 0..100 {
            let result = Pipeline::new(OS::Linux)
                .add(HexObfuscator)
                .add(ParamObfuscator)
                .run(input);
            let stripped = strip_param_modifiers(&result)
                .unwrap_or_else(|| panic!("malformed param block in: {result}"));
            assert_eq!(
                eval_hex_escapes(&collapse_ws(&stripped)),
                Some(input.to_string()),
                "round-trip failed for: {result}"
            );
        }
    }

    #[test]
    fn module_types_are_correct() {
        assert_eq!(
            QuotesObfuscator.module_type(),
            ObfuscatorType::StringObfuscator
        );
        assert_eq!(HexObfuscator.module_type(), ObfuscatorType::Encoder);
        assert_eq!(ParamObfuscator.module_type(), ObfuscatorType::NoiseInjector);
    }

    #[test]
    fn all_modules_includes_every_functional_module() {
        let all = AllModules::all();
        assert_eq!(all.len(), 3);
        assert!(all.contains(&AllModules::Quotes));
        assert!(all.contains(&AllModules::Hex));
        assert!(all.contains(&AllModules::Param));
    }

    #[test]
    fn all_modules_dispatches_apply_and_type() {
        for m in AllModules::all() {
            let _ = m.apply("cat /etc/passwd", OS::Linux);
            let _ = m.module_type();
        }
    }

    // Runs a command line in real bash (if available) and returns its stdout.
    fn bash_output(command: &str) -> Option<String> {
        use std::process::Command;
        let out = Command::new("bash").arg("-c").arg(command).output().ok()?;
        Some(String::from_utf8_lossy(&out.stdout).into_owned())
    }

    #[test]
    fn pipeline_hex_real_bash_roundtrip() {
        let inputs = [
            "echo hello world",
            "echo $HOME",
            "echo $?",
            "echo it's",
            "echo 'x y z'",
            "echo hi; ls /nonexistent_dir 2>/dev/null; echo bye",
            "cat /etc/hostname",
            "printf '%s\\n' a b c",
        ];
        for &input in &inputs {
            let expected = match bash_output(input) {
                None => continue, // bash unavailable
                Some(e) => e,
            };
            for _ in 0..20 {
                let obf = Pipeline::new(OS::Linux).add(HexObfuscator).run(input);
                let actual =
                    bash_output(&obf).unwrap_or_else(|| panic!("failed to run obfuscated: {obf}"));
                assert_eq!(actual, expected, "hex output differs for `{input}`: {obf}");
            }
        }
    }

    #[test]
    fn pipeline_quotes_real_bash_roundtrip() {
        let inputs = [
            "echo hello world",
            "echo a; echo b",
            "echo \"plain text here\"",
            "echo \"it's\"",
            "echo 'x y z'",
            "ls /nonexistent_dir_xyz",
            "echo hi && echo there",
        ];
        for &input in &inputs {
            let expected = match bash_output(input) {
                None => continue, // bash unavailable
                Some(e) => e,
            };
            for _ in 0..30 {
                let obf = Pipeline::new(OS::Linux).add(QuotesObfuscator).run(input);
                let actual =
                    bash_output(&obf).unwrap_or_else(|| panic!("failed to run obfuscated: {obf}"));
                assert_eq!(
                    actual, expected,
                    "quotes output differs for `{input}`: {obf}"
                );
            }
        }
    }

    #[test]
    fn pipeline_param_real_bash_roundtrip() {
        let inputs = [
            "echo hello world",
            "echo a; echo b",
            "echo \"plain text here\"",
            "echo 'x y z'",
            "ls /nonexistent_dir_xyz",
            "echo $HOME",
        ];
        for &input in &inputs {
            let expected = match bash_output(input) {
                None => continue, // bash unavailable
                Some(e) => e,
            };
            for _ in 0..30 {
                let obf = Pipeline::new(OS::Linux).add(ParamObfuscator).run(input);
                let actual =
                    bash_output(&obf).unwrap_or_else(|| panic!("failed to run obfuscated: {obf}"));
                assert_eq!(
                    actual, expected,
                    "param output differs for `{input}`: {obf}"
                );
            }
        }
    }

    #[test]
    fn pipeline_all_real_bash_roundtrip() {
        // The default pipeline runs every module via AllModules::all().
        let inputs = [
            "echo hello world",
            "echo a; echo b",
            "echo \"plain text here\"",
            "echo \"it's\"",
            "echo 'x y z'",
            "whoami",
            "date +%Y",
            "echo $HOME",
            "x=5; echo $x",
            "foo=\"bar baz\"; echo \"$foo\"",
            "for i in 1 2 3; do echo $i; done",
            "if true; then echo yes; fi",
            "cat /etc/hostname | tr a-z A-Z",
        ];
        for &input in &inputs {
            let expected = match bash_output(input) {
                None => continue, // bash unavailable
                Some(e) => e,
            };
            for _ in 0..10 {
                let mut pipeline = Pipeline::new(OS::Linux);
                for m in AllModules::all() {
                    pipeline = pipeline.add(m);
                }
                let obf = pipeline.run(input);
                let actual =
                    bash_output(&obf).unwrap_or_else(|| panic!("failed to run obfuscated: {obf}"));
                assert_eq!(
                    actual, expected,
                    "all-modules output differs for `{input}`: {obf}"
                );
            }
        }
    }

    // ======================================================================
    // Evasion module test helpers
    // ======================================================================

    fn extract_base64_payload(s: &str) -> Option<String> {
        let after_echo = s.strip_prefix("echo '")?;
        let b64 = after_echo.strip_suffix("' | base64 -d | bash")?;
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(b64)
            .ok()?;
        Some(String::from_utf8(decoded).ok()?)
    }

    fn extract_varindir_command(s: &str) -> Option<String> {
        let eval_pos = s.rfind("eval \"")?;
        let assignments_part = &s[..eval_pos];
        let mut result = String::new();
        for part in assignments_part.split(';') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            let eq_pos = part.find('=')?;
            let value_part = &part[eq_pos + 1..];
            let inner = value_part.strip_prefix('\'')?.strip_suffix('\'')?;
            let resolved = inner.replace("'\\''", "'");
            result.push_str(&resolved);
        }
        Some(result)
    }

    fn extract_exec_command(s: &str) -> Option<String> {
        let after_prefix = s.strip_prefix("exec bash -c '")?;
        let cmd = after_prefix.strip_suffix('\'')?;
        Some(cmd.replace("'\\''", "'"))
    }

    fn extract_heredoc_command(s: &str) -> Option<String> {
        let first_newline = s.find('\n')?;
        let header = &s[..first_newline];
        let delimiter = header.strip_prefix("bash <<")?;
        let body = &s[first_newline + 1..];
        let ending = format!("\n{}", delimiter);
        let command = body.strip_suffix(&ending)?;
        Some(command.to_string())
    }

    // ======================================================================
    // BASE64 MODULE TESTS
    // ======================================================================

    #[test]
    fn base64_roundtrip_synthetic() {
        let inputs = [
            "echo test",
            "cat /etc/passwd",
            "echo $HOME",
            "echo \"hello world\"",
            "ls -la /tmp",
            "echo hi; ls",
        ];
        for &input in &inputs {
            let result = Base64Obfuscator.apply(input, OS::Linux);
            let decoded = extract_base64_payload(&result)
                .unwrap_or_else(|| panic!("failed to extract base64 from: {result}"));
            assert_eq!(decoded, input, "base64 roundtrip failed for: {result}");
        }
    }

    #[test]
    fn base64_output_is_valid_bash() {
        let result = Base64Obfuscator.apply("echo test", OS::Linux);
        assert!(result.starts_with("echo '"), "bad prefix: {result}");
        assert!(result.ends_with(" | base64 -d | bash"), "bad suffix: {result}");
    }

    #[test]
    fn base64_empty_command() {
        let result = Base64Obfuscator.apply("", OS::Linux);
        assert_eq!(result, "");
    }

    #[test]
    fn base64_deterministic() {
        let input = "echo test";
        let first = Base64Obfuscator.apply(input, OS::Linux);
        for _ in 0..50 {
            assert_eq!(Base64Obfuscator.apply(input, OS::Linux), first);
        }
    }

    #[test]
    fn base64_real_bash_roundtrip() {
        let inputs = [
            "echo hello world",
            "echo a; echo b",
            "echo \"plain text here\"",
            "ls /nonexistent_dir_xyz",
            "echo hi && echo there",
        ];
        for &input in &inputs {
            let expected = match bash_output(input) {
                None => continue,
                Some(e) => e,
            };
            let obf = Base64Obfuscator.apply(input, OS::Linux);
            let actual = bash_output(&obf)
                .unwrap_or_else(|| panic!("failed to run obfuscated: {obf}"));
            assert_eq!(
                actual, expected,
                "base64 real-bash differs for `{input}`: {obf}"
            );
        }
    }

    // ======================================================================
    // VARINDIR MODULE TESTS
    // ======================================================================

    #[test]
    fn varindir_roundtrip_synthetic() {
        let inputs = [
            "echo test",
            "cat /etc/passwd",
            "echo $HOME",
            "echo \"hello world\"",
        ];
        for &input in &inputs {
            for _ in 0..50 {
                let result = VarIndirObfuscator.apply(input, OS::Linux);
                let reconstructed = extract_varindir_command(&result)
                    .unwrap_or_else(|| panic!("failed to extract command from: {result}"));
                assert_eq!(
                    reconstructed, input,
                    "varindir roundtrip failed for: {result}"
                );
            }
        }
    }

    #[test]
    fn varindir_structure() {
        for _ in 0..100 {
            let result = VarIndirObfuscator.apply("echo test", OS::Linux);
            assert!(result.contains("eval"), "missing eval: {result}");
            let parts: Vec<&str> = result.split(';').collect();
            assert!(parts.len() >= 4, "too few assignments: {result}");
        }
    }

    #[test]
    fn varindir_empty_command() {
        let result = VarIndirObfuscator.apply("", OS::Linux);
        assert_eq!(result, "");
    }

    #[test]
    fn varindir_handles_single_quotes() {
        let input = "echo \"it's fine\"";
        for _ in 0..50 {
            let result = VarIndirObfuscator.apply(input, OS::Linux);
            let reconstructed = extract_varindir_command(&result)
                .unwrap_or_else(|| panic!("failed to extract from: {result}"));
            assert_eq!(reconstructed, input);
        }
    }

    #[test]
    fn varindir_real_bash_roundtrip() {
        let inputs = [
            "echo hello world",
            "echo a; echo b",
            "echo \"plain text here\"",
            "ls /nonexistent_dir_xyz",
        ];
        for &input in &inputs {
            let expected = match bash_output(input) {
                None => continue,
                Some(e) => e,
            };
            for _ in 0..20 {
                let obf = VarIndirObfuscator.apply(input, OS::Linux);
                let actual = bash_output(&obf)
                    .unwrap_or_else(|| panic!("failed to run obfuscated: {obf}"));
                assert_eq!(
                    actual, expected,
                    "varindir real-bash differs for `{input}`: {obf}"
                );
            }
        }
    }

    // ======================================================================
    // EXEC MASK MODULE TESTS
    // ======================================================================

    #[test]
    fn exec_mask_structure() {
        let result = ExecMaskObfuscator.apply("echo test", OS::Linux);
        assert!(result.starts_with("exec bash -c '"), "bad prefix: {result}");
        assert!(result.ends_with('\''), "bad suffix: {result}");
    }

    #[test]
    fn exec_mask_roundtrip_synthetic() {
        let inputs = ["echo test", "cat /etc/passwd", "echo $HOME"];
        for &input in &inputs {
            let result = ExecMaskObfuscator.apply(input, OS::Linux);
            let extracted = extract_exec_command(&result)
                .unwrap_or_else(|| panic!("failed to extract from: {result}"));
            assert_eq!(extracted, input, "exec mask roundtrip failed: {result}");
        }
    }

    #[test]
    fn exec_mask_escapes_single_quotes() {
        let input = "echo \"it's fine\"";
        let result = ExecMaskObfuscator.apply(input, OS::Linux);
        assert!(result.contains("'\\''"), "single quote not escaped: {result}");
        let extracted = extract_exec_command(&result).unwrap();
        assert_eq!(extracted, input);
    }

    #[test]
    fn exec_mask_empty_command() {
        let result = ExecMaskObfuscator.apply("", OS::Linux);
        assert_eq!(result, "");
    }

    #[test]
    fn exec_mask_deterministic() {
        let input = "echo test";
        let first = ExecMaskObfuscator.apply(input, OS::Linux);
        for _ in 0..50 {
            assert_eq!(ExecMaskObfuscator.apply(input, OS::Linux), first);
        }
    }

    #[test]
    fn exec_mask_real_bash_roundtrip() {
        let inputs = [
            "echo hello world",
            "echo a; echo b",
            "echo \"plain text here\"",
            "ls /nonexistent_dir_xyz",
        ];
        for &input in &inputs {
            let expected = match bash_output(input) {
                None => continue,
                Some(e) => e,
            };
            let obf = ExecMaskObfuscator.apply(input, OS::Linux);
            let actual = bash_output(&obf)
                .unwrap_or_else(|| panic!("failed to run obfuscated: {obf}"));
            assert_eq!(
                actual, expected,
                "exec mask real-bash differs for `{input}`: {obf}"
            );
        }
    }

    // ======================================================================
    // HEREDOC MODULE TESTS
    // ======================================================================

    #[test]
    fn heredoc_structure() {
        for _ in 0..100 {
            let result = HeredocObfuscator.apply("echo test", OS::Linux);
            let lines: Vec<&str> = result.lines().collect();
            assert!(lines.len() >= 3, "heredoc too few lines: {result}");
            assert!(
                lines[0].starts_with("bash <<__evasion_"),
                "bad header: {result}"
            );
            let delimiter = &lines[0][6..];
            assert_eq!(
                lines.last().unwrap(),
                delimiter,
                "delimiter mismatch: {result}"
            );
            let command_part = &lines[1..lines.len() - 1].join("\n");
            assert_eq!(command_part, "echo test", "command content wrong: {result}");
        }
    }

    #[test]
    fn heredoc_roundtrip_synthetic() {
        let inputs = ["echo test", "cat /etc/passwd", "echo \"hello world\""];
        for &input in &inputs {
            for _ in 0..50 {
                let result = HeredocObfuscator.apply(input, OS::Linux);
                let extracted = extract_heredoc_command(&result)
                    .unwrap_or_else(|| panic!("failed to extract from: {result}"));
                assert_eq!(extracted, input, "heredoc roundtrip failed: {result}");
            }
        }
    }

    #[test]
    fn heredoc_empty_command() {
        let result = HeredocObfuscator.apply("", OS::Linux);
        assert_eq!(result, "");
    }

    #[test]
    fn heredoc_delimiter_uniqueness() {
        let mut delimiters = std::collections::HashSet::new();
        for _ in 0..200 {
            let result = HeredocObfuscator.apply("echo test", OS::Linux);
            let header = result.lines().next().unwrap();
            let delim = header.strip_prefix("bash <<").unwrap().to_string();
            delimiters.insert(delim);
        }
        assert_eq!(delimiters.len(), 200, "delimiter collision detected");
    }

    #[test]
    fn heredoc_preserves_dollar_expansion() {
        let input = "echo $HOME";
        let expected = match bash_output(input) {
            None => return,
            Some(e) => e,
        };
        let obf = HeredocObfuscator.apply(input, OS::Linux);
        let actual = bash_output(&obf)
            .unwrap_or_else(|| panic!("failed to run obfuscated: {obf}"));
        assert_eq!(actual, expected, "heredoc expansion failed: {obf}");
    }

    #[test]
    fn heredoc_real_bash_roundtrip() {
        let inputs = [
            "echo hello world",
            "echo a; echo b",
            "echo \"plain text here\"",
            "ls /nonexistent_dir_xyz",
            "echo $HOME",
        ];
        for &input in &inputs {
            let expected = match bash_output(input) {
                None => continue,
                Some(e) => e,
            };
            for _ in 0..20 {
                let obf = HeredocObfuscator.apply(input, OS::Linux);
                let actual = bash_output(&obf)
                    .unwrap_or_else(|| panic!("failed to run obfuscated: {obf}"));
                assert_eq!(
                    actual, expected,
                    "heredoc real-bash differs for `{input}`: {obf}"
                );
            }
        }
    }

    // ======================================================================
    // MODULE TYPE TESTS
    // ======================================================================

    #[test]
    fn evasion_module_types_are_correct() {
        assert_eq!(
            Base64Obfuscator.module_type(),
            ObfuscatorType::EvasionModule
        );
        assert_eq!(
            VarIndirObfuscator.module_type(),
            ObfuscatorType::EvasionModule
        );
        assert_eq!(
            ExecMaskObfuscator.module_type(),
            ObfuscatorType::EvasionModule
        );
        assert_eq!(
            HeredocObfuscator.module_type(),
            ObfuscatorType::EvasionModule
        );
    }

    // ======================================================================
    // ALLMODULES DISPATCH TESTS
    // ======================================================================

    #[test]
    fn all_modules_excludes_evasion() {
        let all = AllModules::all();
        assert_eq!(all.len(), 3);
        assert!(!all.contains(&AllModules::Base64));
        assert!(!all.contains(&AllModules::VarIndir));
        assert!(!all.contains(&AllModules::ExecMask));
        assert!(!all.contains(&AllModules::Heredoc));
    }

    #[test]
    fn all_modules_dispatches_all_variants() {
        for m in [
            AllModules::Quotes,
            AllModules::Hex,
            AllModules::Param,
            AllModules::Base64,
            AllModules::VarIndir,
            AllModules::ExecMask,
            AllModules::Heredoc,
        ] {
            let _ = m.apply("cat /etc/passwd", OS::Linux);
            let _ = m.module_type();
        }
    }

    // ======================================================================
    // COMPOSITION TESTS
    // ======================================================================

    #[test]
    fn pipeline_base64_then_varindir() {
        let input = "echo test";
        for _ in 0..20 {
            let result = Pipeline::new(OS::Linux)
                .add(Base64Obfuscator)
                .add(VarIndirObfuscator)
                .run(input);
            let base64_cmd = extract_varindir_command(&result)
                .unwrap_or_else(|| panic!("varindir extraction failed: {result}"));
            let decoded = extract_base64_payload(&base64_cmd)
                .unwrap_or_else(|| panic!("base64 extraction failed: {base64_cmd}"));
            assert_eq!(decoded, input);
        }
    }

    #[test]
    fn pipeline_quotes_hex_then_heredoc() {
        let input = "echo hello";
        for _ in 0..20 {
            let result = Pipeline::new(OS::Linux)
                .add(QuotesObfuscator)
                .add(HexObfuscator)
                .add(HeredocObfuscator)
                .run(input);
            let extracted = extract_heredoc_command(&result)
                .unwrap_or_else(|| panic!("heredoc extraction failed: {result}"));
            let after_hex = eval_hex_escapes(&extracted)
                .unwrap_or_else(|| panic!("hex decode failed: {extracted}"));
            assert_eq!(eval_bash_quotes(&after_hex), Some(input.to_string()));
        }
    }

    #[test]
    fn pipeline_all_evasion_real_bash() {
        let inputs = [
            "echo hello world",
            "echo a; echo b",
            "echo \"plain text here\"",
            "echo $HOME",
        ];
        for &input in &inputs {
            let expected = match bash_output(input) {
                None => continue,
                Some(e) => e,
            };
            for _ in 0..10 {
                let obf = Pipeline::new(OS::Linux)
                    .add(Base64Obfuscator)
                    .add(HeredocObfuscator)
                    .run(input);
                let actual = bash_output(&obf)
                    .unwrap_or_else(|| panic!("failed to run obfuscated: {obf}"));
                assert_eq!(
                    actual, expected,
                    "evasion pipeline differs for `{input}`: {obf}"
                );
            }
        }
    }
}
