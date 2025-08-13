use once_cell::sync::Lazy;
use regex::bytes::Regex;
use tracing::debug;

/// Case-insensitive patterns that indicate a *benign* match (placeholders, examples, redactions, etc.).
/// `is_safe_match()` returns true if any of these are present.
static SAFE_LIST_FILTER_REGEX: Lazy<Vec<Option<Regex>>> = Lazy::new(|| {
    vec![
        // Assignment-like value that ends with "EXAMPLEKEY" (common placeholder)
        // e.g., "KEY=ABC_EXAMPLEKEY" or "key: fooEXAMPLEKEY"
        compile_regex(r"(?i)[:=][^:=]{0,64}EXAMPLEKEY"),

        // AWS-style AKIA keys explicitly marked as example/fake/test/sample
        // e.g., "AKIA...EXAMPLE", "AKIA...FAKE", "AKIA...SAMPLE"
        compile_regex(r"(?i)\b(AKIA(?:.*?EXAMPLE|.*?FAKE|TEST|.*?SAMPLE))\b"),

        // Secret-y key name followed by short value and then "&&" / "||" or a run of asterisks
        // e.g., "password=foo &&", "secret: *****" (redacted/masked)
        compile_regex(
            r"(?i)(password|pass|pwd|passwd|secret|cred|key|auth|authorization)[^=:?]{0,8}[=:?][^=:?]{0,8}\s(&&|\|\||\*{5,50})",
        ),

        // Secret-y key name with short value, then *another* short assignment on the same line
        // Typical of docs/examples rather than hardcoded secrets
        compile_regex(
            r"(?i)(password|pass|pwd|passwd|secret|cred|key|auth|authorization)[^=:?]{0,8}[=:?][^=:?]{0,8}\b\w{4,12}\s{0,6}=\s{0,6}\D{0,3}\w{1,12}",
        ),

        // Secret-y key assigned to a shell variable reference (e.g., "$FOO") — not a literal secret
        compile_regex(
            r"(?i)(password|pass|pwd|passwd|secret|cred|key|auth|authorization)[^=:?]{0,8}[=:?][^=:?]{0,8}\$\w{4,30}",
        ),

        // Secret-y key set via command that *generates* randomness, not a literal value
        // e.g., "password = openssl rand -base64 32"
        compile_regex(
            r"(?i)(password|pass|pwd|passwd|secret|cred|key|auth|authorization)[^=:?]{0,16}[=:?][^=:?]{0,8}\bopenssl\s{0,4}rand\b",
        ),

        // Secret-y key assigned a value containing "encrypted" (marker/metadata, not a secret)
        compile_regex(
            r"(?i)(password|pass|pwd|passwd|secret|cred|key|auth|authorization)[^=:?]{0,8}[=:?][^=:?]{0,8}encrypted",
        ),

        // Secret-y key assigned boolean literals — not secrets
        // e.g., "auth=false"
        compile_regex(
            r"(?i)(password|pass|pwd|passwd|secret|cred|key|auth|authorization)[^=:?]{0,8}[=:?][^=:?]{0,8}\b(?:false|true)\b",
        ),

        // Secret-y key assigned to null-ish or self-referential placeholders — not secrets
        // e.g., "password: null", "secret = none"
        compile_regex(
            r"(?i)(password|pass|pwd|passwd|secret|cred|key|auth|authorization)[^=:?]{0,8}[=:?][^=:?]{0,8}\b(null|nil|none|password|pass|pwd|passwd|secret|cred|key|auth|authorization).{1,6}$",
        ),

        // The classic xkcd "hunter2" fake password
        compile_regex(
            r"(?i)(password|pass|pwd|passwd|secret|cred|key|auth|authorization)[^=:?]{0,8}[=:?][^=:?]{0,8}hunter2",
        ),

        // Obvious placeholder sequences
        // (Consider grouping like (?i)(?:123456789|abcdefghij) for clarity.)
        compile_regex(r"(?i)123456789|abcdefghij"),

        // Literal placeholder tag often used in docs/config
        compile_regex(r"(?i)<secretmanager>"),

        // OpenAPI schema references in assignment/query contexts — not secrets
        // e.g., "password?ref=#/components/schemas/Credential"
        compile_regex(r"(?i)[=:?][^=:?]{0,8}#/components/schemas/"),

        // Example MongoDB URIs with placeholder user/pass like "user:pass" or "foo:bar"
        compile_regex(
            r"(?i)\b(mongodb(?:\+srv)?://(?:user|foo)[^:@]+:(?:pass|bar)[^@]+@[-\w.%+/:]{3,64}(?:/\w+)?)",
        ),

        // "classpath://" URIs — configuration references, not secrets
        compile_regex(r"(?i)\b(classpath://)"),

        // Assignment where the value dereferences a placeholder/property like ${env_var}
        // e.g., "password=${db_password}"
        compile_regex(r"(?i)(\b[^\s\t]{0,16}[=:][^$]*\$\{[a-z_-]{5,30}\})"),

        // URLs with basic auth to hosts ending in "example" or "test" — placeholders
        // e.g., "https://user:pass@example"
        compile_regex(r"(?i)\b((?:https?:)?//[^:@]{3,50}:[^:@]{3,50}@[\w.]{0,16}(?:example|test))"),

        // Assignment ending with "SECRETMANAGER" — explicit placeholder
        compile_regex(r"(?i)[:=][^:=]{0,32}\bSECRETMANAGER"),
    ]
});

fn compile_regex(pattern: &str) -> Option<Regex> {
    match Regex::new(pattern) {
        Ok(regex) => Some(regex),
        Err(e) => {
            debug!("Failed to compile regex '{}': {}", pattern, e);
            None
        }
    }
}

/// Returns true if the input likely contains *benign* placeholder/test strings.
pub fn is_safe_match(input: &[u8]) -> bool {
    SAFE_LIST_FILTER_REGEX
        .iter()
        .filter_map(|regex_option| regex_option.as_ref())
        .any(|regex| regex.is_match(input))
}
