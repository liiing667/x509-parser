//! Resource budgets for the offline parsing chain
//!
//! Parsing untrusted data must not allow a single input to consume an unbounded amount of
//! resources. [`ParseBudget`] groups the limits shared by the PEM, DER, CSR and CRL parsers:
//!
//! - a maximum size for the whole input,
//! - a maximum length for a single line (used by the PEM reader),
//! - a maximum amount of base64-encoded data accumulated inside a PEM block,
//! - a maximum number of PEM blocks produced from a single stream.
//!
//! Every parsing entry point applies a default budget ([`ParseBudget::default`]). A custom
//! budget can be provided through the `*_with_budget` functions, or [`ParseBudget::unlimited`]
//! can be used to explicitly opt out of the limits.

/// Default maximum size of an input (64 KiB of PEM data decodes to 48 KiB of DER data).
pub const DEFAULT_MAX_INPUT_BYTES: usize = 64 * 1024 * 1024;
/// Default maximum length of a single line, including its line terminator.
pub const DEFAULT_MAX_LINE_LENGTH: usize = 1024 * 1024;
/// Default maximum amount of base64-encoded data accumulated inside a PEM block.
pub const DEFAULT_MAX_PEM_BODY_BYTES: usize = 64 * 1024 * 1024;
/// Default maximum number of PEM blocks accepted from a single stream.
pub const DEFAULT_MAX_PEM_BLOCKS: usize = 1024;

/// Resource limits shared by the offline parsers (PEM, DER, CSR and CRL).
///
/// All limits are inclusive: an input reaching exactly the limit is still accepted.
///
/// # Examples
///
/// ```
/// use x509_parser::budget::ParseBudget;
///
/// // tighten the input size limit to 1 KiB
/// let budget = ParseBudget::default().with_max_input_bytes(1024);
/// assert!(!budget.allows_input(1025));
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ParseBudget {
    /// Maximum size of the whole input, in bytes.
    pub max_input_bytes: usize,
    /// Maximum length of a single line (including its terminator), in bytes.
    pub max_line_length: usize,
    /// Maximum amount of base64-encoded data accumulated inside a PEM block, in bytes.
    pub max_pem_body_bytes: usize,
    /// Maximum number of PEM blocks accepted from a single stream.
    pub max_pem_blocks: usize,
}

impl ParseBudget {
    /// Create a budget with the default limits.
    #[inline]
    pub const fn new() -> Self {
        Self {
            max_input_bytes: DEFAULT_MAX_INPUT_BYTES,
            max_line_length: DEFAULT_MAX_LINE_LENGTH,
            max_pem_body_bytes: DEFAULT_MAX_PEM_BODY_BYTES,
            max_pem_blocks: DEFAULT_MAX_PEM_BLOCKS,
        }
    }

    /// Create a budget that does not enforce any limit.
    ///
    /// This restores the historical behavior of the parsers and should only be used when the
    /// caller already controls the input size by other means.
    #[inline]
    pub const fn unlimited() -> Self {
        Self {
            max_input_bytes: usize::MAX,
            max_line_length: usize::MAX,
            max_pem_body_bytes: usize::MAX,
            max_pem_blocks: usize::MAX,
        }
    }

    /// Override the maximum input size, in bytes.
    #[inline]
    pub const fn with_max_input_bytes(mut self, max_input_bytes: usize) -> Self {
        self.max_input_bytes = max_input_bytes;
        self
    }

    /// Override the maximum line length, in bytes.
    #[inline]
    pub const fn with_max_line_length(mut self, max_line_length: usize) -> Self {
        self.max_line_length = max_line_length;
        self
    }

    /// Override the maximum amount of base64 data accumulated per PEM block, in bytes.
    #[inline]
    pub const fn with_max_pem_body_bytes(mut self, max_pem_body_bytes: usize) -> Self {
        self.max_pem_body_bytes = max_pem_body_bytes;
        self
    }

    /// Override the maximum number of PEM blocks accepted from a single stream.
    #[inline]
    pub const fn with_max_pem_blocks(mut self, max_pem_blocks: usize) -> Self {
        self.max_pem_blocks = max_pem_blocks;
        self
    }

    /// Return `true` if an input of `len` bytes is allowed by this budget.
    #[inline]
    pub const fn allows_input(&self, len: usize) -> bool {
        len <= self.max_input_bytes
    }

    /// Return `true` if a line of `len` bytes is allowed by this budget.
    #[inline]
    pub const fn allows_line(&self, len: usize) -> bool {
        len <= self.max_line_length
    }

    /// Return `true` if a PEM body of `len` bytes is allowed by this budget.
    #[inline]
    pub const fn allows_pem_body(&self, len: usize) -> bool {
        len <= self.max_pem_body_bytes
    }

    /// Return `true` if `count` PEM blocks are allowed by this budget.
    #[inline]
    pub const fn allows_pem_blocks(&self, count: usize) -> bool {
        count <= self.max_pem_blocks
    }
}

impl Default for ParseBudget {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_budget_limits_are_inclusive() {
        let budget = ParseBudget::default();
        assert!(budget.allows_input(DEFAULT_MAX_INPUT_BYTES));
        assert!(!budget.allows_input(DEFAULT_MAX_INPUT_BYTES + 1));
        assert!(budget.allows_line(DEFAULT_MAX_LINE_LENGTH));
        assert!(!budget.allows_line(DEFAULT_MAX_LINE_LENGTH + 1));
        assert!(budget.allows_pem_body(DEFAULT_MAX_PEM_BODY_BYTES));
        assert!(!budget.allows_pem_body(DEFAULT_MAX_PEM_BODY_BYTES + 1));
        assert!(budget.allows_pem_blocks(DEFAULT_MAX_PEM_BLOCKS));
        assert!(!budget.allows_pem_blocks(DEFAULT_MAX_PEM_BLOCKS + 1));
    }

    #[test]
    fn unlimited_budget_accepts_any_size() {
        let budget = ParseBudget::unlimited();
        assert!(budget.allows_input(usize::MAX));
        assert!(budget.allows_line(usize::MAX));
        assert!(budget.allows_pem_body(usize::MAX));
        assert!(budget.allows_pem_blocks(usize::MAX));
    }

    #[test]
    fn builder_overrides_single_limit() {
        let budget = ParseBudget::default().with_max_input_bytes(16);
        assert_eq!(budget.max_input_bytes, 16);
        assert_eq!(budget.max_line_length, DEFAULT_MAX_LINE_LENGTH);
    }
}
