use std::collections::HashSet;

pub trait Logger {
    fn warn(&mut self, message: &str);

    fn err(&mut self, message: &str);
}

/// Simple Logger for [`Validator`](crate::validate::Validator) trait, storing messages in `Vec`
///
/// Identical diagnostics are stored only once: this keeps the collected
/// evidence stable when several validators overlap (for ex. when chaining
/// [`X509StructureValidator`](crate::validate::X509StructureValidator) with
/// [`X509CertificateValidator`](crate::validate::X509CertificateValidator)).
/// Warnings and errors are tracked independently, so de-duplication never
/// promotes a warning to an error or vice-versa.
#[derive(Debug, Default)]
pub struct VecLogger {
    warnings: Vec<String>,
    seen_warnings: HashSet<String>,
    errors: Vec<String>,
    seen_errors: HashSet<String>,
}

impl VecLogger {
    /// Get stored warnings
    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }

    /// Get stored errors
    pub fn errors(&self) -> &[String] {
        &self.errors
    }
}

impl Logger for VecLogger {
    fn warn(&mut self, message: &str) {
        if self.seen_warnings.insert(message.to_owned()) {
            self.warnings.push(message.to_owned());
        }
    }

    fn err(&mut self, message: &str) {
        if self.seen_errors.insert(message.to_owned()) {
            self.errors.push(message.to_owned());
        }
    }
}

/// Simple Logger for [`Validator`](crate::validate::Validator) trait, printing messages to `stderr`
#[derive(Debug, Default)]
pub struct StderrLogger;

impl Logger for StderrLogger {
    fn warn(&mut self, message: &str) {
        eprintln!("[W] {message}");
    }

    fn err(&mut self, message: &str) {
        eprintln!("[E] {message}");
    }
}

/// Simple Logger for [`Validator`](crate::validate::Validator) trait, using closures for `warn`/`err`.
#[derive(Debug, Default)]
pub struct CallbackLogger<W, E>
where
    W: FnMut(&str),
    E: FnMut(&str),
{
    warn: W,
    err: E,
}

impl<W, E> CallbackLogger<W, E>
where
    W: FnMut(&str),
    E: FnMut(&str),
{
    pub fn new(warn: W, err: E) -> Self {
        CallbackLogger { warn, err }
    }
}

impl<W, E> Logger for CallbackLogger<W, E>
where
    W: FnMut(&str),
    E: FnMut(&str),
{
    fn warn(&mut self, message: &str) {
        (self.warn)(message);
    }

    fn err(&mut self, message: &str) {
        (self.err)(message);
    }
}
