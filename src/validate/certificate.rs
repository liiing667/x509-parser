use crate::certificate::*;
use crate::validate::*;

/// X.509 extension validator for `X509Certificate`
///
/// This validator runs the extension-level semantic checks
/// ([`X509ExtensionsValidator`]) on the certificate extensions.
///
/// These checks are also run by [`X509StructureValidator`] (which is the
/// recommended entry point). Chaining both validators therefore produces the
/// same single set of warnings and errors, and a hard error raised by either
/// validator always makes the chain fail.
#[derive(Debug)]
pub struct X509CertificateValidator;

impl<'a> Validator<'a> for X509CertificateValidator {
    type Item = X509Certificate<'a>;

    fn validate<L: Logger>(&self, item: &'a Self::Item, l: &'_ mut L) -> bool {
        X509ExtensionsValidator.validate(&item.extensions(), l)
    }
}
