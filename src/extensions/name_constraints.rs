use asn1_rs::Sequence;

use super::GeneralName;
use crate::error::X509Error;
use asn1_rs::DynTagged;

/// Error type for name constraints evaluation (RFC 5280 section 4.2.1.10).
///
/// The evaluation is conservative: anything that cannot be decided safely
/// (unsupported base distances, malformed names, unsupported name forms that
/// are explicitly constrained) results in an error instead of being ignored.
#[derive(Clone, Debug, PartialEq, thiserror::Error)]
pub enum NameConstraintError {
    /// A subtree uses a non-zero `minimum` or a `maximum` base distance.
    ///
    /// These fields change the semantics of the constraint and must not be
    /// silently ignored.
    #[error(
        "name constraint uses a non-zero minimum or a maximum base distance, which is not supported"
    )]
    UnsupportedBaseDistance,
    /// An `iPAddress` name or constraint has an invalid length.
    ///
    /// Names must be 4 (IPv4) or 16 (IPv6) bytes; constraints must be
    /// address + netmask, i.e. 8 or 32 bytes.
    #[error("invalid iPAddress length in name or constraint")]
    InvalidIPAddressLength,
    /// A name (for ex. a URI) is malformed and cannot be evaluated.
    #[error("malformed name, cannot evaluate constraint")]
    InvalidName,
    /// The name form is explicitly constrained, but evaluation of this name
    /// form is not supported.
    #[error("name form is constrained but not supported for evaluation")]
    UnsupportedNameType,
    /// The name matches an excluded subtree.
    #[error("name is excluded by name constraints")]
    Excluded,
    /// Permitted subtrees exist for this name form, but the name matches none.
    #[error("name is not within any permitted subtree")]
    NotPermitted,
    /// Error while reading certificate extensions.
    #[error("x509 error: {0}")]
    X509(#[from] X509Error),
}

/// <pre>
/// -- IMPLICIT tags
/// NameConstraints ::= SEQUENCE {
///     permittedSubtrees       [0]     GeneralSubtrees OPTIONAL,
///     excludedSubtrees        [1]     GeneralSubtrees OPTIONAL }
/// </pre>
#[derive(Clone, Debug, PartialEq, Sequence)]
#[asn1(parse = "DER", encode = "")]
#[error(X509Error)]
pub struct NameConstraints<'a> {
    #[tag_implicit(0)]
    #[optional]
    pub permitted_subtrees: Option<Vec<GeneralSubtree<'a>>>,

    #[tag_implicit(1)]
    #[optional]
    pub excluded_subtrees: Option<Vec<GeneralSubtree<'a>>>,
}

/// Represents the structure used in the name constraints extensions.
/// The fields minimum and maximum are not supported (openssl also has no support).
///
/// <pre>
/// -- IMPLICIT tags
/// GeneralSubtree ::= SEQUENCE {
///     base                    GeneralName,
///     minimum         [0]     BaseDistance DEFAULT 0,
///     maximum         [1]     BaseDistance OPTIONAL }
///
/// BaseDistance ::= INTEGER (0..MAX)
/// </pre>
#[derive(Clone, Debug, PartialEq, Sequence)]
#[asn1(parse = "DER", encode = "")]
#[error(X509Error)]
pub struct GeneralSubtree<'a> {
    pub base: GeneralName<'a>,

    #[tag_implicit(0)]
    #[default(0)]
    pub minimum: u32,

    #[tag_implicit(1)]
    #[optional]
    pub maximum: Option<u32>,
}

impl GeneralSubtree<'_> {
    /// Ensure the base distance fields of this subtree are supported.
    ///
    /// Only the default `minimum = 0` and absent `maximum` are supported.
    /// Any other value changes the meaning of the constraint, so it must not
    /// be ignored: an error is returned instead.
    pub fn check_base_distance(&self) -> Result<(), NameConstraintError> {
        if self.minimum != 0 || self.maximum.is_some() {
            Err(NameConstraintError::UnsupportedBaseDistance)
        } else {
            Ok(())
        }
    }

    /// Test whether `name` matches this subtree.
    ///
    /// Only subtrees of the same name form as `name` can match; different
    /// forms return `Ok(false)`. Supported forms are `dNSName`, `rfc822Name`,
    /// `uniformResourceIdentifier` and `iPAddress`.
    pub fn matches(&self, name: &GeneralName<'_>) -> Result<bool, NameConstraintError> {
        self.check_base_distance()?;
        match (&self.base, name) {
            (GeneralName::DNSName(constraint), GeneralName::DNSName(name)) => {
                Ok(dns_name_matches(constraint, name))
            }
            (GeneralName::RFC822Name(constraint), GeneralName::RFC822Name(name)) => {
                Ok(rfc822_name_matches(constraint, name))
            }
            (GeneralName::URI(constraint), GeneralName::URI(name)) => {
                uri_name_matches(constraint, name)
            }
            (GeneralName::IPAddress(constraint), GeneralName::IPAddress(name)) => {
                ip_address_matches(constraint, name)
            }
            _ => Ok(false),
        }
    }
}

impl NameConstraints<'_> {
    /// Check a single [`GeneralName`] against these name constraints.
    ///
    /// Returns `Ok(())` if the name is permitted, or an error describing why
    /// it is not (excluded, not permitted, or not decidable).
    ///
    /// The check is conservative:
    /// - any subtree with a non-default `minimum`/`maximum` base distance
    ///   causes [`NameConstraintError::UnsupportedBaseDistance`], even if it
    ///   would not match the name;
    /// - name forms other than DNS, e-mail, URI and IP are accepted only if
    ///   no subtree constrains that form.
    pub fn check_general_name(&self, name: &GeneralName<'_>) -> Result<(), NameConstraintError> {
        // unknown base distances must never be ignored
        for subtree in self
            .permitted_subtrees
            .iter()
            .flatten()
            .chain(self.excluded_subtrees.iter().flatten())
        {
            subtree.check_base_distance()?;
        }

        let supported = matches!(
            name,
            GeneralName::DNSName(_)
                | GeneralName::RFC822Name(_)
                | GeneralName::URI(_)
                | GeneralName::IPAddress(_)
        );
        if !supported {
            // fail closed if this name form is explicitly constrained
            let tag = name.tag();
            let constrained = self
                .permitted_subtrees
                .iter()
                .flatten()
                .chain(self.excluded_subtrees.iter().flatten())
                .any(|subtree| subtree.base.tag() == tag);
            return if constrained {
                Err(NameConstraintError::UnsupportedNameType)
            } else {
                Ok(())
            };
        }

        // excluded subtrees take precedence over permitted subtrees
        if let Some(excluded) = &self.excluded_subtrees {
            for subtree in excluded {
                if subtree.matches(name)? {
                    return Err(NameConstraintError::Excluded);
                }
            }
        }

        if let Some(permitted) = &self.permitted_subtrees {
            let mut has_subtree_for_form = false;
            for subtree in permitted {
                if subtree.base.tag() != name.tag() {
                    continue;
                }
                has_subtree_for_form = true;
                if subtree.matches(name)? {
                    return Ok(());
                }
            }
            // if the permitted subtrees cover this name form, the name must
            // match one of them
            if has_subtree_for_form {
                return Err(NameConstraintError::NotPermitted);
            }
        }

        Ok(())
    }

    /// Check a list of [`GeneralName`]s (for ex. from a Subject Alternative
    /// Name extension) against these name constraints.
    ///
    /// Returns `Ok(())` if all names are permitted.
    pub fn check_general_names<'a, 'b: 'a>(
        &self,
        names: impl IntoIterator<Item = &'a GeneralName<'b>>,
    ) -> Result<(), NameConstraintError> {
        for name in names {
            self.check_general_name(name)?;
        }
        Ok(())
    }
}

/// Compare two ASCII strings case-insensitively (DNS, host and domain parts
/// are case-insensitive per RFC 5280 / RFC 1034).
fn ascii_eq_ignore_case(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}

/// Test whether `name` is `domain` or a subdomain of `domain`
/// (case-insensitive, label boundary aware).
fn is_in_domain(name: &str, domain: &str) -> bool {
    if name.len() < domain.len() {
        return false;
    }
    let (head, tail) = name.split_at(name.len() - domain.len());
    ascii_eq_ignore_case(tail, domain) && (head.is_empty() || head.ends_with('.'))
}

/// RFC 5280 4.2.1.10: DNS name restrictions are expressed as
/// `host.example.com`. Any DNS name constructed by adding zero or more labels
/// to the left of the constraint satisfies it. A leading period restricts the
/// match to proper subdomains (`.example.com` does not match `example.com`).
fn dns_name_matches(constraint: &str, name: &str) -> bool {
    if let Some(suffix) = constraint.strip_prefix('.') {
        !suffix.is_empty() && name.len() > suffix.len() && is_in_domain(name, suffix)
    } else {
        !constraint.is_empty() && is_in_domain(name, constraint)
    }
}

/// RFC 5280 4.2.1.10: a constraint for `rfc822Name` may be a full mailbox
/// (`user@example.com`, exact match), a host (`example.com`, matches any
/// mailbox on that host), or a domain (`.example.com`, matches mailboxes on
/// any subdomain).
fn rfc822_name_matches(constraint: &str, name: &str) -> bool {
    if constraint.contains('@') {
        return ascii_eq_ignore_case(constraint, name);
    }
    // host part of the mailbox (everything after the last '@')
    let host = name.rsplit('@').next().unwrap_or(name);
    if let Some(suffix) = constraint.strip_prefix('.') {
        !suffix.is_empty() && host.len() > suffix.len() && is_in_domain(host, suffix)
    } else {
        !constraint.is_empty() && ascii_eq_ignore_case(host, constraint)
    }
}

/// Extract the host part of an URI (`scheme://[userinfo@]host[:port]/...`).
fn uri_host(uri: &str) -> Option<&str> {
    let (_, rest) = uri.split_once("://")?;
    let authority = rest.split(['/', '?', '#']).next()?;
    let host_port = authority.rsplit('@').next()?;
    if host_port.starts_with('[') {
        // IPv6 literal: keep the brackets for comparison
        let end = host_port.find(']')?;
        Some(&host_port[..=end])
    } else {
        Some(host_port.split(':').next()?)
    }
}

/// RFC 5280 4.2.1.10: for URIs, the constraint applies to the host part of
/// the name. A leading period means any subdomain; without it, the
/// constraint specifies an exact host.
fn uri_name_matches(constraint: &str, name: &str) -> Result<bool, NameConstraintError> {
    let host = uri_host(name).ok_or(NameConstraintError::InvalidName)?;
    if host.is_empty() {
        return Err(NameConstraintError::InvalidName);
    }
    if let Some(suffix) = constraint.strip_prefix('.') {
        Ok(!suffix.is_empty() && host.len() > suffix.len() && is_in_domain(host, suffix))
    } else {
        Ok(!constraint.is_empty() && ascii_eq_ignore_case(host, constraint))
    }
}

/// RFC 5280 4.2.1.10: an `iPAddress` constraint is address + netmask
/// (8 octets for IPv4, 32 for IPv6); a name is a single address
/// (4 or 16 octets). Any other length is invalid and must not be ignored.
fn ip_address_matches(constraint: &[u8], name: &[u8]) -> Result<bool, NameConstraintError> {
    match (constraint.len(), name.len()) {
        (8, 4) | (32, 16) => {
            let (network, mask) = constraint.split_at(name.len());
            Ok(name
                .iter()
                .zip(network)
                .zip(mask)
                .all(|((addr, net), m)| addr & m == net & m))
        }
        // different address families cannot match
        (8, 16) | (32, 4) => Ok(false),
        _ => Err(NameConstraintError::InvalidIPAddressLength),
    }
}

#[cfg(test)]
mod tests {
    use asn1_rs::{DerParser, Input};
    use hex_literal::hex;

    use crate::prelude::GeneralName;

    use super::NameConstraints;

    #[test]
    fn extension_name_constraints() {
        // permitted subtree with 1 item DNS:".example.com"
        let bytes = &hex!("30 12 A0 10 30 0E 82 0C 2E 65 78 61 6D 70 6C 65 2E 63 6F 6D");

        let (rem, res) = NameConstraints::parse_der(Input::from(bytes)).expect("NameConstraints");
        assert!(rem.is_empty());
        assert!(res.permitted_subtrees.is_some());
        let permitted0 = &res.permitted_subtrees.as_ref().unwrap()[0];
        assert_eq!(permitted0.base, GeneralName::DNSName(".example.com"));
    }
}
