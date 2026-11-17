use asn1_rs::Any;
use x509_parser::extensions::{CanonicalGeneralName, GeneralName};
use x509_parser::prelude::*;

/// Table of (input, expected canonical identity) cases, exercised through
/// the same entry point used by security comparisons.
#[test]
fn canonical_identity_table() {
    let cases: &[(&GeneralName, Result<CanonicalGeneralName, X509Error>)] = &[
        // URI: scheme and host are case-folded, trailing dot removed
        (
            &GeneralName::URI("HTTP://Example.COM./path"),
            Ok(CanonicalGeneralName::Uri("http://example.com/path".into())),
        ),
        // URI: userinfo and port preserved, host folded
        (
            &GeneralName::URI("https://user@Example.com:8443/x?y#z"),
            Ok(CanonicalGeneralName::Uri(
                "https://user@example.com:8443/x?y#z".into(),
            )),
        ),
        // URI: percent-encoded unreserved decoded, other triplets uppercased
        (
            &GeneralName::URI("http://example.com/%7euser/%2f"),
            Ok(CanonicalGeneralName::Uri(
                "http://example.com/~user/%2F".into(),
            )),
        ),
        // URI: IPv6 literal host folded
        (
            &GeneralName::URI("http://[2001:DB8::1]:8080/"),
            Ok(CanonicalGeneralName::Uri(
                "http://[2001:db8::1]:8080/".into(),
            )),
        ),
        // URI: no authority component
        (
            &GeneralName::URI("MAILTO:User@Example.com"),
            Ok(CanonicalGeneralName::Uri("mailto:User@Example.com".into())),
        ),
        // URI: malformed percent-encoding fails closed
        (
            &GeneralName::URI("http://example.com/%zz"),
            Err(X509Error::InvalidGeneralName),
        ),
        (
            &GeneralName::URI("http://example.com/%"),
            Err(X509Error::InvalidGeneralName),
        ),
        (
            &GeneralName::URI("http://example.com/%2"),
            Err(X509Error::InvalidGeneralName),
        ),
        // URI: missing scheme fails closed
        (
            &GeneralName::URI("example.com"),
            Err(X509Error::InvalidGeneralName),
        ),
        // URI: non-digit port fails closed
        (
            &GeneralName::URI("http://example.com:8o8o/"),
            Err(X509Error::InvalidGeneralName),
        ),
        // E-mail: domain folded, local part case preserved
        (
            &GeneralName::RFC822Name("User@Example.COM"),
            Ok(CanonicalGeneralName::RFC822Name("User@example.com".into())),
        ),
        // E-mail: bare domain (name-constraint form) folded
        (
            &GeneralName::RFC822Name("Example.COM"),
            Ok(CanonicalGeneralName::RFC822Name("example.com".into())),
        ),
        // DNS: folded, single trailing root dot removed
        (
            &GeneralName::DNSName("Example.COM."),
            Ok(CanonicalGeneralName::DNSName("example.com".into())),
        ),
        // DNS: root-only or empty names fail closed
        (
            &GeneralName::DNSName("."),
            Err(X509Error::InvalidGeneralName),
        ),
        (
            &GeneralName::DNSName(""),
            Err(X509Error::InvalidGeneralName),
        ),
        // IP: only 4 or 16 bytes are well-formed
        (
            &GeneralName::IPAddress(&[192, 0, 2, 1]),
            Ok(CanonicalGeneralName::IPAddress(vec![192, 0, 2, 1])),
        ),
        (
            &GeneralName::IPAddress(&[0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
            Ok(CanonicalGeneralName::IPAddress(vec![
                0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
            ])),
        ),
        (
            &GeneralName::IPAddress(&[192, 0, 2]),
            Err(X509Error::InvalidGeneralName),
        ),
        (
            &GeneralName::IPAddress(&[192, 0, 2, 1, 0]),
            Err(X509Error::InvalidGeneralName),
        ),
        (
            &GeneralName::IPAddress(&[]),
            Err(X509Error::InvalidGeneralName),
        ),
    ];
    for (input, expected) in cases {
        assert_eq!(&input.canonical_identity(), expected, "input: {input}");
    }
}

/// Identities that must be considered equal for security comparisons.
#[test]
fn canonical_identity_equivalences() {
    let groups: &[&[GeneralName]] = &[
        &[
            GeneralName::DNSName("example.com"),
            GeneralName::DNSName("EXAMPLE.COM"),
            GeneralName::DNSName("example.com."),
        ],
        &[
            GeneralName::RFC822Name("User@example.com"),
            GeneralName::RFC822Name("User@EXAMPLE.COM"),
        ],
        &[
            GeneralName::URI("http://example.com/path"),
            GeneralName::URI("HTTP://EXAMPLE.COM./path"),
            GeneralName::URI("http://example.com/%70ath"),
        ],
    ];
    for group in groups {
        let first = group[0].canonical_identity().unwrap();
        for other in &group[1..] {
            assert_eq!(first, other.canonical_identity().unwrap(), "{other}");
        }
    }
}

/// Cross-type table: names that share a surface string but have different
/// GeneralName types must never share a canonical identity.
#[test]
fn canonical_identity_cross_type_distinct() {
    let names: &[GeneralName] = &[
        GeneralName::DNSName("example.com"),
        GeneralName::RFC822Name("example.com"),
        GeneralName::RFC822Name("user@example.com"),
        GeneralName::URI("http://example.com"),
        GeneralName::URI("example.com"),
        GeneralName::IPAddress(&[93, 184, 216, 34]),
    ];
    let identities: Vec<_> = names.iter().map(|n| n.canonical_identity()).collect();
    // the URI without scheme fails closed rather than colliding with the DNS name
    assert_eq!(identities[4], Err(X509Error::InvalidGeneralName));
    for (i, a) in identities.iter().enumerate() {
        for (j, b) in identities.iter().enumerate() {
            if i != j && a.is_ok() && b.is_ok() {
                assert_ne!(a, b, "cross-type collision between {i} and {j}");
            }
        }
    }
}

/// Invalid entries and raw accessors: canonicalization fails closed on
/// invalid data, while the raw GeneralName is preserved untouched.
#[test]
fn canonical_identity_fails_closed_and_raw_preserved() {
    // an entry that could not be interpreted as any GeneralName choice
    let (_, any) = Any::from_der(&[0x04, 0x00]).unwrap();
    let gn = GeneralName::Invalid(any);
    assert!(matches!(gn, GeneralName::Invalid(_)));
    assert_eq!(gn.canonical_identity(), Err(X509Error::InvalidGeneralName));

    // raw accessors are unchanged by canonicalization
    let raw = GeneralName::URI("HTTP://Example.COM./%7epath");
    let _ = raw.canonical_identity().unwrap();
    assert_eq!(raw, GeneralName::URI("HTTP://Example.COM./%7epath"));
    let raw = GeneralName::DNSName("Example.COM.");
    let _ = raw.canonical_identity().unwrap();
    assert_eq!(raw, GeneralName::DNSName("Example.COM."));
}
