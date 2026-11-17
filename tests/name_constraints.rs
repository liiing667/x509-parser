//! Fixed certificate matrix for name constraints (RFC 5280, 4.2.1.10).
//!
//! For each identity type (DNS, e-mail, URI, IP) the matrix shows the
//! allowed, excluded, not-permitted and unknown-constraint cases, plus the
//! final result for an ordinary constrained CA chain.
//!
//! Certificates live in `assets/name_constraints/` (see `gen_certs.sh`).
//! Cases that cannot be expressed with openssl (non-default minimum/maximum
//! base distances, invalid IP lengths, unsupported name forms) are built
//! directly as `NameConstraints` values.

use x509_parser::extensions::{GeneralSubtree, NameConstraints};
use x509_parser::prelude::*;

fn load(name: &str) -> X509Certificate<'static> {
    let path = format!(
        "{}/assets/name_constraints/{name}.der",
        env!("CARGO_MANIFEST_DIR")
    );
    let der = std::fs::read(path).expect("read certificate");
    let (_, cert) =
        X509Certificate::from_der(Box::leak(der.into_boxed_slice())).expect("parse certificate");
    cert
}

fn subtree(base: GeneralName<'static>) -> GeneralSubtree<'static> {
    GeneralSubtree {
        base,
        minimum: 0,
        maximum: None,
    }
}

fn constraints(
    permitted: Vec<GeneralSubtree<'static>>,
    excluded: Vec<GeneralSubtree<'static>>,
) -> NameConstraints<'static> {
    NameConstraints {
        permitted_subtrees: if permitted.is_empty() {
            None
        } else {
            Some(permitted)
        },
        excluded_subtrees: if excluded.is_empty() {
            None
        } else {
            Some(excluded)
        },
    }
}

fn check_row(
    kind: &str,
    case: &str,
    got: &Result<(), NameConstraintError>,
    expected: &Result<(), NameConstraintError>,
) {
    let status = if got == expected { "OK  " } else { "FAIL" };
    println!("  [{status}] {kind:5} | {case:28} | got {got:?}");
    assert_eq!(got, expected, "{kind} / {case}");
}

#[test]
fn name_constraints_certificate_matrix() {
    println!("== certificate matrix (assets/name_constraints) ==");
    for kind in ["dns", "email", "uri", "ip"] {
        let ca = load(&format!("ca_{kind}"));
        for (case, expected) in [
            ("ok", Ok(())),
            ("excluded", Err(NameConstraintError::Excluded)),
            ("not_permitted", Err(NameConstraintError::NotPermitted)),
        ] {
            let leaf = load(&format!("leaf_{kind}_{case}"));
            let got = leaf.verify_name_constraints(&ca);
            check_row(kind, case, &got, &expected);
        }
    }

    // an unconstrained issuer must not affect the result
    let root = load("root");
    let leaf = load("leaf_dns_ok");
    let got = leaf.verify_name_constraints(&root);
    check_row("dns", "no constraints on issuer", &got, &Ok(()));
}

#[test]
fn name_constraints_constructed_names_and_case() {
    println!("== constructed names and case (DNS) ==");
    let nc = constraints(
        vec![
            subtree(GeneralName::DNSName(".example.com")),
            subtree(GeneralName::DNSName("host.other.org")),
        ],
        vec![],
    );
    let cases: &[(&str, &str, Result<(), NameConstraintError>)] = &[
        ("subdomain of permitted domain", "www.example.com", Ok(())),
        ("deep subdomain", "a.b.c.example.com", Ok(())),
        // ".example.com" does not include the bare domain itself
        (
            "bare domain of dotted constraint",
            "example.com",
            Err(NameConstraintError::NotPermitted),
        ),
        // "host.other.org" includes the host itself and its subdomains
        ("exact host constraint", "host.other.org", Ok(())),
        ("constructed below host", "a.host.other.org", Ok(())),
        (
            "label-boundary attack",
            "evilhost.other.org",
            Err(NameConstraintError::NotPermitted),
        ),
        (
            "suffix-but-not-subdomain",
            "notexample.com",
            Err(NameConstraintError::NotPermitted),
        ),
        // comparisons are case-insensitive
        ("upper-case name", "WWW.EXAMPLE.COM", Ok(())),
    ];
    for (case, name, expected) in cases {
        let got = nc.check_general_name(&GeneralName::DNSName(name));
        check_row("dns", case, &got, expected);
    }
    // constraint case must not matter either
    let nc_upper = constraints(vec![subtree(GeneralName::DNSName(".EXAMPLE.COM"))], vec![]);
    let got = nc_upper.check_general_name(&GeneralName::DNSName("www.example.com"));
    check_row("dns", "upper-case constraint", &got, &Ok(()));

    println!("== constructed names and case (e-mail) ==");
    let nc = constraints(
        vec![
            subtree(GeneralName::RFC822Name(".example.com")),
            subtree(GeneralName::RFC822Name("host.other.org")),
            subtree(GeneralName::RFC822Name("alice@example.org")),
        ],
        vec![],
    );
    let cases: &[(&str, &str, Result<(), NameConstraintError>)] = &[
        ("mailbox in domain", "user@mail.example.com", Ok(())),
        (
            "bare domain of dotted constraint",
            "user@example.com",
            Err(NameConstraintError::NotPermitted),
        ),
        // host constraint matches the host itself only
        ("mailbox on host", "user@host.other.org", Ok(())),
        (
            "host constraint is not a domain",
            "user@sub.host.other.org",
            Err(NameConstraintError::NotPermitted),
        ),
        // full mailbox constraint, compared case-insensitively
        ("exact mailbox", "alice@example.org", Ok(())),
        ("exact mailbox, case", "ALICE@EXAMPLE.ORG", Ok(())),
        (
            "other mailbox on same host",
            "bob@example.org",
            Err(NameConstraintError::NotPermitted),
        ),
    ];
    for (case, name, expected) in cases {
        let got = nc.check_general_name(&GeneralName::RFC822Name(name));
        check_row("email", case, &got, expected);
    }

    println!("== constructed names and case (URI) ==");
    let nc = constraints(
        vec![
            subtree(GeneralName::URI(".example.com")),
            subtree(GeneralName::URI("host.other.org")),
        ],
        vec![],
    );
    let cases: &[(&str, &str, Result<(), NameConstraintError>)] = &[
        ("host in domain", "https://www.example.com/path", Ok(())),
        ("scheme and host case", "HTTPS://WWW.EXAMPLE.COM/", Ok(())),
        (
            "port and userinfo",
            "https://user@www.example.com:8443/",
            Ok(()),
        ),
        ("exact host", "https://host.other.org/", Ok(())),
        (
            "host constraint is exact",
            "https://sub.host.other.org/",
            Err(NameConstraintError::NotPermitted),
        ),
        (
            "bare domain of dotted constraint",
            "https://example.com/",
            Err(NameConstraintError::NotPermitted),
        ),
        (
            "malformed URI",
            "not-an-absolute-uri",
            Err(NameConstraintError::InvalidName),
        ),
    ];
    for (case, name, expected) in cases {
        let got = nc.check_general_name(&GeneralName::URI(name));
        check_row("uri", case, &got, expected);
    }
}

#[test]
fn name_constraints_ip_length_semantics() {
    println!("== IP address length semantics ==");
    // 192.168.0.0/16 and 2001:db8::/32
    let v4: &[u8] = &[192, 168, 0, 0, 255, 255, 0, 0];
    let v6: &[u8] = &[
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // address
        255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // mask
    ];
    let nc = constraints(
        vec![
            subtree(GeneralName::IPAddress(v4)),
            subtree(GeneralName::IPAddress(v6)),
        ],
        vec![],
    );
    let cases: &[(&str, &[u8], Result<(), NameConstraintError>)] = &[
        ("IPv4 in range", &[192, 168, 1, 2], Ok(())),
        (
            "IPv4 out of range",
            &[10, 0, 0, 1],
            Err(NameConstraintError::NotPermitted),
        ),
        (
            "IPv6 in range",
            &[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            Ok(()),
        ),
        (
            "IPv6 out of range",
            &[0x20, 0x01, 0x0d, 0xb9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            Err(NameConstraintError::NotPermitted),
        ),
        // unknown lengths must not be ignored
        (
            "IPv4 name, bad length",
            &[192, 168, 1],
            Err(NameConstraintError::InvalidIPAddressLength),
        ),
        (
            "IPv6 name, bad length",
            &[0x20, 0x01, 0x0d, 0xb8, 0],
            Err(NameConstraintError::InvalidIPAddressLength),
        ),
    ];
    for (case, name, expected) in cases {
        let got = nc.check_general_name(&GeneralName::IPAddress(name));
        check_row("ip", case, &got, expected);
    }
    // a constraint with an unknown length must not be ignored either
    let nc_bad = constraints(
        vec![subtree(GeneralName::IPAddress(&[192, 168, 0]))],
        vec![],
    );
    let got = nc_bad.check_general_name(&GeneralName::IPAddress(&[192, 168, 0, 1]));
    check_row(
        "ip",
        "constraint, bad length",
        &got,
        &Err(NameConstraintError::InvalidIPAddressLength),
    );
}

#[test]
fn name_constraints_unknown_base_distance_not_ignored() {
    println!("== unknown minimum/maximum base distances ==");
    let name = GeneralName::DNSName("www.example.com");
    for (case, minimum, maximum) in [
        ("minimum = 1", 1, None),
        ("maximum = 1", 0, Some(1)),
        ("minimum = 1, maximum = 1", 1, Some(1)),
    ] {
        let nc = constraints(
            vec![GeneralSubtree {
                base: GeneralName::DNSName(".example.com"),
                minimum,
                maximum,
            }],
            vec![],
        );
        let got = nc.check_general_name(&name);
        check_row(
            "dns",
            case,
            &got,
            &Err(NameConstraintError::UnsupportedBaseDistance),
        );
    }
    // an unsupported base distance is reported even if the subtree would
    // never match the name being checked
    let nc = constraints(
        vec![GeneralSubtree {
            base: GeneralName::DNSName(".unrelated.org"),
            minimum: 2,
            maximum: None,
        }],
        vec![],
    );
    let got = nc.check_general_name(&name);
    check_row(
        "dns",
        "non-matching subtree, minimum = 2",
        &got,
        &Err(NameConstraintError::UnsupportedBaseDistance),
    );
}

#[test]
fn name_constraints_unsupported_name_form() {
    println!("== unsupported name forms ==");
    use asn1_rs::Oid;
    let oid = Oid::from(&[1, 2, 3, 4]).expect("valid OID");
    let name = GeneralName::RegisteredID(oid.clone());
    // unconstrained forms are accepted
    let nc = constraints(vec![subtree(GeneralName::DNSName(".example.com"))], vec![]);
    let got = nc.check_general_name(&name);
    check_row("other", "unconstrained form", &got, &Ok(()));
    // but a constrained unsupported form fails closed
    let nc = constraints(vec![subtree(GeneralName::RegisteredID(oid))], vec![]);
    let got = nc.check_general_name(&name);
    check_row(
        "other",
        "constrained unsupported form",
        &got,
        &Err(NameConstraintError::UnsupportedNameType),
    );
}

#[test]
fn name_constraints_excluded_takes_precedence() {
    println!("== excluded subtrees take precedence ==");
    let nc = constraints(
        vec![subtree(GeneralName::DNSName(".example.com"))],
        vec![subtree(GeneralName::DNSName(".blocked.example.com"))],
    );
    let cases: &[(&str, &str, Result<(), NameConstraintError>)] = &[
        ("permitted and not excluded", "www.example.com", Ok(())),
        (
            "permitted but excluded",
            "www.blocked.example.com",
            Err(NameConstraintError::Excluded),
        ),
    ];
    for (case, name, expected) in cases {
        let got = nc.check_general_name(&GeneralName::DNSName(name));
        check_row("dns", case, &got, expected);
    }
}
