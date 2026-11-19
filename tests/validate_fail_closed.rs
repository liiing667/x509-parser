#![cfg(feature = "validate")]

use asn1_rs::Input;
use nom::Parser;
use x509_parser::prelude::*;

/// Certificates containing a hard extension error must be rejected by the
/// strict parser entry point, while the default parser keeps its historical
/// lenient behavior (the error surfaces through the validators instead).
#[test]
fn strict_parser_rejects_unsupported_critical_extension() {
    let critical = include_bytes!("../assets/unsupported_critical_ext.der");
    let non_critical = include_bytes!("../assets/unsupported_noncritical_ext.der");
    let good = include_bytes!("../assets/IGC_A.der");

    // default parsing remains unchanged (backward compatibility)
    assert!(X509Certificate::from_der(critical).is_ok());
    assert!(X509Certificate::from_der(non_critical).is_ok());

    let mut strict = X509CertificateParser::new().with_check_extensions(true);
    // unknown CRITICAL extension: entry point must fail closed
    assert!(strict.parse(Input::from(critical)).is_err());
    // unknown non-critical extension is still accepted
    assert!(strict.parse(Input::from(non_critical)).is_ok());
    // ordinary valid certificates are unaffected
    assert!(strict.parse(Input::from(good)).is_ok());
}

#[test]
fn strict_tbs_parser_rejects_unsupported_critical_extension() {
    let critical = include_bytes!("../assets/unsupported_critical_ext.der");
    let (_, cert) = X509Certificate::from_der(critical).expect("default parse should succeed");

    let mut tbs_strict = TbsCertificateParser::new().with_check_extensions(true);
    assert!(tbs_strict
        .parse(Input::from(cert.tbs_certificate.as_ref()))
        .is_err());

    // default TBS parser still accepts it
    let mut tbs_default = TbsCertificateParser::new();
    assert!(tbs_default
        .parse(Input::from(cert.tbs_certificate.as_ref()))
        .is_ok());
}

#[test]
fn strict_parser_rejects_unparseable_extension() {
    let malformed = include_bytes!("../assets/malformed_extension.der");

    // default parser keeps returning the certificate with a ParseError extension
    let (_, cert) = X509Certificate::from_der(malformed).expect("default parse should succeed");
    assert!(cert
        .extensions()
        .iter()
        .any(|e| matches!(e.parsed_extension(), ParsedExtension::ParseError { .. })));

    // strict entry point fails closed on the unparseable extension
    let mut strict = X509CertificateParser::new().with_check_extensions(true);
    assert!(strict.parse(Input::from(malformed)).is_err());
}

#[test]
fn hard_errors_fail_but_warnings_pass() {
    let cases: &[(&[u8], bool, &str)] = &[
        (
            include_bytes!("../assets/keyusage_zero.der"),
            false,
            "KeyUsage",
        ),
        (
            include_bytes!("../assets/duplicate_policy.der"),
            false,
            "duplicate policy",
        ),
        (include_bytes!("../assets/aki_critical.der"), false, "AKI"),
        (
            include_bytes!("../assets/duplicate_extension.der"),
            false,
            "Duplicate extension",
        ),
        (
            include_bytes!("../assets/unsupported_critical_ext.der"),
            false,
            "Unsupported critical",
        ),
        (
            include_bytes!("../assets/unsupported_noncritical_ext.der"),
            true,
            "Unsupported extension",
        ),
    ];

    for (der, should_pass, marker) in cases {
        let (_, cert) = X509Certificate::from_der(der).expect("all fixtures are valid DER");
        let mut logger = VecLogger::default();
        let ok = X509StructureValidator.validate(&cert, &mut logger);

        assert_eq!(ok, *should_pass, "validation result mismatch for {marker}");
        if *should_pass {
            assert!(
                logger.errors().is_empty(),
                "no hard errors expected for {marker}, got {:?}",
                logger.errors()
            );
            assert!(
                logger.warnings().iter().any(|w| w.contains(marker)),
                "expected warning containing {marker}, got {:?}",
                logger.warnings()
            );
        } else {
            assert!(
                logger.errors().iter().any(|e| e.contains(marker)),
                "expected hard error containing {marker}, got {:?}",
                logger.errors()
            );
        }
    }
}
