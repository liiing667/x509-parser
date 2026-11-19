//! Tests for the consistency between the inner (TBS) and outer signature
//! algorithm identifiers (RFC 5280, sections 4.1.1.2 and 5.1.1.2).
//!
//! Parsing must remain lenient (an inconsistent object is still parsed), but
//! the conflict must be reported explicitly and deterministically, and an
//! inconsistent object must not be considered verifiable.

use x509_parser::certificate::X509CertificateParser;
use x509_parser::error::X509Error;
use x509_parser::nom::Parser;
use x509_parser::prelude::*;

static IGCA_DER: &[u8] = include_bytes!("../assets/IGC_A.der");
static IGCA_PEM: &str = include_str!("../assets/IGC_A.pem");
static CRL_DER: &[u8] = include_bytes!("../assets/example.crl");
static RSA_PSS_SHA256_DER: &[u8] = include_bytes!("../assets/rsa-pss/self_signed_sha256.der");

// sha1WithRSAEncryption (1.2.840.113549.1.1.5), DER-encoded OID
const SHA1_WITH_RSA_OID: &[u8] = &[
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05,
];
// sha256 (2.16.840.1.101.3.4.2.1), DER-encoded OID (used in RSASSA-PSS parameters)
const SHA256_OID: &[u8] = &[
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
];

/// Return a copy of `der` where the last byte of the first occurrence of
/// `oid_der` is replaced by `new_last_byte`.
///
/// In certificates and CRLs, the inner (TBS) signature algorithm identifier
/// always appears before the outer one, so this patches the inner identifier.
fn patch_first_oid(der: &[u8], oid_der: &[u8], new_last_byte: u8) -> Vec<u8> {
    let count = der.windows(oid_der.len()).filter(|w| *w == oid_der).count();
    assert!(
        count >= 2,
        "expected at least inner and outer algorithm identifiers"
    );
    let pos = der
        .windows(oid_der.len())
        .position(|w| w == oid_der)
        .expect("OID not found");
    let mut v = der.to_vec();
    v[pos + oid_der.len() - 1] = new_last_byte;
    v
}

/// Classification of a DER-encoded certificate: (parses, consistency result)
fn classify_certificate(der: &[u8]) -> (bool, Option<X509Error>) {
    match parse_x509_certificate(der) {
        Ok((_, cert)) => {
            let consistency = cert.check_signature_algorithm_consistency().err();
            (true, consistency)
        }
        Err(_) => (false, None),
    }
}

#[test]
fn consistent_certificate_is_accepted() {
    let (_, cert) = parse_x509_certificate(IGCA_DER).expect("could not parse certificate");
    assert_eq!(cert.check_signature_algorithm_consistency(), Ok(()));
}

#[test]
fn consistent_certificate_pem_is_accepted() {
    let (pem, _) = ::x509_parser::pem::Pem::read(std::io::Cursor::new(IGCA_PEM))
        .expect("could not read PEM");
    let cert = pem.parse_x509().expect("could not parse certificate");
    assert_eq!(cert.check_signature_algorithm_consistency(), Ok(()));
}

#[test]
fn mismatched_certificate_algorithm_is_detected() {
    // replace inner algorithm sha1WithRSAEncryption by sha512WithRSAEncryption
    // (1.2.840.113549.1.1.13): same length, so the DER stays valid
    let der = patch_first_oid(IGCA_DER, SHA1_WITH_RSA_OID, 0x0d);
    // parsing must still succeed (lenient parsing layer)
    let (_, cert) = parse_x509_certificate(&der).expect("could not parse certificate");
    // ... but the conflict must be reported explicitly
    assert_eq!(
        cert.check_signature_algorithm_consistency(),
        Err(X509Error::SignatureAlgorithmMismatch)
    );
}

#[test]
fn mismatched_certificate_pss_parameters_are_detected() {
    // replace the hash algorithm of the inner RSASSA-PSS parameters
    // (sha256 -> sha512, 2.16.840.1.101.3.4.2.3): the algorithm OID is
    // unchanged, only the parameters conflict
    let der = patch_first_oid(RSA_PSS_SHA256_DER, SHA256_OID, 0x03);
    let (_, cert) = parse_x509_certificate(&der).expect("could not parse certificate");
    assert_eq!(
        cert.check_signature_algorithm_consistency(),
        Err(X509Error::SignatureAlgorithmMismatch)
    );
    // control: the unmodified certificate is consistent
    let (_, cert) = parse_x509_certificate(RSA_PSS_SHA256_DER).expect("could not parse certificate");
    assert_eq!(cert.check_signature_algorithm_consistency(), Ok(()));
}

#[test]
fn certificate_classification_is_stable() {
    let der = patch_first_oid(IGCA_DER, SHA1_WITH_RSA_OID, 0x0d);
    let expected = classify_certificate(&der);
    assert_eq!(expected, (true, Some(X509Error::SignatureAlgorithmMismatch)));
    // retries must yield the same classification
    for _ in 0..100 {
        assert_eq!(classify_certificate(&der), expected);
    }
    // concurrent classification must yield the same result
    let handles: Vec<_> = (0..8)
        .map(|_| {
            let der = der.clone();
            std::thread::spawn(move || classify_certificate(&der))
        })
        .collect();
    for handle in handles {
        assert_eq!(handle.join().unwrap(), expected);
    }
    // parser configuration must not change the classification
    let mut parser = X509CertificateParser::new().with_deep_parse_extensions(false);
    let (_, cert) = parser
        .parse(Input::from(&der[..]))
        .expect("could not parse certificate");
    assert_eq!(
        cert.check_signature_algorithm_consistency(),
        Err(X509Error::SignatureAlgorithmMismatch)
    );
}

#[test]
fn consistent_crl_is_accepted() {
    let (_, crl) = parse_x509_crl(CRL_DER).expect("could not parse CRL");
    assert_eq!(crl.check_signature_algorithm_consistency(), Ok(()));
}

#[test]
fn mismatched_crl_algorithm_is_detected() {
    let der = patch_first_oid(CRL_DER, SHA1_WITH_RSA_OID, 0x0d);
    let (_, crl) = parse_x509_crl(&der).expect("could not parse CRL");
    assert_eq!(
        crl.check_signature_algorithm_consistency(),
        Err(X509Error::SignatureAlgorithmMismatch)
    );
}

#[cfg(any(
    feature = "verify",
    feature = "verify-aws",
    feature = "verify-aws-fips"
))]
mod verify {
    use super::*;

    #[test]
    fn inconsistent_certificate_is_not_verifiable() {
        let der = patch_first_oid(IGCA_DER, SHA1_WITH_RSA_OID, 0x0d);
        let (_, cert) = parse_x509_certificate(&der).expect("could not parse certificate");
        // the conflict must be reported as such, not as a generic verification error
        assert_eq!(
            cert.verify_signature(None),
            Err(X509Error::SignatureAlgorithmMismatch)
        );
    }

    #[test]
    fn inconsistent_pss_certificate_is_not_verifiable() {
        let der = patch_first_oid(RSA_PSS_SHA256_DER, SHA256_OID, 0x03);
        let (_, cert) = parse_x509_certificate(&der).expect("could not parse certificate");
        assert_eq!(
            cert.verify_signature(None),
            Err(X509Error::SignatureAlgorithmMismatch)
        );
    }

    #[test]
    fn consistent_certificate_remains_verifiable() {
        let (_, cert) =
            parse_x509_certificate(RSA_PSS_SHA256_DER).expect("could not parse certificate");
        assert_eq!(cert.verify_signature(None), Ok(()));
    }
}
