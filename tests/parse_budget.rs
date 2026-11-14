//! Acceptance tests for the unified resource budget and strict PEM framing.

use std::io::Cursor;

use x509_parser::budget::ParseBudget;
use x509_parser::error::{PEMError, X509Error};
use x509_parser::pem::{parse_x509_pem, parse_x509_pem_with_budget, Pem};
use x509_parser::prelude::{FromDer, X509CertificationRequest};
use x509_parser::{
    parse_x509_certificate, parse_x509_certificate_with_budget, parse_x509_crl,
    parse_x509_crl_with_budget, parse_x509_csr, parse_x509_csr_with_budget,
};

const CERT_DER: &[u8] = include_bytes!("../assets/IGC_A.der");
const CERT_PEM: &[u8] = include_bytes!("../assets/IGC_A.pem");
const CRL_DER: &[u8] = include_bytes!("../assets/example.crl");
const CSR_DER: &[u8] = include_bytes!("../assets/csr-empty-attributes.csr");

const fn small_budget() -> ParseBudget {
    ParseBudget {
        max_input_bytes: 64,
        max_line_length: 64,
        max_pem_body_bytes: 64,
        max_pem_blocks: 4,
    }
}

fn dangling_pem(body_len: usize) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(b"-----BEGIN CERTIFICATE-----\n");
    let full_lines = body_len / 64;
    for _ in 0..full_lines {
        data.extend_from_slice(&[b'A'; 64]);
        data.push(b'\n');
    }
    let remainder = body_len % 64;
    if remainder != 0 {
        data.extend(std::iter::repeat_n(b'A', remainder));
        data.push(b'\n');
    }
    data
}

fn valid_pem_block(seq: usize) -> Vec<u8> {
    format!("-----BEGIN CERTIFICATE{seq}-----\nAA==\n-----END CERTIFICATE{seq}-----\n").into_bytes()
}

// ---------- PEM: strict framing ----------

#[test]
fn parse_budget_dangling_block_without_end_is_incomplete() {
    let data = dangling_pem(128);
    let err = Pem::read(Cursor::new(data.as_slice())).unwrap_err();
    assert!(matches!(err, PEMError::IncompletePEM));
}

#[test]
fn parse_budget_end_tag_without_closing_dashes_is_rejected() {
    const DATA: &[u8] = b"-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE\n";
    let err = Pem::read(Cursor::new(DATA)).unwrap_err();
    assert!(matches!(err, PEMError::InvalidEndTag));
}

#[test]
fn parse_budget_end_tag_with_trailing_junk_is_rejected() {
    const DATA: &[u8] = b"-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE----- junk\n";
    let err = Pem::read(Cursor::new(DATA)).unwrap_err();
    assert!(matches!(err, PEMError::InvalidEndTag));
}

#[test]
fn parse_budget_begin_tag_with_trailing_junk_is_rejected() {
    const DATA: &[u8] = b"-----BEGIN CERTIFICATE----- junk\nAA==\n-----END CERTIFICATE-----\n";
    let err = Pem::read(Cursor::new(DATA)).unwrap_err();
    assert!(matches!(err, PEMError::InvalidHeader));
}

#[test]
fn parse_budget_mismatched_end_label_remains_invalid_header() {
    const DATA: &[u8] = b"-----BEGIN CERTIFICATE-----\nAA==\n-----END PRIVATE KEY-----\n";
    let err = Pem::read(Cursor::new(DATA)).unwrap_err();
    assert!(matches!(err, PEMError::InvalidHeader));
}

// ---------- PEM: resource budget ----------

#[test]
fn parse_budget_dangling_block_is_bounded() {
    let budget = small_budget();
    let data = dangling_pem(4096);
    let err = Pem::read_with_budget(Cursor::new(data.as_slice()), &budget).unwrap_err();
    assert!(matches!(err, PEMError::BudgetExceeded));
}

#[test]
fn parse_budget_huge_line_does_not_allocate_unbounded() {
    let budget = small_budget();
    let mut data = b"-----BEGIN CERTIFICATE-----\n".to_vec();
    data.extend(std::iter::repeat_n(b'A', 8192));
    data.push(b'\n');
    let err = Pem::read_with_budget(Cursor::new(data.as_slice()), &budget).unwrap_err();
    assert!(matches!(err, PEMError::BudgetExceeded));
}

#[test]
fn parse_budget_complete_oversized_block_is_rejected() {
    let budget = small_budget();
    let mut data = dangling_pem(256);
    data.extend_from_slice(b"-----END CERTIFICATE-----\n");
    let err = Pem::read_with_budget(Cursor::new(data.as_slice()), &budget).unwrap_err();
    assert!(matches!(err, PEMError::BudgetExceeded));
}

#[test]
fn parse_budget_iterator_stops_after_block_limit() {
    let budget = ParseBudget::default().with_max_pem_blocks(2);
    let mut data = Vec::new();
    for seq in 0..5 {
        data.extend_from_slice(&valid_pem_block(seq));
    }
    let results: Vec<_> = Pem::iter_from_buffer_with_budget(&data, budget).collect();
    assert_eq!(results.len(), 3, "two blocks then one stable error");
    assert!(results[0].is_ok());
    assert!(results[1].is_ok());
    assert!(matches!(
        results[2].as_ref().unwrap_err(),
        PEMError::BudgetExceeded
    ));
}

#[test]
fn parse_budget_iterator_error_is_stable_and_terminal() {
    let budget = small_budget();
    let mut data = valid_pem_block(0);
    // dangling block: the iterator must surface IncompletePEM once and then stop
    data.extend_from_slice(b"-----BEGIN CERTIFICATE-----\nAA==\n");
    let results: Vec<_> = Pem::iter_from_buffer_with_budget(&data, budget).collect();
    assert_eq!(results.len(), 2);
    assert!(results[0].is_ok());
    assert!(matches!(
        results[1].as_ref().unwrap_err(),
        PEMError::IncompletePEM
    ));
}

#[test]
fn parse_budget_unlimited_pem_accepts_large_input() {
    let mut complete = b"-----BEGIN CERTIFICATE-----\n".to_vec();
    complete.extend(std::iter::repeat_n(b'A', 4096));
    complete.extend_from_slice(b"\n-----END CERTIFICATE-----\n");
    // `A` repeated 4096 times decodes to 3072 zero bytes
    let (rem, pem) =
        parse_x509_pem_with_budget(&complete, &ParseBudget::unlimited()).expect("parse");
    assert!(rem.is_empty());
    assert_eq!(pem.label, "CERTIFICATE");
    assert_eq!(pem.contents.len(), 3072);
}

#[test]
fn parse_budget_pem_custom_limit_overrides_default() {
    // a small custom budget rejects inputs the default budget would accept
    let mut complete = b"-----BEGIN CERTIFICATE-----\n".to_vec();
    complete.extend(std::iter::repeat_n(b'A', 512));
    complete.extend_from_slice(b"\n-----END CERTIFICATE-----\n");

    let tight = ParseBudget::default()
        .with_max_pem_body_bytes(64)
        .with_max_input_bytes(64);
    let err = parse_x509_pem_with_budget(&complete, &tight).unwrap_err();
    assert!(matches!(err, nom::Err::Error(PEMError::BudgetExceeded)));

    // the same input parses with the default budget and with an unlimited one
    assert!(parse_x509_pem(&complete).is_ok());
    assert!(parse_x509_pem_with_budget(&complete, &ParseBudget::unlimited()).is_ok());
}

// ---------- DER / CSR / CRL: input budget ----------

#[test]
fn parse_budget_certificate_input_over_limit() {
    let budget = ParseBudget::default().with_max_input_bytes(CERT_DER.len() - 1);
    let err = parse_x509_certificate_with_budget(CERT_DER, &budget).unwrap_err();
    match err {
        nom::Err::Error(X509Error::BudgetExceeded)
        | nom::Err::Failure(X509Error::BudgetExceeded) => {}
        _ => panic!("expected BudgetExceeded"),
    }
}

#[test]
fn parse_budget_csr_input_over_limit() {
    let budget = ParseBudget::default().with_max_input_bytes(CSR_DER.len() - 1);
    let err = parse_x509_csr_with_budget(CSR_DER, &budget).unwrap_err();
    assert!(matches!(
        err,
        nom::Err::Error(X509Error::BudgetExceeded) | nom::Err::Failure(X509Error::BudgetExceeded)
    ));
}

#[test]
fn parse_budget_crl_input_over_limit() {
    let budget = ParseBudget::default().with_max_input_bytes(CRL_DER.len() - 1);
    let err = parse_x509_crl_with_budget(CRL_DER, &budget).unwrap_err();
    assert!(matches!(
        err,
        nom::Err::Error(X509Error::BudgetExceeded) | nom::Err::Failure(X509Error::BudgetExceeded)
    ));
}

#[test]
fn parse_budget_unlimited_der_chain_parses_normally() {
    let unlimited = ParseBudget::unlimited();
    parse_x509_certificate_with_budget(CERT_DER, &unlimited).expect("certificate");
    parse_x509_csr_with_budget(CSR_DER, &unlimited).expect("csr");
    parse_x509_crl_with_budget(CRL_DER, &unlimited).expect("crl");
}

#[test]
fn parse_budget_unlimited_overrides_default_limits_on_every_chain() {
    // A budget larger than the default must not be silently capped by the default budget that
    // the trait entry points apply internally.
    let large =
        ParseBudget::default().with_max_input_bytes(ParseBudget::default().max_input_bytes + 1);
    parse_x509_certificate_with_budget(CERT_DER, &large).expect("certificate");
    parse_x509_csr_with_budget(CSR_DER, &large).expect("csr");
    parse_x509_crl_with_budget(CRL_DER, &large).expect("crl");

    // unlimited keeps working regardless of the default limits on every chain
    let unlimited = ParseBudget::unlimited();
    parse_x509_certificate_with_budget(CERT_DER, &unlimited).expect("certificate");
    parse_x509_csr_with_budget(CSR_DER, &unlimited).expect("csr");
    parse_x509_crl_with_budget(CRL_DER, &unlimited).expect("crl");
}

// ---------- Regression: legal inputs and field access ----------

#[test]
fn parse_budget_legal_multi_block_pem_still_parses() {
    let mut data = Vec::new();
    for seq in 0..3 {
        data.extend_from_slice(&valid_pem_block(seq));
    }
    let blocks: Vec<_> = Pem::iter_from_buffer(&data)
        .collect::<Result<Vec<_>, _>>()
        .expect("all blocks must parse");
    assert_eq!(blocks.len(), 3);
    for (seq, block) in blocks.iter().enumerate() {
        assert_eq!(block.label, format!("CERTIFICATE{seq}"));
        assert_eq!(block.contents, vec![0x00]);
    }
}

#[test]
fn parse_budget_legal_pem_certificate_fields_unchanged() {
    let (rem, pem) = parse_x509_pem(CERT_PEM).expect("pem");
    assert!(rem.is_empty());
    assert_eq!(pem.label, "CERTIFICATE");
    let (rem, cert) = parse_x509_certificate(&pem.contents).expect("cert");
    assert!(rem.is_empty());
    assert_eq!(
        cert.tbs_certificate.version,
        x509_parser::x509::X509Version::V3
    );
    assert!(cert.issuer().to_string().contains("IGC/A"));
}

#[test]
fn parse_budget_legal_der_chain_fields_unchanged() {
    let (rem, cert) = parse_x509_certificate(CERT_DER).expect("cert");
    assert!(rem.is_empty());
    assert_eq!(
        cert.tbs_certificate.version,
        x509_parser::x509::X509Version::V3
    );

    let (rem, csr) = parse_x509_csr(CSR_DER).expect("csr");
    assert!(rem.is_empty());
    assert_eq!(
        csr.certification_request_info.version,
        x509_parser::x509::X509Version(0)
    );

    let (rem, crl) = parse_x509_crl(CRL_DER).expect("crl");
    assert!(rem.is_empty());
    assert!(crl.issuer().to_string().contains("CN=Sample Signer Cert"));
}

#[test]
fn parse_budget_inherent_methods_match_free_functions() {
    let budget = ParseBudget::unlimited();
    let (a, _) = X509CertificationRequest::from_der_with_budget(CSR_DER, &budget).expect("csr");
    let (b, _) = X509CertificationRequest::from_der(CSR_DER).expect("csr");
    assert_eq!(a, b);
}
