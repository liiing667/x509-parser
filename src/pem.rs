//! Decoding functions for PEM-encoded data
//!
//! A PEM object is a container, which can store (amongst other formats) a public X.509
//! Certificate, or a CRL, etc. It contains only printable characters.
//! PEM-encoded binary data is essentially a beginning and matching end tag that encloses
//! base64-encoded binary data (see:
//! <https://en.wikipedia.org/wiki/Privacy-enhanced_Electronic_Mail>).
//!
//! # Examples
//!
//! To parse a certificate in PEM format, first create the `Pem` object, then decode
//! contents:
//!
//! ```rust,no_run
//! use x509_parser::pem::Pem;
//! use x509_parser::x509::X509Version;
//!
//! static IGCA_PEM: &str = "../assets/IGC_A.pem";
//!
//! # fn main() {
//! let data = std::fs::read(IGCA_PEM).expect("Could not read file");
//! for pem in Pem::iter_from_buffer(&data) {
//!     let pem = pem.expect("Reading next PEM block failed");
//!     let x509 = pem.parse_x509().expect("X.509: decoding DER failed");
//!     assert_eq!(x509.tbs_certificate.version, X509Version::V3);
//! }
//! # }
//! ```
//!
//! This is the most direct method to parse PEM data.
//!
//! Another method to parse the certificate is to use `parse_x509_pem`:
//!
//! ```rust,no_run
//! use x509_parser::pem::parse_x509_pem;
//! use x509_parser::parse_x509_certificate;
//!
//! static IGCA_PEM: &[u8] = include_bytes!("../assets/IGC_A.pem");
//!
//! # fn main() {
//! let res = parse_x509_pem(IGCA_PEM);
//! match res {
//!     Ok((rem, pem)) => {
//!         assert!(rem.is_empty());
//!         //
//!         assert_eq!(pem.label, String::from("CERTIFICATE"));
//!         //
//!         let res_x509 = parse_x509_certificate(&pem.contents);
//!         assert!(res_x509.is_ok());
//!     },
//!     _ => panic!("PEM parsing failed: {:?}", res),
//! }
//! # }
//! ```
//!
//! Note that all methods require to store the `Pem` object in a variable, mainly because decoding
//! the PEM object requires allocation of buffers, and that the lifetime of X.509 certificates will
//! be bound to these buffers.

use crate::budget::ParseBudget;
use crate::certificate::X509Certificate;
use crate::error::{PEMError, X509Error};
use crate::parse_x509_certificate;
use nom::{Err, IResult};
use std::io::{BufRead, Cursor, ErrorKind, Seek};

/// Representation of PEM data
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Pem {
    /// The PEM label
    pub label: String,
    /// The PEM decoded data
    pub contents: Vec<u8>,
}

#[deprecated(since = "0.8.3", note = "please use `parse_x509_pem` instead")]
pub fn pem_to_der(i: &[u8]) -> IResult<&[u8], Pem, PEMError> {
    parse_x509_pem(i)
}

/// Read a PEM-encoded structure using an explicit resource [`ParseBudget`]
///
/// See [`parse_x509_pem`] for the general behavior. This variant rejects an input that exceeds
/// `budget` with [`PEMError::BudgetExceeded`].
pub fn parse_x509_pem_with_budget<'a>(
    i: &'a [u8],
    budget: &ParseBudget,
) -> IResult<&'a [u8], Pem, PEMError> {
    let reader = Cursor::new(i);
    let res = Pem::read_with_budget(reader, budget);
    match res {
        Ok((pem, bytes_read)) => Ok((&i[bytes_read..], pem)),
        Err(e) => Err(Err::Error(e)),
    }
}

/// Read a PEM-encoded structure, and decode the base64 data
///
/// Return a structure describing the PEM object: the enclosing tag, and the data.
/// Allocates a new buffer for the decoded data.
///
/// Note that only the *first* PEM block is decoded. To iterate all blocks from PEM data,
/// use [`Pem::iter_from_buffer`].
///
/// For X.509 (`CERTIFICATE` tag), the data is a certificate, encoded in DER. To parse the
/// certificate content, use `Pem::parse_x509` or `parse_x509_certificate`.
pub fn parse_x509_pem(i: &[u8]) -> IResult<&'_ [u8], Pem, PEMError> {
    parse_x509_pem_with_budget(i, &ParseBudget::default())
}

/// Read one line while enforcing the line-length and total-input limits of `budget`.
///
/// Returns `Ok(None)` on EOF (no byte read). Bytes are copied chunk by chunk, so the
/// accumulated line never grows beyond [`ParseBudget::max_line_length`], even when the
/// underlying reader never returns a line terminator.
///
/// Invalid UTF-8 is reported as an IO error of kind [`ErrorKind::InvalidData`], matching the
/// historical `BufRead::read_line` behavior.
fn read_bounded_line<R: BufRead + ?Sized>(
    r: &mut R,
    budget: &ParseBudget,
    total_read: &mut usize,
) -> Result<Option<String>, PEMError> {
    let mut raw: Vec<u8> = Vec::new();
    loop {
        let available = r.fill_buf()?;
        if available.is_empty() {
            if raw.is_empty() {
                return Ok(None);
            }
            break;
        }
        match available.iter().position(|&b| b == b'\n') {
            Some(pos) => {
                let chunk_len = pos + 1;
                if raw.len().saturating_add(chunk_len) > budget.max_line_length {
                    return Err(PEMError::BudgetExceeded);
                }
                raw.extend_from_slice(&available[..chunk_len]);
                r.consume(chunk_len);
                *total_read = total_read.saturating_add(chunk_len);
                break;
            }
            None => {
                if raw.len().saturating_add(available.len()) > budget.max_line_length {
                    return Err(PEMError::BudgetExceeded);
                }
                raw.extend_from_slice(available);
                let chunk_len = available.len();
                r.consume(chunk_len);
                *total_read = total_read.saturating_add(chunk_len);
            }
        }
        if !budget.allows_input(*total_read) {
            return Err(PEMError::BudgetExceeded);
        }
    }
    if !budget.allows_input(*total_read) {
        return Err(PEMError::BudgetExceeded);
    }
    String::from_utf8(raw).map(Some).map_err(|_| {
        PEMError::IOError(std::io::Error::new(ErrorKind::InvalidData, "invalid UTF-8"))
    })
}

impl Pem {
    /// Read the next PEM-encoded structure, and decode the base64 data
    ///
    /// Returns the certificate (encoded in DER) and the number of bytes read.
    /// Allocates a new buffer for the decoded data.
    ///
    /// Note that a PEM file can contain multiple PEM blocks. This function returns the
    /// *first* decoded object, starting from the current reader position.
    /// To get all objects, call this function repeatedly until `PEMError::MissingHeader`
    /// is returned.
    ///
    /// # Examples
    /// ```
    /// let file = std::fs::File::open("assets/certificate.pem").unwrap();
    /// let subject = x509_parser::pem::Pem::read(std::io::BufReader::new(file))
    ///      .unwrap().0
    ///     .parse_x509().unwrap()
    ///     .tbs_certificate.subject.to_string();
    /// assert_eq!(subject, "CN=lists.for-our.info");
    /// ```
    pub fn read(mut r: impl BufRead + Seek) -> Result<(Pem, usize), PEMError> {
        Self::read_with_budget(&mut r, &ParseBudget::default())
    }

    /// Read the next PEM-encoded structure using an explicit resource [`ParseBudget`]
    ///
    /// This is the budget-aware variant of [`Pem::read`]: lines, the accumulated PEM body and
    /// the total amount of data read are checked against `budget`, and an over-limit input
    /// returns [`PEMError::BudgetExceeded`].
    ///
    /// The PEM framing is also checked strictly: the BEGIN and END lines must be exactly
    /// `-----BEGIN <label>-----` and `-----END <label>-----` (apart from the line terminator),
    /// the labels must match, and a block without a complete END line returns
    /// [`PEMError::IncompletePEM`].
    pub fn read_with_budget(
        mut r: impl BufRead + Seek,
        budget: &ParseBudget,
    ) -> Result<(Pem, usize), PEMError> {
        let start_position = r.stream_position()? as usize;
        let mut total_read: usize = 0;
        let mut line = String::new();
        let label = loop {
            let read_line = match read_bounded_line(&mut r, budget, &mut total_read) {
                Ok(maybe_line) => maybe_line,
                Err(PEMError::IOError(e)) if e.kind() == ErrorKind::InvalidData => {
                    // some tools put invalid UTF-8 data in PEM comment section. Ignore line
                    line.clear();
                    continue;
                }
                Err(e) => return Err(e),
            };
            let Some(next_line) = read_line else {
                // EOF
                return Err(PEMError::MissingHeader);
            };
            line = next_line;
            if !line.starts_with("-----BEGIN ") {
                line.clear();
                continue;
            }
            // strict framing: exactly `-----BEGIN <label>-----` followed by the line ending
            let begin_line = line.trim_end_matches(['\r', '\n']);
            let v: Vec<&str> = begin_line.split("-----").collect();
            if v.len() != 3 || !v[0].is_empty() || !v[2].is_empty() {
                return Err(PEMError::InvalidHeader);
            }
            let label = v[1]
                .strip_prefix("BEGIN ")
                .filter(|label| !label.is_empty())
                .ok_or(PEMError::InvalidHeader)?;
            break label;
        };
        let label = label
            .split('-')
            .next()
            .ok_or(PEMError::InvalidHeader)?
            .to_string();
        let mut s = String::new();
        loop {
            let Some(l) = read_bounded_line(&mut r, budget, &mut total_read)? else {
                return Err(PEMError::IncompletePEM);
            };
            if l.starts_with("-----END ") {
                // strict framing: exactly `-----END <label>-----` followed by the line ending
                let end_line = l.trim_end_matches(['\r', '\n']);
                let end_v: Vec<&str> = end_line.split("-----").collect();
                if end_v.len() != 3 || !end_v[0].is_empty() || !end_v[2].is_empty() {
                    return Err(PEMError::InvalidEndTag);
                }
                let end_label = end_v[1]
                    .strip_prefix("END ")
                    .filter(|label| !label.is_empty())
                    .ok_or(PEMError::InvalidEndTag)?;
                // validate that END label matches BEGIN label
                if end_label != label {
                    return Err(PEMError::InvalidHeader);
                }
                break;
            }
            let body_line = l.trim_end_matches(['\r', '\n']);
            let new_body_len = s.len().saturating_add(body_line.len());
            if !budget.allows_pem_body(new_body_len) {
                return Err(PEMError::BudgetExceeded);
            }
            s.push_str(body_line);
        }

        let contents = data_encoding::BASE64
            .decode(s.as_bytes())
            .or(Err(PEMError::Base64DecodeError))?;
        if !budget.allows_input(contents.len()) {
            return Err(PEMError::BudgetExceeded);
        }
        let pem = Pem { label, contents };
        let end_position = r.stream_position()? as usize;
        let bytes_read = end_position.saturating_sub(start_position);
        Ok((pem, bytes_read))
    }

    /// Decode the PEM contents into a X.509 object
    pub fn parse_x509(&self) -> Result<X509Certificate<'_>, Err<X509Error>> {
        parse_x509_certificate(&self.contents).map(|(_, x509)| x509)
    }

    /// Returns an iterator over the PEM-encapsulated parts of a buffer
    ///
    /// Only the sections enclosed in blocks starting with `-----BEGIN xxx-----`
    /// and ending with `-----END xxx-----` will be considered.
    /// Lines before, between or after such blocks will be ignored.
    ///
    /// The iterator is fallible: `next()` returns a `Result<Pem, PEMError>` object.
    /// An error indicates a block is present but invalid.
    ///
    /// If the buffer does not contain any block, iterator will be empty.
    pub fn iter_from_buffer(i: &[u8]) -> PemIterator<Cursor<&[u8]>> {
        Self::iter_from_buffer_with_budget(i, ParseBudget::default())
    }

    /// Returns an iterator over the PEM-encapsulated parts of a buffer, using an explicit
    /// resource [`ParseBudget`].
    ///
    /// See [`Pem::iter_from_buffer`]. In addition to the per-block limits, the iterator stops
    /// with [`PEMError::BudgetExceeded`] once the number of produced blocks exceeds
    /// [`ParseBudget::max_pem_blocks`].
    pub fn iter_from_buffer_with_budget(
        i: &[u8],
        budget: ParseBudget,
    ) -> PemIterator<Cursor<&[u8]>> {
        let reader = Cursor::new(i);
        PemIterator {
            reader,
            budget,
            blocks_seen: 0,
            failed: false,
        }
    }

    /// Returns an iterator over the PEM-encapsulated parts of a reader
    ///
    /// Only the sections enclosed in blocks starting with `-----BEGIN xxx-----`
    /// and ending with `-----END xxx-----` will be considered.
    /// Lines before, between or after such blocks will be ignored.
    ///
    /// The iterator is fallible: `next()` returns a `Result<Pem, PEMError>` object.
    /// An error indicates a block is present but invalid.
    ///
    /// If the reader does not contain any block, iterator will be empty.
    pub fn iter_from_reader<R: BufRead + Seek>(reader: R) -> PemIterator<R> {
        Self::iter_from_reader_with_budget(reader, ParseBudget::default())
    }

    /// Returns an iterator over the PEM-encapsulated parts of a reader, using an explicit
    /// resource [`ParseBudget`].
    ///
    /// See [`Pem::iter_from_reader`]. In addition to the per-block limits, the iterator stops
    /// with [`PEMError::BudgetExceeded`] once the number of produced blocks exceeds
    /// [`ParseBudget::max_pem_blocks`].
    pub fn iter_from_reader_with_budget<R: BufRead + Seek>(
        reader: R,
        budget: ParseBudget,
    ) -> PemIterator<R> {
        PemIterator {
            reader,
            budget,
            blocks_seen: 0,
            failed: false,
        }
    }
}

/// Iterator over PEM-encapsulated blocks
///
/// Only the sections enclosed in blocks starting with `-----BEGIN xxx-----`
/// and ending with `-----END xxx-----` will be considered.
/// Lines before, between or after such blocks will be ignored.
///
/// The iterator is fallible: `next()` returns a `Result<Pem, PEMError>` object.
/// An error indicates a block is present but invalid.
///
/// If the buffer does not contain any block, iterator will be empty.
#[allow(missing_debug_implementations)]
pub struct PemIterator<Reader: BufRead + Seek> {
    reader: Reader,
    budget: ParseBudget,
    blocks_seen: usize,
    failed: bool,
}

impl<R: BufRead + Seek> Iterator for PemIterator<R> {
    type Item = Result<Pem, PEMError>;

    fn next(&mut self) -> Option<Self::Item> {
        // stop permanently after the first hard error so a non-EOF error cannot loop forever
        if self.failed {
            return None;
        }
        if let Ok(&[]) = self.reader.fill_buf() {
            return None;
        }
        let r = Pem::read_with_budget(self.reader.by_ref(), &self.budget).map(|(pem, _)| pem);
        match r {
            Err(PEMError::MissingHeader) => None,
            Err(e) => {
                self.failed = true;
                Some(Err(e))
            }
            Ok(pem) => {
                self.blocks_seen = self.blocks_seen.saturating_add(1);
                if !self.budget.allows_pem_blocks(self.blocks_seen) {
                    self.failed = true;
                    return Some(Err(PEMError::BudgetExceeded));
                }
                Some(Ok(pem))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_pem_from_file() {
        let file = std::io::BufReader::new(std::fs::File::open("assets/certificate.pem").unwrap());
        let subject = Pem::read(file)
            .unwrap()
            .0
            .parse_x509()
            .unwrap()
            .tbs_certificate
            .subject
            .to_string();
        assert_eq!(subject, "CN=lists.for-our.info");
    }

    #[test]
    fn pem_multi_word_label() {
        const PEM_BYTES: &[u8] =
            b"-----BEGIN MULTI WORD LABEL-----\n-----END MULTI WORD LABEL-----";
        let (_, pem) = parse_x509_pem(PEM_BYTES).expect("should parse pem");
        assert_eq!(pem.label, "MULTI WORD LABEL");
    }

    #[test]
    fn pem_invalid_utf8_in_comment_is_skipped() {
        // Build PEM data with an invalid UTF-8 line before the BEGIN header.
        // The parser should skip the invalid line and still parse the PEM block.
        let mut data: Vec<u8> = Vec::new();
        // A comment line with invalid UTF-8 bytes (0xFF is never valid in UTF-8)
        data.extend_from_slice(b"# comment \xff\xff\n");
        data.extend_from_slice(b"-----BEGIN CERTIFICATE-----\n");
        // Minimal base64 content (one byte: 0x00)
        data.extend_from_slice(b"AA==\n");
        data.extend_from_slice(b"-----END CERTIFICATE-----\n");

        let cursor = Cursor::new(data.as_slice());
        let (pem, _) = Pem::read(cursor).expect("should skip invalid UTF-8 and parse PEM");
        assert_eq!(pem.label, "CERTIFICATE");
        assert_eq!(pem.contents, vec![0x00]);
    }

    #[test]
    fn pem_mismatched_end_label_returns_error() {
        // A PEM block where the END label does not match the BEGIN label should
        // be rejected with an InvalidHeader error.
        const PEM_BYTES: &[u8] = b"-----BEGIN CERTIFICATE-----\nAA==\n-----END PRIVATE KEY-----\n";
        let cursor = Cursor::new(PEM_BYTES);
        let result = Pem::read(cursor);
        assert!(result.is_err(), "mismatched END label should return error");
        let err = result.unwrap_err();
        assert!(
            matches!(err, PEMError::InvalidHeader),
            "expected InvalidHeader, got: {:?}",
            err
        );
    }
}
