use crate::error::X509Error;
use crate::prelude::format_serial;
use crate::x509::X509Name;
use asn1_rs::{Any, DerParser, DynTagged, Header, InnerError, Input, Oid, Tag};
use nom::{Err, IResult, Input as _};
use std::fmt;

/// GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
pub type GeneralNames<'a> = Vec<GeneralName<'a>>;

/// Represents a GeneralName as defined in RFC5280. There
/// is no support X.400 addresses and EDIPartyName.
///
/// String formats are not validated (except for valid UTF-8).
///
/// <pre>
/// -- Note: IMPLICIT Tags
/// GeneralName ::= CHOICE {
///     otherName                 [0]  AnotherName,
///     rfc822Name                [1]  IA5String,
///     dNSName                   [2]  IA5String,
///     x400Address               [3]  ORAddress,
///     directoryName             [4]  Name,
///     ediPartyName              [5]  EDIPartyName,
///     uniformResourceIdentifier [6]  IA5String,
///     iPAddress                 [7]  OCTET STRING,
///     registeredID              [8]  OBJECT IDENTIFIER }
/// </pre>
#[derive(Clone, Debug, PartialEq)]
pub enum GeneralName<'a> {
    OtherName(Oid<'a>, Any<'a>),
    /// More or less an e-mail, the format is not checked.
    RFC822Name(&'a str),
    /// A hostname, format is not checked.
    DNSName(&'a str),
    /// X400Address,
    X400Address(Any<'a>),
    /// RFC5280 defines several string types, we always try to parse as utf-8
    /// which is more or less a superset of the string types.
    DirectoryName(X509Name<'a>),
    /// EDIPartyName
    EDIPartyName(Any<'a>),
    /// An uniform resource identifier. The format is not checked.
    URI(&'a str),
    /// An ip address, provided as encoded.
    IPAddress(&'a [u8]),
    RegisteredID(Oid<'a>),
    /// Invalid data (for ex. invalid UTF-8 data in DNSName entry)
    Invalid(Any<'a>),
}

impl DynTagged for GeneralName<'_> {
    fn constructed(&self) -> bool {
        matches!(
            self,
            GeneralName::OtherName(_, _)
                | GeneralName::X400Address(_)
                | GeneralName::DirectoryName(_)
                | GeneralName::EDIPartyName(_)
        )
    }

    fn tag(&self) -> Tag {
        match self {
            GeneralName::OtherName(_, _) => Tag(0),
            GeneralName::RFC822Name(_) => Tag(1),
            GeneralName::DNSName(_) => Tag(2),
            GeneralName::X400Address(_) => Tag(3),
            GeneralName::DirectoryName(_) => Tag(4),
            GeneralName::EDIPartyName(_) => Tag(5),
            GeneralName::URI(_) => Tag(6),
            GeneralName::IPAddress(_) => Tag(7),
            GeneralName::RegisteredID(_) => Tag(8),
            GeneralName::Invalid(any) => any.tag(),
        }
    }

    fn accept_tag(tag: Tag) -> bool {
        (0..9).contains(&tag.0)
    }
}

impl<'a> DerParser<'a> for GeneralName<'a> {
    type Error = X509Error;

    fn from_der_content(
        header: &'_ Header<'a>,
        input: Input<'a>,
    ) -> IResult<Input<'a>, Self, Self::Error> {
        let (rem, gn) = match header.tag().0 {
            0 => {
                // AnotherName ::= SEQUENCE {
                //     type-id    OBJECT IDENTIFIER,
                //     value      [0] EXPLICIT ANY DEFINED BY type-id }
                let (rem, (type_id, value)) =
                    <(Oid, Any)>::from_der_content(header, input).map_err(Err::convert)?;
                (rem, GeneralName::OtherName(type_id, value))
            }
            1 => {
                let (rem, s) = ia5str_relaxed(input)?;
                (rem, GeneralName::RFC822Name(s))
            }
            2 => {
                let (rem, s) = ia5str_relaxed(input)?;
                (rem, GeneralName::DNSName(s))
            }
            3 => {
                // XXX Not yet implemented
                let rem = input.take_from(input.input_len());
                let any = Any::new(header.clone(), input);
                (rem, GeneralName::X400Address(any))
            }
            4 => {
                // Field is 'IMPLICIT [4] Name', but name is a CHOICE { RDNSequence }
                // so tags are EXPLICIT
                let (rem, name) = X509Name::parse_der(input)?;
                (rem, GeneralName::DirectoryName(name))
            }
            5 => {
                // Deep parsing not yet implemented, so just read Any
                let rem = input.take_from(input.input_len());
                let any = Any::new(header.clone(), input);
                (rem, GeneralName::EDIPartyName(any))
            }
            6 => {
                let (rem, s) = ia5str_relaxed(input)?;
                (rem, GeneralName::URI(s))
            }
            7 => {
                let (rem, b) = <&[u8]>::from_der_content(header, input).map_err(Err::convert)?;
                (rem, GeneralName::IPAddress(b))
            }
            8 => {
                let (rem, oid) = Oid::from_der_content(header, input).map_err(Err::convert)?;
                (rem, GeneralName::RegisteredID(oid))
            }
            _ => {
                let rem = input.take_from(input.input_len());
                let any = Any::new(header.clone(), input);
                (rem, GeneralName::Invalid(any))
            }
        };
        Ok((rem, gn))
    }
}

impl fmt::Display for GeneralName<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GeneralName::OtherName(oid, _) => write!(f, "OtherName({oid}, [...])"),
            GeneralName::RFC822Name(s) => write!(f, "RFC822Name({s})"),
            GeneralName::DNSName(s) => write!(f, "DNSName({s})"),
            GeneralName::X400Address(_) => write!(f, "X400Address(<unparsed>)"),
            GeneralName::DirectoryName(dn) => write!(f, "DirectoryName({dn})"),
            GeneralName::EDIPartyName(_) => write!(f, "EDIPartyName(<unparsed>)"),
            GeneralName::URI(s) => write!(f, "URI({s})"),
            GeneralName::IPAddress(b) => write!(f, "IPAddress({})", format_serial(b)),
            GeneralName::RegisteredID(oid) => write!(f, "RegisteredID({oid})"),
            GeneralName::Invalid(any) => {
                write!(
                    f,
                    "Invalid(tag={}, data={})",
                    any.tag(),
                    format_serial(any.data.as_bytes2())
                )
            }
        }
    }
}

/// Canonical identity of a [`GeneralName`], for security comparisons only.
///
/// Different accessors interpret the same `GeneralName` differently (URI
/// scheme/host casing and percent-encoding, e-mail case, DNS trailing dot,
/// IP address length), so certificate matching and name constraints may
/// observe different subjects for the same raw value. This owned,
/// normalized form collapses those ambiguities so that values can be
/// compared with `==` (or used as hash/ordered keys) across code paths.
///
/// The canonical form is derived with the following rules:
///
/// - `RFC822Name`: the domain part (after the last `@`) is lowercased; the
///   local part is kept verbatim. Names without `@` are treated as a domain.
/// - `DNSName`: lowercased, with a single trailing root dot removed.
/// - `URI`: scheme and host are lowercased, a single trailing dot is removed
///   from the host, percent-encoded unreserved characters are decoded and
///   remaining percent triplets are uppercased. The rest of the URI is kept
///   verbatim.
/// - `IPAddress`: must be 4 (IPv4) or 16 (IPv6) bytes.
/// - `DirectoryName`/`X400Address`/`EDIPartyName`/`OtherName`: compared on
///   their raw DER content.
///
/// Ambiguous or invalid encodings fail closed: [`GeneralName::canonical_identity`]
/// returns an error instead of guessing a canonical form.
///
/// The raw [`GeneralName`] is never modified; field accessors keep returning
/// the certificate content exactly as encoded.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum CanonicalGeneralName {
    /// `(type-id OID, raw DER content of value)`
    OtherName(String, Vec<u8>),
    /// Local part verbatim + `@` + lowercased domain, or lowercased domain only
    RFC822Name(String),
    /// Lowercased, trailing root dot removed
    DNSName(String),
    /// Raw DER content
    X400Address(Vec<u8>),
    /// Raw DER encoding of the `Name`
    DirectoryName(Vec<u8>),
    /// Raw DER content
    EDIPartyName(Vec<u8>),
    /// Normalized URI (see type-level documentation)
    Uri(String),
    /// 4 (IPv4) or 16 (IPv6) bytes
    IPAddress(Vec<u8>),
    /// OID in string form
    RegisteredID(String),
}

impl GeneralName<'_> {
    /// Compute the canonical identity of this name, for security comparisons.
    ///
    /// Returns `Err(X509Error::InvalidGeneralName)` when the encoding is
    /// ambiguous or invalid (e.g. malformed percent-encoding in a URI, an IP
    /// address that is neither 4 nor 16 bytes, an empty DNS name, or an
    /// [`GeneralName::Invalid`] entry), so callers fail closed.
    pub fn canonical_identity(&self) -> Result<CanonicalGeneralName, X509Error> {
        match self {
            GeneralName::OtherName(oid, any) => Ok(CanonicalGeneralName::OtherName(
                oid.to_string(),
                any.data.as_bytes2().to_vec(),
            )),
            GeneralName::RFC822Name(s) => canonicalize_email(s),
            GeneralName::DNSName(s) => canonicalize_dns(s),
            GeneralName::X400Address(any) => Ok(CanonicalGeneralName::X400Address(
                any.data.as_bytes2().to_vec(),
            )),
            GeneralName::DirectoryName(name) => {
                Ok(CanonicalGeneralName::DirectoryName(name.as_raw().to_vec()))
            }
            GeneralName::EDIPartyName(any) => Ok(CanonicalGeneralName::EDIPartyName(
                any.data.as_bytes2().to_vec(),
            )),
            GeneralName::URI(s) => canonicalize_uri(s),
            GeneralName::IPAddress(b) => match b.len() {
                4 | 16 => Ok(CanonicalGeneralName::IPAddress(b.to_vec())),
                _ => Err(X509Error::InvalidGeneralName),
            },
            GeneralName::RegisteredID(oid) => {
                Ok(CanonicalGeneralName::RegisteredID(oid.to_string()))
            }
            GeneralName::Invalid(_) => Err(X509Error::InvalidGeneralName),
        }
    }
}

impl fmt::Display for CanonicalGeneralName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CanonicalGeneralName::OtherName(oid, _) => write!(f, "OtherName({oid}, [...])"),
            CanonicalGeneralName::RFC822Name(s) => write!(f, "RFC822Name({s})"),
            CanonicalGeneralName::DNSName(s) => write!(f, "DNSName({s})"),
            CanonicalGeneralName::X400Address(_) => write!(f, "X400Address(<unparsed>)"),
            CanonicalGeneralName::DirectoryName(b) => {
                write!(f, "DirectoryName({})", format_serial(b))
            }
            CanonicalGeneralName::EDIPartyName(_) => write!(f, "EDIPartyName(<unparsed>)"),
            CanonicalGeneralName::Uri(s) => write!(f, "URI({s})"),
            CanonicalGeneralName::IPAddress(b) => write!(f, "IPAddress({})", format_serial(b)),
            CanonicalGeneralName::RegisteredID(oid) => write!(f, "RegisteredID({oid})"),
        }
    }
}

fn canonicalize_email(s: &str) -> Result<CanonicalGeneralName, X509Error> {
    // The domain part is case-insensitive; the local part is kept verbatim
    // (it is case-sensitive per RFC 5321, so folding it could wrongly match).
    match s.rfind('@') {
        Some(i) => {
            let domain = s[i + 1..].to_ascii_lowercase();
            Ok(CanonicalGeneralName::RFC822Name(format!(
                "{}@{domain}",
                &s[..i]
            )))
        }
        // name constraints allow a bare host/domain as rfc822Name
        None => Ok(CanonicalGeneralName::RFC822Name(s.to_ascii_lowercase())),
    }
}

fn canonicalize_dns(s: &str) -> Result<CanonicalGeneralName, X509Error> {
    let lower = s.to_ascii_lowercase();
    let name = lower.strip_suffix('.').unwrap_or(&lower);
    if name.is_empty() {
        return Err(X509Error::InvalidGeneralName);
    }
    Ok(CanonicalGeneralName::DNSName(name.to_string()))
}

fn canonicalize_uri(uri: &str) -> Result<CanonicalGeneralName, X509Error> {
    validate_pct_encoding(uri)?;
    let normalized = normalize_pct_encoding(uri);
    let scheme_end = normalized.find(':').ok_or(X509Error::InvalidGeneralName)?;
    let scheme = &normalized[..scheme_end];
    let mut scheme_chars = scheme.chars();
    match scheme_chars.next() {
        Some(c) if c.is_ascii_alphabetic() => {}
        _ => return Err(X509Error::InvalidGeneralName),
    }
    if !scheme_chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.')) {
        return Err(X509Error::InvalidGeneralName);
    }
    let scheme = scheme.to_ascii_lowercase();
    let rest = &normalized[scheme_end + 1..];
    let Some(after_slashes) = rest.strip_prefix("//") else {
        // no authority component (e.g. "mailto:user@example.com")
        return Ok(CanonicalGeneralName::Uri(format!("{scheme}:{rest}")));
    };
    let auth_end = after_slashes
        .find(['/', '?', '#'])
        .unwrap_or(after_slashes.len());
    let authority = &after_slashes[..auth_end];
    let tail = &after_slashes[auth_end..];
    let (userinfo, hostport) = match authority.rfind('@') {
        Some(i) => (&authority[..i + 1], &authority[i + 1..]),
        None => ("", authority),
    };
    let (host, port) = split_host_port(hostport)?;
    Ok(CanonicalGeneralName::Uri(format!(
        "{scheme}://{userinfo}{host}{port}{tail}"
    )))
}

/// Split an authority host:port part, returning the canonical host and the
/// port (including the leading ':'), or an error on ambiguous encodings.
fn split_host_port(hostport: &str) -> Result<(String, &str), X509Error> {
    if let Some(rest) = hostport.strip_prefix('[') {
        // IPv6 (or IPvFuture) literal
        let end = rest.find(']').ok_or(X509Error::InvalidGeneralName)?;
        let host = rest[..end].to_ascii_lowercase();
        let after = &rest[end + 1..];
        let port = validate_port(after)?;
        Ok((format!("[{host}]"), port))
    } else {
        let (host, port) = match hostport.rfind(':') {
            Some(i) => (&hostport[..i], validate_port(&hostport[i..])?),
            None => (hostport, ""),
        };
        let host = host.to_ascii_lowercase();
        let host = host.strip_suffix('.').unwrap_or(&host);
        Ok((host.to_string(), port))
    }
}

/// Validate a port suffix: must be empty or `:` followed by digits only.
fn validate_port(s: &str) -> Result<&str, X509Error> {
    if s.is_empty() {
        return Ok("");
    }
    let digits = s.strip_prefix(':').ok_or(X509Error::InvalidGeneralName)?;
    if !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(X509Error::InvalidGeneralName);
    }
    Ok(s)
}

/// Every '%' must be followed by exactly two hex digits, otherwise the
/// encoding is ambiguous and we fail closed.
fn validate_pct_encoding(s: &str) -> Result<(), X509Error> {
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            if i + 2 >= b.len() || !b[i + 1].is_ascii_hexdigit() || !b[i + 2].is_ascii_hexdigit() {
                return Err(X509Error::InvalidGeneralName);
            }
            i += 3;
        } else {
            i += 1;
        }
    }
    Ok(())
}

/// Decode percent-encoded unreserved characters (RFC 3986 §2.3) and
/// uppercase the hex digits of the remaining triplets. The input must have
/// been validated with [`validate_pct_encoding`] first.
fn normalize_pct_encoding(s: &str) -> String {
    fn hex_val(c: char) -> u8 {
        c.to_digit(16).expect("validated hex digit") as u8
    }
    fn is_unreserved(b: u8) -> bool {
        b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~')
    }
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '%' {
            // validated above: two hex digits always follow
            let hi = chars.next().expect("validated percent-encoding");
            let lo = chars.next().expect("validated percent-encoding");
            let value = hex_val(hi) * 16 + hex_val(lo);
            if is_unreserved(value) {
                out.push(value as char);
            } else {
                out.push('%');
                out.push(hi.to_ascii_uppercase());
                out.push(lo.to_ascii_uppercase());
            }
        } else {
            out.push(c);
        }
    }
    out
}

fn ia5str_relaxed(input: Input<'_>) -> Result<(Input<'_>, &str), Err<X509Error>> {
    let (rem, input) = input.take_split(input.input_len());
    // Relax constraints from RFC here: we are expecting an IA5String, but many certificates
    // are using unicode characters
    let s = std::str::from_utf8(input.as_bytes2())
        .map_err(|_| Err::Failure(X509Error::DerParser(InnerError::StringInvalidCharset)))?;
    Ok((rem, s))
}
