//! Composable revocation coverage determination based on Certificate Revocation Lists.
//!
//! Parsing a CRL only gives the raw content of a single revocation list. Deciding whether a
//! certificate can be considered *not revoked* requires answering several additional questions:
//!
//! - does the CRL scope ([`IssuingDistributionPoint`]) actually cover this kind of certificate
//!   and this revocation reason?
//! - is the CRL fresh, or has it passed its `nextUpdate`?
//! - is it a delta CRL that can only be used together with a matching base CRL?
//! - does it carry an unknown *critical* extension that must not be ignored?
//! - do repeated entries, `removeFromCRL` reason codes or indirect-CRL issuer names produce an
//!   ambiguous result?
//!
//! This module provides composable building blocks to answer these questions:
//!
//! - [`CrlScope`] describes the scope and metadata extracted from a single CRL.
//! - [`CrlCoverage::check`] classifies a fixed certificate/CRL pair as
//!   [`Covered`](CrlStatus::Covered), [`NotCovered`](CrlStatus::NotCovered) or
//!   [`Conflict`](CrlStatus::Conflict), together with [`CrlWarning`]s and
//!   [`CrlConflict`]s explaining the decision.
//! - [`RevocationCheck`] combines a base CRL and optional delta CRLs into a single
//!   [`RevocationStatus`], so a clean result is only returned when the revocation set is
//!   complete and unambiguous.
//!
//! All decisions are deterministic: the same certificate/CRL inputs always produce the same
//! status, including for repeated serial numbers, `removeFromCRL` entries and indirect CRLs.
//!
//! [RFC 5280]: https://tools.ietf.org/html/rfc5280

mod coverage;

pub use coverage::*;
