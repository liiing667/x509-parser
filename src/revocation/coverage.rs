//! Coverage and revocation status determination for a certificate against CRLs.

use asn1_rs::num_bigint::BigUint;

use crate::certificate::X509Certificate;
use crate::extensions::{
    DistributionPointName, GeneralName, IssuingDistributionPoint, ParsedExtension,
};
use crate::revocation_list::{CertificateRevocationList, RevokedCertificate};
use crate::time::ASN1Time;
use crate::x509::ReasonCode;
use crate::x509::X509Name;

/// Bit position of a [`ReasonCode`] inside the `onlySomeReasons` bit string of an
/// [`IssuingDistributionPoint`] (RFC 5280 section 5.2.5).
///
/// Returns `None` for reason codes that cannot appear in `onlySomeReasons`
/// (`unspecified`, `removeFromCRL`).
fn reason_flag_bit(reason: ReasonCode) -> Option<u32> {
    match reason {
        ReasonCode::Unspecified => None,
        ReasonCode::KeyCompromise => Some(1),
        ReasonCode::CACompromise => Some(2),
        ReasonCode::AffiliationChanged => Some(3),
        ReasonCode::Superseded => Some(4),
        ReasonCode::CessationOfOperation => Some(5),
        ReasonCode::CertificateHold => Some(6),
        ReasonCode::RemoveFromCRL => None,
        ReasonCode::PrivilegeWithdrawn => Some(7),
        ReasonCode::AACompromise => Some(8),
    }
}

/// Compare two X.509 names by their DER content.
///
/// The derived `PartialEq` implementation of [`X509Name`] also compares the byte spans of the
/// underlying [`asn1_rs::Input`], which differ whenever two names are parsed from separate
/// objects. Name equality for revocation purposes is defined by the encoded content instead.
fn names_equal(left: &X509Name<'_>, right: &X509Name<'_>) -> bool {
    left.as_raw() == right.as_raw()
}

/// Compare two CRL entry extension lists semantically.
///
/// Extension equality ignores byte spans and compares the OID, criticality, encoded value and
/// parsed content, so two independently parsed but identical entries compare equal.
fn entry_extensions_equal(
    left: &[crate::extensions::X509Extension<'_>],
    right: &[crate::extensions::X509Extension<'_>],
) -> bool {
    left.len() == right.len()
        && left.iter().zip(right.iter()).all(|(a, b)| {
            a.oid == b.oid && a.critical == b.critical && a.value.as_bytes2() == b.value.as_bytes2()
        })
}

/// Compare two general names semantically (directory names use their DER content).
fn general_names_equal(left: &GeneralName<'_>, right: &GeneralName<'_>) -> bool {
    match (left, right) {
        (GeneralName::DirectoryName(a), GeneralName::DirectoryName(b)) => names_equal(a, b),
        _ => left == right,
    }
}

/// Non-fatal conditions detected while inspecting a CRL or a certificate/CRL pair.
///
/// Warnings do not by themselves invalidate the CRL content, but several of them forbid
/// returning a clean (not revoked) result (see [`RevocationStatus`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum CrlWarning {
    /// The current time (or the evaluation time given to the check) is after `nextUpdate`.
    ///
    /// An expired CRL cannot be treated as an up-to-date revocation set.
    Expired,
    /// The CRL has no `nextUpdate` field, so freshness cannot be asserted.
    NoNextUpdate,
    /// The CRL contains the delta CRL indicator extension: it only carries updates relative to
    /// a base CRL and must not be used as a complete revocation set.
    DeltaCrl,
    /// The CRL contains an unknown extension marked as critical. RFC 5280 requires such an
    /// extension to be recognized before relying on the CRL.
    UnrecognizedCriticalExtension,
    /// A known extension could not be parsed (its content is stored as
    /// [`ParsedExtension::ParseError`]).
    ExtensionParseError,
    /// The CRL scope only contains a subset of revocation reasons, and does not cover all
    /// possible reason codes.
    PartitionedByReason,
}

/// Deterministic conflicts that make a certificate/CRL pair ambiguous or invalid.
///
/// Any conflict prevents a clean (not revoked) conclusion for the checked certificate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum CrlConflict {
    /// The certificate serial number appears more than once in the CRL.
    DuplicateSerial,
    /// The serial appears several times with inconsistent revocation entries (different reason
    /// codes, revocation dates or entry extensions).
    InconsistentEntries,
    /// A `removeFromCRL` entry is present on a complete (non-delta) CRL. RFC 5280 only allows
    /// this reason code in delta CRLs, so the entry cannot be interpreted.
    RemoveFromCrlOutsideDelta,
    /// The CRL is marked as an indirect CRL but an entry for this certificate has no usable
    /// `certificateIssuer` extension and the CRL issuer does not match the certificate issuer.
    IndirectCrlUnknownIssuer,
    /// Two entries for the same serial disagree about whether the certificate is revoked.
    RevocationStateDisagreement,
}

/// Whether a CRL entry for a certificate represents a current revocation or a release.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntryState {
    /// The certificate is currently revoked.
    Revoked,
    /// The certificate was previously on hold and the entry only records the hold
    /// (`certificateHold` reason code).
    OnHold,
    /// A delta CRL entry with `removeFromCRL` releases a previous hold/revocation.
    Removed,
}

/// A matched CRL entry for the checked certificate.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct MatchedEntry<'a> {
    /// The revoked certificate entry from the CRL.
    pub entry: &'a RevokedCertificate<'a>,
    /// Deterministic interpretation of the entry reason.
    pub state: EntryState,
    /// Reason code carried by the entry, if present.
    pub reason: Option<ReasonCode>,
}

impl MatchedEntry<'_> {
    /// Interpret a single CRL entry.
    ///
    /// `removeFromCRL` entries are mapped to [`EntryState::Removed`]; the legality of that
    /// reason code (only delta CRLs may carry it) is checked separately by
    /// [`CrlCoverage::check`].
    pub fn from_entry<'a>(entry: &'a RevokedCertificate<'a>) -> MatchedEntry<'a> {
        let reason = entry.reason_code().map(|(_critical, code)| code);
        let state = match reason {
            Some(ReasonCode::RemoveFromCRL) => EntryState::Removed,
            Some(ReasonCode::CertificateHold) => EntryState::OnHold,
            // every other reason code (including a missing one) is a current revocation
            _ => EntryState::Revoked,
        };
        MatchedEntry {
            entry,
            state,
            reason,
        }
    }
}

/// Scope and metadata extracted from a CRL, used for composable coverage decisions.
///
/// Built once with [`CrlScope::new`], it captures everything that can be determined from a
/// single CRL without looking at a specific certificate:
///
/// - the optional [issuing distribution point](IssuingDistributionPoint) restrictions,
/// - the CRL number and the base CRL number of delta CRLs,
/// - freshness (`thisUpdate` / `nextUpdate`),
/// - unknown critical extensions and malformed known extensions.
#[derive(Clone, Debug)]
pub struct CrlScope<'a> {
    crl: &'a CertificateRevocationList<'a>,
    idp: Option<&'a IssuingDistributionPoint<'a>>,
    crl_number: Option<BigUint>,
    delta_base: Option<BigUint>,
    warnings: Vec<CrlWarning>,
}

impl<'a> CrlScope<'a> {
    /// Extract the scope of a CRL and record the warnings that always apply to it
    /// (delta indicator, unknown critical extensions, freshness).
    pub fn new(crl: &'a CertificateRevocationList<'a>) -> CrlScope<'a> {
        let mut idp = None;
        let mut crl_number = None;
        let mut delta_base = None;
        let mut warnings = Vec::new();

        for ext in crl.extensions() {
            match ext.parsed_extension() {
                ParsedExtension::IssuingDistributionPoint(parsed_idp) => {
                    idp = Some(parsed_idp);
                    if parsed_idp.only_some_reasons.is_some() {
                        warnings.push(CrlWarning::PartitionedByReason);
                    }
                }
                ParsedExtension::CRLNumber(num) => crl_number = Some(num.clone()),
                ParsedExtension::DeltaCRLIndicator(base) => {
                    delta_base = Some(base.clone());
                    warnings.push(CrlWarning::DeltaCrl);
                }
                ParsedExtension::UnsupportedExtension(unsupported) if unsupported.critical => {
                    warnings.push(CrlWarning::UnrecognizedCriticalExtension);
                }
                ParsedExtension::ParseError { .. } => {
                    warnings.push(CrlWarning::ExtensionParseError);
                }
                _ => {}
            }
        }

        if crl.next_update().is_none() {
            warnings.push(CrlWarning::NoNextUpdate);
        }

        CrlScope {
            crl,
            idp,
            crl_number,
            delta_base,
            warnings,
        }
    }

    /// The wrapped CRL.
    #[inline]
    pub fn crl(&self) -> &'a CertificateRevocationList<'a> {
        self.crl
    }

    /// The parsed issuing distribution point, if any.
    #[inline]
    pub fn issuing_distribution_point(&self) -> Option<&'a IssuingDistributionPoint<'a>> {
        self.idp
    }

    /// The CRL number extension value, if present.
    #[inline]
    pub fn crl_number(&self) -> Option<&BigUint> {
        self.crl_number.as_ref()
    }

    /// For a delta CRL, the base CRL number referenced by the delta CRL indicator extension.
    #[inline]
    pub fn delta_base_crl_number(&self) -> Option<&BigUint> {
        self.delta_base.as_ref()
    }

    /// `true` if this CRL carries a delta CRL indicator extension.
    #[inline]
    pub fn is_delta(&self) -> bool {
        self.delta_base.is_some()
    }

    /// Warnings derived from the CRL itself, independent of any checked certificate.
    #[inline]
    pub fn warnings(&self) -> &[CrlWarning] {
        &self.warnings
    }

    /// Evaluate CRL freshness at `at_time`.
    ///
    /// Returns [`CrlWarning::Expired`] when a `nextUpdate` is present and already past, and
    /// [`CrlWarning::NoNextUpdate`] when no `nextUpdate` exists.
    pub fn freshness_at(&self, at_time: ASN1Time) -> Option<CrlWarning> {
        match self.crl.next_update() {
            None => Some(CrlWarning::NoNextUpdate),
            Some(next_update) if at_time > next_update => Some(CrlWarning::Expired),
            Some(_) => None,
        }
    }

    /// Return `true` if the CRL carries an unknown critical extension or a malformed extension.
    ///
    /// Relying parties that do not recognize a critical extension cannot assume the CRL is a
    /// complete revocation set.
    pub fn has_unrecognized_critical_extension(&self) -> bool {
        self.warnings.iter().any(|w| {
            matches!(
                w,
                CrlWarning::UnrecognizedCriticalExtension | CrlWarning::ExtensionParseError
            )
        })
    }

    /// `true` if the IDP restricts the CRL to a reason subset that does not include `reason`.
    ///
    /// When there is no IDP or no `onlySomeReasons` field, every expressible reason is covered.
    /// `removeFromCRL` and `unspecified` are not represented in the bit string: they never
    /// exclude a CRL from coverage by themselves (a `removeFromCRL` entry is additionally
    /// only legal on delta CRLs, checked separately).
    pub fn excludes_reason(&self, reason: ReasonCode) -> bool {
        match reason_flag_bit(reason) {
            None => false,
            Some(bit) => self.idp.is_some_and(|idp| {
                idp.only_some_reasons
                    .as_ref()
                    .is_some_and(|flags| (flags.flags >> bit) & 1 == 0)
            }),
        }
    }

    /// `true` if the IDP scope cannot contain the given certificate.
    ///
    /// The certificate kind is derived from its basic constraints extension
    /// (`CA: true` means a CA certificate).
    pub fn excludes_certificate(&self, cert: &X509Certificate<'_>) -> bool {
        let Some(idp) = self.idp else {
            return false;
        };
        let is_ca = cert
            .tbs_certificate
            .basic_constraints()
            .ok()
            .flatten()
            .is_some_and(|bc| bc.value.ca);
        if idp.only_contains_ca_certs && !is_ca {
            return true;
        }
        if idp.only_contains_user_certs && is_ca {
            return true;
        }
        // attribute certificates are a separate ASN.1 object, never an X509Certificate
        if idp.only_contains_attribute_certs {
            return true;
        }
        false
    }

    /// `true` if the IDP marks this CRL as an indirect CRL.
    #[inline]
    pub fn is_indirect(&self) -> bool {
        self.idp.is_some_and(|idp| idp.indirect_crl)
    }

    /// Check whether a CRL entry applies to `cert` on an indirect CRL.
    ///
    /// On an indirect CRL, entries whose issuer differs from the CRL issuer must carry a
    /// `certificateIssuer` extension. An entry applies when either:
    ///
    /// - it has no `certificateIssuer` and the certificate issuer equals the CRL issuer, or
    /// - its `certificateIssuer` contains a directory name equal to the certificate issuer.
    ///
    /// On direct CRLs every entry is issued by the CRL issuer, so only the issuer equality is
    /// checked.
    pub fn entry_matches_certificate_issuer(
        &self,
        cert: &X509Certificate<'_>,
        entry: &RevokedCertificate<'_>,
    ) -> bool {
        let cert_issuer = cert.tbs_certificate.issuer();
        match entry.certificate_issuer() {
            None => names_equal(cert_issuer, self.crl.issuer()),
            Some(names) => names.iter().any(|name| match name {
                GeneralName::DirectoryName(dn) => names_equal(dn, cert_issuer),
                _ => false,
            }),
        }
    }

    /// Find all entries matching the certificate serial number.
    fn matching_entries(&self, cert: &X509Certificate<'_>) -> Vec<MatchedEntry<'a>> {
        let serial = &cert.tbs_certificate.serial;
        self.crl
            .iter_revoked_certificates()
            .filter(|entry| entry.serial() == serial)
            .map(MatchedEntry::from_entry)
            .collect()
    }

    /// Determine whether a specific reason code is covered for this certificate by the CRL
    /// scope, without looking at the revoked entries.
    ///
    /// This is the composable building block used by [`CrlCoverage`]: it combines the IDP
    /// certificate-kind restrictions and the `onlySomeReasons` reason partition.
    pub fn scope_covers(&self, cert: &X509Certificate<'_>, reason: Option<ReasonCode>) -> bool {
        if self.excludes_certificate(cert) {
            return false;
        }
        if let Some(reason) = reason {
            if self.excludes_reason(reason) {
                return false;
            }
        }
        true
    }

    /// Check whether the issuing distribution point of this CRL is compatible with the
    /// CRL distribution points advertised by the certificate.
    ///
    /// Matching rules follow RFC 5280 section 5.2.5:
    ///
    /// - an IDP without `distributionPoint` only matches when the certificate has no
    ///   distribution point name of its own;
    /// - an IDP `fullName` must contain one of the certificate's distribution point names;
    /// - a `nameRelativeToCRLIssuer` IDP cannot be matched against the current certificate
    ///   extension representation and therefore returns `false`.
    pub fn distribution_points_match(&self, cert: &X509Certificate<'_>) -> bool {
        let Some(idp) = self.idp else {
            return true;
        };
        let Some(idp_name) = &idp.distribution_point else {
            // no distributionPoint component: the CRL only covers certs that do not name a
            // distribution point of their own
            return cert_distribution_point_names(cert).is_empty();
        };
        let cert_names = cert_distribution_point_names(cert);
        match idp_name {
            DistributionPointName::FullName(idp_names) => idp_names.iter().any(|idp_name| {
                cert_names
                    .iter()
                    .any(|cert_name| general_names_equal(cert_name, idp_name))
            }),
            DistributionPointName::NameRelativeToCRLIssuer(_) => false,
        }
    }
}

/// Collect every general name advertised in the certificate CRL distribution points extension.
fn cert_distribution_point_names<'a>(cert: &'a X509Certificate<'a>) -> Vec<&'a GeneralName<'a>> {
    let Ok(Some(ext)) = cert
        .tbs_certificate
        .get_extension_unique(&oid_registry::OID_X509_EXT_CRL_DISTRIBUTION_POINTS)
    else {
        return Vec::new();
    };
    let ParsedExtension::CRLDistributionPoints(points) = ext.parsed_extension() else {
        return Vec::new();
    };
    points
        .iter()
        .filter_map(|point| point.distribution_point.as_ref())
        .filter_map(|name| match name {
            DistributionPointName::FullName(names) => Some(names.iter()),
            DistributionPointName::NameRelativeToCRLIssuer(_) => None,
        })
        .flatten()
        .collect()
}

/// Options controlling a single certificate/CRL coverage check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CrlCoverageOptions {
    /// Time at which freshness and revocation are evaluated. When `None`, no freshness check
    /// is performed and time-based warnings are omitted.
    pub at_time: Option<ASN1Time>,
    /// When `true`, also require the IDP distribution point name to match one of the
    /// certificate's CRL distribution points (RFC 5280 section 5.2.5).
    pub check_distribution_points: bool,
}

impl Default for CrlCoverageOptions {
    fn default() -> Self {
        CrlCoverageOptions {
            at_time: None,
            check_distribution_points: true,
        }
    }
}

/// Deterministic status of a fixed certificate/CRL pair.
#[derive(Clone, Debug)]
pub enum CrlStatus<'a> {
    /// The CRL scope covers the certificate, but the certificate serial is absent.
    ///
    /// Absence only means "not revoked" when the CRL is complete and has no blocking warning;
    /// see [`CrlCoverage::clean`].
    Covered(CrlCoverage<'a>),
    /// The CRL scope does not cover the certificate (IDP kind/reason/distribution-point
    /// mismatch), so its absence from the revoked list proves nothing.
    NotCovered(CrlCoverage<'a>),
    /// The certificate appears in the CRL but the entries are ambiguous or invalid
    /// (duplicate/inconsistent entries, illegal `removeFromCRL`, unresolved indirect issuer).
    Conflict(CrlCoverage<'a>),
}

impl<'a> CrlStatus<'a> {
    /// Return the underlying coverage details regardless of the status kind.
    pub fn coverage(&self) -> &CrlCoverage<'a> {
        match self {
            CrlStatus::Covered(c) | CrlStatus::NotCovered(c) | CrlStatus::Conflict(c) => c,
        }
    }

    /// `true` if the status is [`CrlStatus::Covered`].
    pub fn is_covered(&self) -> bool {
        matches!(self, CrlStatus::Covered(_))
    }

    /// `true` if the status is [`CrlStatus::NotCovered`].
    pub fn is_not_covered(&self) -> bool {
        matches!(self, CrlStatus::NotCovered(_))
    }

    /// `true` if the status is [`CrlStatus::Conflict`].
    pub fn is_conflict(&self) -> bool {
        matches!(self, CrlStatus::Conflict(_))
    }

    /// Consume the status and return the underlying coverage details.
    pub fn into_coverage(self) -> CrlCoverage<'a> {
        match self {
            CrlStatus::Covered(c) | CrlStatus::NotCovered(c) | CrlStatus::Conflict(c) => c,
        }
    }
}

/// Detailed result of checking one certificate against one CRL.
#[derive(Clone, Debug)]
pub struct CrlCoverage<'a> {
    /// The extracted CRL scope used for the check.
    pub scope: CrlScope<'a>,
    /// CRL entries whose serial matches the certificate and that apply to its issuer.
    pub matched: Vec<MatchedEntry<'a>>,
    /// All warnings relevant to this certificate/CRL pair (including CRL-level warnings).
    pub warnings: Vec<CrlWarning>,
    /// All conflicts detected for this certificate/CRL pair.
    pub conflicts: Vec<CrlConflict>,
}

impl<'a> CrlCoverage<'a> {
    /// Check a fixed certificate/CRL pair deterministically.
    ///
    /// The decision is computed as follows:
    ///
    /// 1. scope checks (IDP certificate kind, reason partition, distribution point names) decide
    ///    whether the CRL can contain this certificate at all;
    /// 2. matching entries are collected, resolving indirect-CRL issuer names;
    /// 3. repeated or inconsistent entries and illegal `removeFromCRL` uses produce conflicts;
    /// 4. the pair is classified as covered / not covered / conflict.
    pub fn check(
        scope: CrlScope<'a>,
        cert: &X509Certificate<'_>,
        options: CrlCoverageOptions,
    ) -> CrlStatus<'a> {
        let mut warnings = scope.warnings().to_vec();
        let mut conflicts = Vec::new();

        if let Some(at_time) = options.at_time {
            if let Some(warning) = scope.freshness_at(at_time) {
                warnings.push(warning);
            }
        }

        // certificate-kind restrictions apply regardless of the reason partition
        let kind_applies = !scope.excludes_certificate(cert)
            && (!options.check_distribution_points || scope.distribution_points_match(cert));
        if !kind_applies {
            return CrlStatus::NotCovered(CrlCoverage {
                scope,
                matched: Vec::new(),
                warnings,
                conflicts,
            });
        }

        let all_matches = scope.matching_entries(cert);

        // indirect CRL: keep only entries that provably apply to this certificate issuer
        let matched: Vec<MatchedEntry<'a>> = if scope.is_indirect() {
            let mut applicable = Vec::new();
            for candidate in all_matches {
                if scope.entry_matches_certificate_issuer(cert, candidate.entry) {
                    applicable.push(candidate);
                } else if candidate.entry.certificate_issuer().is_none() {
                    // no certificateIssuer on an indirect CRL and the CRL issuer differs:
                    // the entry cannot be attributed deterministically
                    conflicts.push(CrlConflict::IndirectCrlUnknownIssuer);
                }
            }
            applicable
        } else {
            all_matches
        };

        // A reason-partitioned CRL only answers for reasons inside its partition. A matching
        // entry with an excluded reason cannot exist in a conforming CRL, and absence of the
        // serial proves nothing for reasons outside the partition.
        let reason_outside_partition = scope.idp.is_some_and(|idp| {
            idp.only_some_reasons.is_some()
                && matched.iter().all(|m| match m.reason {
                    None => true,
                    Some(reason) => scope.excludes_reason(reason),
                })
        });
        if reason_outside_partition {
            return CrlStatus::NotCovered(CrlCoverage {
                scope,
                matched,
                warnings,
                conflicts,
            });
        }

        analyze_entries(&scope, &matched, &mut conflicts);

        let coverage = CrlCoverage {
            scope,
            matched,
            warnings,
            conflicts,
        };
        if coverage.conflicts.is_empty() {
            CrlStatus::Covered(coverage)
        } else {
            CrlStatus::Conflict(coverage)
        }
    }

    /// `true` if at least one matched entry currently revokes the certificate.
    pub fn is_revoked(&self) -> bool {
        self.matched
            .iter()
            .any(|m| matches!(m.state, EntryState::Revoked | EntryState::OnHold))
    }

    /// `true` if every matched entry is a `removeFromCRL` release (only possible on deltas).
    pub fn is_released(&self) -> bool {
        !self.matched.is_empty() && self.matched.iter().all(|m| m.state == EntryState::Removed)
    }

    /// Conditions that forbid treating absence from the revoked list as "not revoked".
    fn blocking_warnings(&self) -> impl Iterator<Item = &CrlWarning> {
        self.warnings.iter().filter(|warning| {
            matches!(
                warning,
                CrlWarning::Expired
                    | CrlWarning::NoNextUpdate
                    | CrlWarning::DeltaCrl
                    | CrlWarning::UnrecognizedCriticalExtension
                    | CrlWarning::ExtensionParseError
            )
        })
    }

    /// Return `true` if absence from this CRL can safely be interpreted as "not revoked".
    ///
    /// This requires the certificate to be covered, no conflict, no matched revoking entry, and
    /// no blocking warning (expired CRL, missing `nextUpdate`, delta-only data, unknown critical
    /// extension or extension parse error).
    pub fn clean(&self) -> bool {
        self.conflicts.is_empty() && !self.is_revoked() && self.blocking_warnings().next().is_none()
    }
}

/// Deterministic analysis of the entries matching one certificate serial inside one CRL.
fn analyze_entries(
    scope: &CrlScope<'_>,
    matched: &[MatchedEntry<'_>],
    conflicts: &mut Vec<CrlConflict>,
) {
    if matched.len() > 1 {
        conflicts.push(CrlConflict::DuplicateSerial);
        let first = &matched[0].entry;
        let inconsistent = matched[1..].iter().any(|candidate| {
            candidate.entry.revocation_date != first.revocation_date
                || candidate.entry.reason_code() != first.reason_code()
                || !entry_extensions_equal(candidate.entry.extensions(), first.extensions())
        });
        if inconsistent {
            conflicts.push(CrlConflict::InconsistentEntries);
        }
        let states: Vec<EntryState> = matched.iter().map(|m| m.state).collect();
        let has_revoked = states
            .iter()
            .any(|s| matches!(s, EntryState::Revoked | EntryState::OnHold));
        let has_removed = states.contains(&EntryState::Removed);
        if has_revoked && has_removed {
            conflicts.push(CrlConflict::RevocationStateDisagreement);
        }
    }

    if !scope.is_delta() {
        let illegal_removal = matched
            .iter()
            .any(|m| m.reason == Some(ReasonCode::RemoveFromCRL));
        if illegal_removal {
            conflicts.push(CrlConflict::RemoveFromCrlOutsideDelta);
        }
    }
}

/// Final revocation status for a certificate evaluated against a composed revocation set
/// (one base CRL and zero or more delta CRLs).
#[derive(Clone, Debug)]
pub enum RevocationStatus<'a> {
    /// The certificate is currently revoked; the attached entries explain why.
    Revoked {
        /// Matched entries that establish the revocation.
        entries: Vec<MatchedEntry<'a>>,
        /// All per-CRL coverages used to reach the decision.
        coverages: Vec<CrlCoverage<'a>>,
    },
    /// The revocation set covers the certificate and contains no current revocation.
    ///
    /// This is the only outcome that allows treating the certificate as not revoked.
    Clean {
        /// All per-CRL coverages used to reach the decision.
        coverages: Vec<CrlCoverage<'a>>,
    },
    /// The available CRLs do not form a complete, unambiguous revocation set for this
    /// certificate, so neither revocation nor cleanliness can be asserted.
    ///
    /// The attached coverages carry the precise warnings and conflicts (expired CRL, delta
    /// without a usable base, scope mismatch, unknown critical extension, duplicate serials,
    /// illegal `removeFromCRL`, ...).
    Unknown {
        /// All per-CRL coverages used to reach the decision.
        coverages: Vec<CrlCoverage<'a>>,
    },
}

impl<'a> RevocationStatus<'a> {
    /// `true` for [`RevocationStatus::Revoked`].
    pub fn is_revoked(&self) -> bool {
        matches!(self, RevocationStatus::Revoked { .. })
    }

    /// `true` for [`RevocationStatus::Clean`].
    pub fn is_clean(&self) -> bool {
        matches!(self, RevocationStatus::Clean { .. })
    }

    /// `true` for [`RevocationStatus::Unknown`].
    pub fn is_unknown(&self) -> bool {
        matches!(self, RevocationStatus::Unknown { .. })
    }

    /// Every coverage involved in the decision.
    pub fn coverages(&self) -> &[CrlCoverage<'a>] {
        match self {
            RevocationStatus::Revoked { coverages, .. }
            | RevocationStatus::Clean { coverages }
            | RevocationStatus::Unknown { coverages } => coverages,
        }
    }
}

/// Composable revocation check over one base CRL and optional delta CRLs.
///
/// A delta CRL only contains updates relative to a base CRL, identified by the delta CRL
/// indicator value. The check refuses to draw conclusions when:
///
/// - no base CRL is provided and only delta CRLs are available;
/// - a delta references a base CRL number different from the base CRL number;
/// - any involved CRL is expired, misses `nextUpdate`, has an unknown critical extension or
///   reports entry-level conflicts.
#[derive(Clone, Debug, Default)]
pub struct RevocationCheck<'a> {
    base: Option<CrlScope<'a>>,
    deltas: Vec<CrlScope<'a>>,
    options: CrlCoverageOptions,
}

impl<'a> RevocationCheck<'a> {
    /// Create an empty check.
    pub fn new() -> Self {
        RevocationCheck::default()
    }

    /// Create a check initialized with a complete (base) CRL.
    pub fn with_base_crl(crl: &'a CertificateRevocationList<'a>) -> Self {
        RevocationCheck {
            base: Some(CrlScope::new(crl)),
            deltas: Vec::new(),
            options: CrlCoverageOptions::default(),
        }
    }

    /// Set the evaluation options (time and distribution-point matching behavior).
    pub fn with_options(mut self, options: CrlCoverageOptions) -> Self {
        self.options = options;
        self
    }

    /// Register a complete CRL as the base of the revocation set.
    ///
    /// Prefer [`RevocationCheck::add_delta_crl`] for CRLs carrying the delta CRL indicator
    /// extension; composing a delta CRL as if it were the base always results in
    /// [`RevocationStatus::Unknown`] because it cannot be a complete revocation set.
    pub fn set_base_crl(&mut self, crl: &'a CertificateRevocationList<'a>) -> &mut Self {
        self.base = Some(CrlScope::new(crl));
        self
    }

    /// Register a delta CRL.
    ///
    /// The CRL must carry the delta CRL indicator extension; its compatibility with the base
    /// CRL number is verified during [`RevocationCheck::evaluate`].
    pub fn add_delta_crl(&mut self, crl: &'a CertificateRevocationList<'a>) -> &mut Self {
        self.deltas.push(CrlScope::new(crl));
        self
    }

    /// Number of registered delta CRLs.
    pub fn delta_count(&self) -> usize {
        self.deltas.len()
    }

    /// Evaluate the revocation status of `cert` against the composed revocation set.
    pub fn evaluate(&self, cert: &X509Certificate<'_>) -> RevocationStatus<'a> {
        let mut coverages: Vec<CrlCoverage<'a>> = Vec::new();

        // Evaluate the base CRL, if any.
        if let Some(base_scope) = &self.base {
            let status = CrlCoverage::check(base_scope.clone(), cert, self.options);
            coverages.push(status.into_coverage());
        }

        // Evaluate every delta and verify the delta/base linkage.
        let base_number = self.base.as_ref().and_then(CrlScope::crl_number);
        let mut delta_link_broken = false;
        for delta_scope in &self.deltas {
            if !delta_scope.is_delta() {
                // a complete CRL registered as delta cannot be composed deterministically
                delta_link_broken = true;
            }
            match (delta_scope.delta_base_crl_number(), base_number) {
                (Some(delta_base), Some(base)) if delta_base == base => {}
                (Some(_), Some(_)) => delta_link_broken = true,
                (Some(_), None) => delta_link_broken = true,
                (None, _) => delta_link_broken = true,
            }
            let status = CrlCoverage::check(delta_scope.clone(), cert, self.options);
            coverages.push(status.into_coverage());
        }

        // No base CRL: delta-only or empty data can never be a complete revocation set.
        if self.base.is_none() {
            return RevocationStatus::Unknown { coverages };
        }

        let any_conflict = coverages.iter().any(|c| !c.conflicts.is_empty());
        let any_not_covered = coverages.iter().any(|c| {
            // a scope that does not cover the certificate proves nothing by itself
            c.scope.excludes_certificate(cert)
                || (self.options.check_distribution_points
                    && !c.scope.distribution_points_match(cert))
                || (c
                    .scope
                    .idp
                    .is_some_and(|idp| idp.only_some_reasons.is_some())
                    && c.matched.is_empty())
        });

        // Revocation: base revocations stand unless released by a valid delta; delta
        // revocations add to the set. Releases only cancel certificateHold entries and cannot
        // resurrect a definitively revoked certificate.
        let mut revoking_entries: Vec<MatchedEntry<'a>> = Vec::new();
        for coverage in &coverages {
            for matched in &coverage.matched {
                match matched.state {
                    EntryState::Revoked | EntryState::OnHold => {
                        revoking_entries.push(*matched);
                    }
                    EntryState::Removed => {
                        revoking_entries.retain(|existing| {
                            existing.reason != Some(ReasonCode::CertificateHold)
                                || existing.entry.serial() != matched.entry.serial()
                        });
                    }
                }
            }
        }

        if !revoking_entries.is_empty() {
            return RevocationStatus::Revoked {
                entries: revoking_entries,
                coverages,
            };
        }

        if delta_link_broken || any_conflict || any_not_covered {
            return RevocationStatus::Unknown { coverages };
        }

        // cleanliness requires:
        // - every base CRL to be individually clean (fresh, no blocking extension),
        // - every delta to be clean except for the expected `DeltaCrl` warning (a delta is
        //   never a complete set alone, but composes with the base),
        // - no conflict, scope mismatch or broken linkage.
        let all_clean = coverages.iter().all(|c| {
            c.conflicts.is_empty()
                && !c.is_revoked()
                && c.warnings
                    .iter()
                    .all(|warning| c.scope.is_delta() && *warning == CrlWarning::DeltaCrl)
        });
        if all_clean {
            RevocationStatus::Clean { coverages }
        } else {
            RevocationStatus::Unknown { coverages }
        }
    }
}
