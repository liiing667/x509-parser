"""Generate deterministic CRL/certificate assets for the revocation coverage tests.

The assets exercise the scope and conflict rules implemented in
`src/revocation/coverage.rs`: delta CRL linkage, reason partitioning, indirect CRLs,
duplicate serial numbers, removeFromCRL and unknown critical extensions.
"""

import datetime
import os.path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import (
    DistributionPoint,
    ReasonFlags,
    UniformResourceIdentifier,
)
from cryptography.x509.oid import (
    CRLEntryExtensionOID,
    ExtensionOID,
    NameOID,
)

HERE = os.path.dirname(__file__)

# fixed reference time (the assets use fixed validity windows around it)
NOW = datetime.datetime(2026, 1, 1, 0, 0, 0, tzinfo=datetime.timezone.utc)
PAST = NOW - datetime.timedelta(days=10)
FUTURE = NOW + datetime.timedelta(days=10)

# serial numbers used in the fixtures
SERIAL_REVOKED_KEY_COMPROMISE = 0x1111
SERIAL_REVOKED_CESSATION = 0x2222
SERIAL_HOLD = 0x3333
SERIAL_CLEAN = 0x4444
SERIAL_DUPLICATE = 0x5555
SERIAL_INDIRECT = 0x6666

# private OID arc for "unknown" critical extensions in tests
OID_UNKNOWN_CRITICAL = x509.ObjectIdentifier("1.3.6.1.4.1.99999.42.1")


def write_der(name, data):
    with open(os.path.join(HERE, name), "wb") as f:
        f.write(data)


def make_ca(cn, is_ca):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(PAST)
        .not_valid_after(FUTURE + datetime.timedelta(days=365))
    )
    if is_ca:
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True
        )
    else:
        builder = builder.add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True
        )
    cert = builder.sign(key, hashes.SHA256())
    return key, cert


def make_ee_cert(issuer_cert, issuer_key, serial, cn, dp_uri=None):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_cert.subject)
        .public_key(key.public_key())
        .serial_number(serial)
        .not_valid_before(PAST)
        .not_valid_after(FUTURE + datetime.timedelta(days=30))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True
        )
    )
    if dp_uri is not None:
        builder = builder.add_extension(
            x509.CRLDistributionPoints(
                [
                    DistributionPoint(
                        full_name=[UniformResourceIdentifier(dp_uri)],
                        relative_name=None,
                        reasons=None,
                        crl_issuer=None,
                    )
                ]
            ),
            critical=False,
        )
    return builder.sign(issuer_key, hashes.SHA256())


def revoked_builder(serial, reason, revocation_date=PAST):
    return (
        x509.RevokedCertificateBuilder()
        .serial_number(serial)
        .revocation_date(revocation_date)
        .add_extension(x509.CRLReason(reason), critical=False)
    )


def base_crl_builder(issuer_cert, crl_number, last_update, next_update):
    return (
        x509.CertificateRevocationListBuilder()
        .issuer_name(issuer_cert.subject)
        .last_update(last_update)
        .next_update(next_update)
        .add_extension(x509.CRLNumber(crl_number), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                issuer_cert.public_key()
            ),
            critical=False,
        )
    )


def main():
    ca_key, ca_cert = make_ca("Coverage Test CA", True)
    write_der("ca.der", ca_cert.public_bytes(serialization.Encoding.DER))

    # end-entity certificates, one clean and one revoked serial
    clean_cert = make_ee_cert(
        ca_cert, ca_key, SERIAL_CLEAN, "clean ee", dp_uri="http://example.com/ca.crl"
    )
    write_der(
        "cert_clean.der", clean_cert.public_bytes(serialization.Encoding.DER)
    )
    revoked_cert = make_ee_cert(
        ca_cert, ca_key, SERIAL_REVOKED_KEY_COMPROMISE, "revoked ee"
    )
    write_der(
        "cert_revoked.der",
        revoked_cert.public_bytes(serialization.Encoding.DER),
    )
    hold_cert = make_ee_cert(ca_cert, ca_key, SERIAL_HOLD, "hold ee")
    write_der(
        "cert_hold.der", hold_cert.public_bytes(serialization.Encoding.DER)
    )
    duplicate_cert = make_ee_cert(
        ca_cert, ca_key, SERIAL_DUPLICATE, "duplicate serial ee"
    )
    write_der(
        "cert_duplicate.der",
        duplicate_cert.public_bytes(serialization.Encoding.DER),
    )

    # 1. regular, fresh full CRL: one keyCompromise and one cessationOfOperation
    crl = (
        base_crl_builder(ca_cert, 100, PAST, FUTURE)
        .add_revoked_certificate(
            revoked_builder(
                SERIAL_REVOKED_KEY_COMPROMISE, ReasonFlags.key_compromise
            ).build()
        )
        .add_revoked_certificate(
            revoked_builder(
                SERIAL_REVOKED_CESSATION,
                ReasonFlags.cessation_of_operation,
            ).build()
        )
        .sign(ca_key, hashes.SHA256())
    )
    write_der("full_fresh.der", crl.public_bytes(serialization.Encoding.DER))

    # 2. same content but already expired (nextUpdate in the past)
    crl = (
        base_crl_builder(
            ca_cert, 100, PAST - datetime.timedelta(days=30), PAST
        )
        .add_revoked_certificate(
            revoked_builder(
                SERIAL_REVOKED_KEY_COMPROMISE, ReasonFlags.key_compromise
            ).build()
        )
        .sign(ca_key, hashes.SHA256())
    )
    write_der("full_expired.der", crl.public_bytes(serialization.Encoding.DER))

    # 3. delta CRL based on CRL number 100: adds a hold entry and a duplicate-free update
    crl = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca_cert.subject)
        .last_update(PAST)
        .next_update(FUTURE)
        .add_extension(x509.CRLNumber(101), critical=False)
        .add_extension(x509.DeltaCRLIndicator(100), critical=True)
        .add_revoked_certificate(
            revoked_builder(SERIAL_HOLD, ReasonFlags.certificate_hold).build()
        )
        .sign(ca_key, hashes.SHA256())
    )
    write_der("delta_101.der", crl.public_bytes(serialization.Encoding.DER))

    # 4. delta CRL referencing a non-matching base number
    crl = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(ca_cert.subject)
        .last_update(PAST)
        .next_update(FUTURE)
        .add_extension(x509.CRLNumber(102), critical=False)
        .add_extension(x509.DeltaCRLIndicator(999), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    write_der("delta_wrong_base.der", crl.public_bytes(serialization.Encoding.DER))

    # 5. full CRL partitioned by reasons (only keyCompromise)
    idp = x509.IssuingDistributionPoint(
        full_name=None,
        relative_name=None,
        only_contains_user_certs=False,
        only_contains_ca_certs=False,
        only_some_reasons=frozenset([ReasonFlags.key_compromise]),
        indirect_crl=False,
        only_contains_attribute_certs=False,
    )
    crl = (
        base_crl_builder(ca_cert, 200, PAST, FUTURE)
        .add_extension(idp, critical=True)
        .add_revoked_certificate(
            revoked_builder(
                SERIAL_REVOKED_KEY_COMPROMISE, ReasonFlags.key_compromise
            ).build()
        )
        .sign(ca_key, hashes.SHA256())
    )
    write_der("only_reasons.der", crl.public_bytes(serialization.Encoding.DER))

    # 6. full CRL restricted to CA certificates
    idp = x509.IssuingDistributionPoint(
        full_name=None,
        relative_name=None,
        only_contains_user_certs=False,
        only_contains_ca_certs=True,
        only_some_reasons=None,
        indirect_crl=False,
        only_contains_attribute_certs=False,
    )
    crl = (
        base_crl_builder(ca_cert, 300, PAST, FUTURE)
        .add_extension(idp, critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    write_der("only_ca.der", crl.public_bytes(serialization.Encoding.DER))

    # 7. CRL with an unknown critical extension
    unknown_ext = x509.UnrecognizedExtension(OID_UNKNOWN_CRITICAL, b"\x01\x01\xff")
    crl = (
        base_crl_builder(ca_cert, 400, PAST, FUTURE)
         .add_extension(unknown_ext, critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    write_der("unknown_critical.der", crl.public_bytes(serialization.Encoding.DER))

    # 8. CRL containing the same serial twice with identical content
    entry = revoked_builder(
        SERIAL_DUPLICATE, ReasonFlags.key_compromise
    ).build()
    crl = (
        base_crl_builder(ca_cert, 500, PAST, FUTURE)
        .add_revoked_certificate(entry)
        .add_revoked_certificate(entry)
        .sign(ca_key, hashes.SHA256())
    )
    write_der("duplicate_serial.der", crl.public_bytes(serialization.Encoding.DER))

    # 8b. same serial twice, but with different reason codes (inconsistent duplicate)
    crl = (
        base_crl_builder(ca_cert, 501, PAST, FUTURE)
        .add_revoked_certificate(
            revoked_builder(
                SERIAL_DUPLICATE, ReasonFlags.key_compromise
            ).build()
        )
        .add_revoked_certificate(
            revoked_builder(
                SERIAL_DUPLICATE,
                ReasonFlags.cessation_of_operation,
            ).build()
        )
        .sign(ca_key, hashes.SHA256())
    )
    write_der(
        "duplicate_inconsistent.der",
        crl.public_bytes(serialization.Encoding.DER),
    )

    # 9. full (non-delta) CRL carrying an illegal removeFromCRL entry
    entry = (
        x509.RevokedCertificateBuilder()
        .serial_number(SERIAL_HOLD)
        .revocation_date(PAST)
        .add_extension(x509.CRLReason(ReasonFlags.remove_from_crl), critical=False)
        .build()
    )
    crl = (
        base_crl_builder(ca_cert, 600, PAST, FUTURE)
        .add_revoked_certificate(entry)
        .sign(ca_key, hashes.SHA256())
    )
    write_der(
        "remove_from_crl_full.der",
        crl.public_bytes(serialization.Encoding.DER),
    )

    # 10. indirect CRL: an entry for a cert issued by a second CA, with certificateIssuer
    other_key, other_ca = make_ca("Other CA", True)
    indirect_idp = x509.IssuingDistributionPoint(
        full_name=None,
        relative_name=None,
        only_contains_user_certs=False,
        only_contains_ca_certs=False,
        only_some_reasons=None,
        indirect_crl=True,
        only_contains_attribute_certs=False,
    )
    entry = (
        x509.RevokedCertificateBuilder()
        .serial_number(SERIAL_INDIRECT)
        .revocation_date(PAST)
        .add_extension(x509.CRLReason(ReasonFlags.key_compromise), critical=False)
        .add_extension(
            x509.CertificateIssuer(
                [x509.DirectoryName(other_ca.subject)]
            ),
            critical=False,
        )
        .build()
    )
    crl = (
        base_crl_builder(ca_cert, 700, PAST, FUTURE)
        .add_extension(indirect_idp, critical=True)
        .add_revoked_certificate(entry)
        .sign(ca_key, hashes.SHA256())
    )
    write_der("indirect.der", crl.public_bytes(serialization.Encoding.DER))
    write_der(
        "other_ca.der", other_ca.public_bytes(serialization.Encoding.DER)
    )
    indirect_cert = make_ee_cert(
        other_ca, other_key, SERIAL_INDIRECT, "indirect ee"
    )
    write_der(
        "cert_indirect.der",
        indirect_cert.public_bytes(serialization.Encoding.DER),
    )

    # 10b. indirect CRL with an entry lacking certificateIssuer: attribution is ambiguous for
    # certificates not issued by the CRL issuer
    entry = (
        x509.RevokedCertificateBuilder()
        .serial_number(SERIAL_INDIRECT)
        .revocation_date(PAST)
        .add_extension(
            x509.CRLReason(ReasonFlags.key_compromise), critical=False
        )
        .build()
    )
    crl = (
        base_crl_builder(ca_cert, 701, PAST, FUTURE)
        .add_extension(indirect_idp, critical=True)
        .add_revoked_certificate(entry)
        .sign(ca_key, hashes.SHA256())
    )
    write_der(
        "indirect_no_issuer.der",
        crl.public_bytes(serialization.Encoding.DER),
    )


if __name__ == "__main__":
    main()
