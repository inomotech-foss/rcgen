//! Tests for detached signing: obtaining a "to be signed" (TBS) structure's DER encoding,
//! signing it out of process, and assembling the result, without ever going through
//! [`rcgen::SigningKey::sign`].

use std::time::Duration as StdDuration;

use pki_types::{CertificateDer, PrivateKeyDer, SignatureVerificationAlgorithm, UnixTime};
use rcgen::{
	BasicConstraints, CertificateParams, CertificateRevocationListParams, DnType, IsCa, Issuer,
	KeyPair, KeyUsagePurpose, PublicKeyData, RevocationReason, RevokedCertParams, SerialNumber,
	SignatureAlgorithm, SigningKey,
};
use ring::rand::SystemRandom;
use ring::signature::{self, EcdsaKeyPair};
use time::{Duration, OffsetDateTime};
use webpki::{anchor_from_trusted_cert, EndEntityCert, KeyUsage};

/// A public key handed out by a remote custody service: only [`PublicKeyData`]'s two required
/// methods, no [`rcgen::SigningKey`] impl. This is exactly what a downstream consumer would
/// write themselves; rcgen does not need to provide a constructor for it.
struct RemotePublicKey {
	algorithm: &'static SignatureAlgorithm,
	der_bytes: Vec<u8>,
}

impl PublicKeyData for RemotePublicKey {
	fn der_bytes(&self) -> &[u8] {
		&self.der_bytes
	}

	fn algorithm(&self) -> &'static SignatureAlgorithm {
		self.algorithm
	}
}

fn sign_ecdsa_p256(key_der: &PrivateKeyDer<'_>, msg: &[u8]) -> Vec<u8> {
	let rng = SystemRandom::new();
	let key_pair = EcdsaKeyPair::from_pkcs8(
		&signature::ECDSA_P256_SHA256_ASN1_SIGNING,
		key_der.secret_der(),
		&rng,
	)
	.unwrap();
	let signature = key_pair.sign(&rng, msg).unwrap();
	signature.as_ref().to_vec()
}

fn verify_chain(
	cert_der: &CertificateDer<'_>,
	ca_der: &CertificateDer<'_>,
	alg: &dyn SignatureVerificationAlgorithm,
) {
	let trust_anchor = anchor_from_trusted_cert(ca_der).unwrap();
	let trust_anchor_list = &[trust_anchor];
	let end_entity_cert = EndEntityCert::try_from(cert_der).unwrap();
	// Set time to Jan 10, 2004, matching the other verify-tests.
	let time = UnixTime::since_unix_epoch(StdDuration::from_secs(0x40_00_00_00));
	end_entity_cert
		.verify_for_usage(
			&[alg],
			&trust_anchor_list[..],
			&[],
			time,
			KeyUsage::server_auth(),
			None,
			None,
		)
		.expect("chain should verify");
}

fn ca_params() -> CertificateParams {
	let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
	params
		.distinguished_name
		.push(DnType::CommonName, "Detached signing test CA");
	params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
	params.key_usages.push(KeyUsagePurpose::KeyCertSign);
	params
}

fn leaf_params() -> CertificateParams {
	let mut params = CertificateParams::new(vec!["crabs.crabs".to_string()]).unwrap();
	params
		.distinguished_name
		.push(DnType::CommonName, "Dev domain");
	params
}

/// Ed25519 signatures are deterministic, so a certificate assembled from the detached TBS,
/// signature and algorithm must be byte-identical to one produced directly by `signed_by`.
#[test]
fn detached_equals_direct_leaf_ed25519() {
	let (ca_key, _) = KeyPair::generate_for(&rcgen::ED25519).unwrap();
	let ca_params = ca_params();
	let issuer = Issuer::from_params(&ca_params, &ca_key);

	let (leaf_key, _) = KeyPair::generate_for(&rcgen::ED25519).unwrap();
	let params = leaf_params();

	let direct = params.signed_by(&leaf_key, &issuer).unwrap();

	let tbs = params.tbs_certificate(&leaf_key, &issuer).unwrap();
	let sig = ca_key.sign(&tbs).unwrap();
	let assembled = rcgen::serialize_signed_der(&tbs, ca_key.algorithm(), &sig);

	assert_eq!(direct.der().as_ref(), assembled.as_slice());
}

/// The same equality as [`detached_equals_direct_leaf_ed25519`], but for a CRL.
#[test]
fn detached_equals_direct_crl_ed25519() {
	let (ca_key, _) = KeyPair::generate_for(&rcgen::ED25519).unwrap();
	let mut params = ca_params();
	params.key_usages.push(KeyUsagePurpose::CrlSign);
	let issuer = Issuer::from_params(&params, &ca_key);

	let now = OffsetDateTime::from_unix_timestamp(0x40_00_00_00).unwrap();
	let mut crl_params = CertificateRevocationListParams::new(
		now,
		now + Duration::weeks(1),
		SerialNumber::from(1234),
		rcgen::KeyIdMethod::Sha256,
	);
	let mut revoked_cert = RevokedCertParams::new(SerialNumber::from(9999), now);
	revoked_cert.reason_code = Some(RevocationReason::KeyCompromise);
	crl_params.revoked_certs = vec![revoked_cert];

	let direct = crl_params.signed_by(&issuer).unwrap();

	let tbs = crl_params.tbs_cert_list(&issuer).unwrap();
	let sig = ca_key.sign(&tbs).unwrap();
	let assembled = rcgen::serialize_signed_der(&tbs, ca_key.algorithm(), &sig);

	assert_eq!(direct.der().as_ref(), assembled.as_slice());
}

/// The use case the patch exists for: an issuer built from a CA certificate's DER and *only*
/// its public key and algorithm (no [`rcgen::SigningKey`] impl at all), with the actual
/// signature produced separately, as if by a remote custody service.
#[test]
fn public_key_only_issuer_end_to_end() {
	let alg = &rcgen::ECDSA_P256_SHA256;
	let (ca_key, ca_key_der) = KeyPair::generate_for(alg).unwrap();
	let params = ca_params();
	let ca_cert = params.self_signed(&ca_key).unwrap();

	// All the "custody service" hands out is the CA's public key and algorithm.
	let ca_public_key = RemotePublicKey {
		algorithm: ca_key.algorithm(),
		der_bytes: ca_key.der_bytes().to_vec(),
	};
	let issuer = Issuer::from_ca_cert_der(ca_cert.der(), ca_public_key).unwrap();
	assert_eq!(issuer.key_usages(), &[KeyUsagePurpose::KeyCertSign]);

	let (leaf_key, _) = KeyPair::generate_for(alg).unwrap();
	let leaf = leaf_params();

	// No `SigningKey` is ever available for the issuer; only its public key is used here.
	let tbs = leaf.tbs_certificate(&leaf_key, &issuer).unwrap();

	// The private key never leaves the custody service; only the signature comes back.
	let sig = sign_ecdsa_p256(&ca_key_der, &tbs);
	let cert_der: CertificateDer<'_> = rcgen::serialize_signed_der(&tbs, alg, &sig).into();

	verify_chain(&cert_der, ca_cert.der(), webpki::ring::ECDSA_P256_SHA256);
}
