//! Tests for detached signing: obtaining a "to be signed" (TBS) structure's DER encoding,
//! signing it out of process, and assembling the result, without ever going through
//! [`rcgen::SigningKey::sign`].

use std::time::Duration as StdDuration;

use pki_types::{CertificateDer, SignatureVerificationAlgorithm, UnixTime};
use rcgen::{
	BasicConstraints, Certificate, CertificateParams, CertificateRevocationList,
	CertificateRevocationListParams, DnType, IsCa, Issuer, KeyPair, KeyUsagePurpose, PublicKeyData,
	RevocationReason, RevokedCertParams, SerialNumber, SigningKey, SubjectPublicKeyInfo,
};
use ring::rand::SystemRandom;
use ring::signature::{self, EcdsaKeyPair};
use time::{Duration, OffsetDateTime};
use webpki::{anchor_from_trusted_cert, EndEntityCert, KeyUsage};

/// Returns the raw DER bytes (tag, length and content) of the first element inside the
/// top-level `SEQUENCE` of `der`.
///
/// Every structure rcgen signs is `SEQUENCE { tbs, signatureAlgorithm, signature }`, so this
/// extracts exactly the `tbs` bytes a direct (non-detached) call produced, for comparison
/// against [`rcgen::CertificateParams::tbs_certificate`] and friends.
fn first_tlv(der: &[u8]) -> &[u8] {
	let outer_content = &der[der_header_len(der)..];
	&outer_content[..der_element_len(outer_content)]
}

/// Returns the number of bytes making up the tag and length of the DER element at the start of
/// `der` (i.e. the offset at which its content begins).
fn der_header_len(der: &[u8]) -> usize {
	let first_length_byte = der[1];
	if first_length_byte & 0x80 == 0 {
		2
	} else {
		2 + (first_length_byte & 0x7f) as usize
	}
}

/// Returns the total length (tag, length and content) of the DER element at the start of `der`.
fn der_element_len(der: &[u8]) -> usize {
	let header_len = der_header_len(der);
	let first_length_byte = der[1];
	let content_len = if first_length_byte & 0x80 == 0 {
		first_length_byte as usize
	} else {
		let n = (first_length_byte & 0x7f) as usize;
		der[2..2 + n]
			.iter()
			.fold(0usize, |len, byte| (len << 8) | *byte as usize)
	};
	header_len + content_len
}

fn sign_ecdsa_p256(key_pair: &KeyPair, msg: &[u8]) -> Vec<u8> {
	let pk_der = key_pair.serialize_der();
	let rng = SystemRandom::new();
	let key_pair =
		EcdsaKeyPair::from_pkcs8(&signature::ECDSA_P256_SHA256_ASN1_SIGNING, &pk_der, &rng)
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
	let ca_key = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
	let ca_params = ca_params();
	let issuer = Issuer::from_params(&ca_params, &ca_key);

	let leaf_key = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
	let params = leaf_params();

	let direct = params.signed_by(&leaf_key, &issuer).unwrap();

	let tbs = params.tbs_certificate(&leaf_key, &issuer).unwrap();
	let sig = ca_key.sign(&tbs).unwrap();
	let assembled = rcgen::serialize_signed_der(&tbs, ca_key.algorithm(), &sig);
	let detached = Certificate::from_der(assembled.into());

	assert_eq!(direct.der(), detached.der());
}

/// The same equality as [`detached_equals_direct_leaf_ed25519`], but for a self-signed
/// certificate: the subject's own key doubles as the issuer.
#[test]
fn detached_equals_direct_self_signed_ed25519() {
	let key = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
	let params = leaf_params();

	let direct = params.self_signed(&key).unwrap();

	let issuer = Issuer::from_params(&params, &key);
	let tbs = params.tbs_certificate(&key, &issuer).unwrap();
	let sig = key.sign(&tbs).unwrap();
	let assembled = rcgen::serialize_signed_der(&tbs, key.algorithm(), &sig);
	let detached = Certificate::from_der(assembled.into());

	assert_eq!(direct.der(), detached.der());
}

/// The same equality as [`detached_equals_direct_leaf_ed25519`], but for a CRL.
#[test]
fn detached_equals_direct_crl_ed25519() {
	let ca_key = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
	let mut params = ca_params();
	params.key_usages.push(KeyUsagePurpose::CrlSign);
	let issuer = Issuer::from_params(&params, &ca_key);

	let now = OffsetDateTime::from_unix_timestamp(0x40_00_00_00).unwrap();
	let crl_params = CertificateRevocationListParams {
		this_update: now,
		next_update: now + Duration::weeks(1),
		crl_number: SerialNumber::from(1234),
		issuing_distribution_point: None,
		revoked_certs: vec![RevokedCertParams {
			serial_number: SerialNumber::from(9999),
			revocation_time: now,
			reason_code: Some(RevocationReason::KeyCompromise),
			invalidity_date: None,
		}],
		key_identifier_method: rcgen::KeyIdMethod::Sha256,
	};

	let direct = crl_params.signed_by(&issuer).unwrap();

	let tbs = crl_params.tbs_cert_list(&issuer).unwrap();
	let sig = ca_key.sign(&tbs).unwrap();
	let assembled = rcgen::serialize_signed_der(&tbs, ca_key.algorithm(), &sig);
	let detached = CertificateRevocationList::from_der(assembled.into());

	assert_eq!(direct.der(), detached.der());
}

/// With an ECDSA P-256 issuer (non-deterministic signatures), the TBS bytes produced by the
/// direct `signed_by` path and by [`rcgen::CertificateParams::tbs_certificate`] must still be
/// identical, and a certificate assembled from the latter must verify like any other.
#[test]
fn detached_tbs_equals_direct_ecdsa_p256() {
	let alg = &rcgen::PKCS_ECDSA_P256_SHA256;
	let ca_key = KeyPair::generate_for(alg).unwrap();
	let params = ca_params();
	let ca_cert = params.self_signed(&ca_key).unwrap();
	let issuer = Issuer::from_params(&params, &ca_key);

	let leaf_key = KeyPair::generate_for(alg).unwrap();
	let leaf = leaf_params();

	let direct = leaf.signed_by(&leaf_key, &issuer).unwrap();
	let direct_tbs = first_tlv(direct.der());

	let detached_tbs = leaf.tbs_certificate(&leaf_key, &issuer).unwrap();
	assert_eq!(direct_tbs, detached_tbs.as_slice());

	let sig = sign_ecdsa_p256(&ca_key, &detached_tbs);
	let assembled = rcgen::serialize_signed_der(&detached_tbs, alg, &sig);
	let cert = Certificate::from_der(assembled.into());

	verify_chain(cert.der(), ca_cert.der(), webpki::ring::ECDSA_P256_SHA256);
}

/// The use case the patch exists for: an issuer built from a CA certificate's DER and *only*
/// its public key and algorithm (no [`SigningKey`] impl at all), with the actual signature
/// produced separately, as if by a remote custody service.
#[test]
fn public_key_only_issuer_end_to_end() {
	let alg = &rcgen::PKCS_ECDSA_P256_SHA256;
	let ca_key = KeyPair::generate_for(alg).unwrap();
	let params = ca_params();
	let ca_cert = params.self_signed(&ca_key).unwrap();

	// All the "custody service" hands out is the CA's public key and algorithm.
	let ca_public_key = SubjectPublicKeyInfo::new(ca_key.algorithm(), ca_key.der_bytes().to_vec());
	let issuer = Issuer::from_ca_cert_der(ca_cert.der(), ca_public_key).unwrap();
	assert_eq!(issuer.key_usages(), &[KeyUsagePurpose::KeyCertSign]);

	let leaf_key = KeyPair::generate_for(alg).unwrap();
	let leaf = leaf_params();

	// No `SigningKey` is ever available for the issuer; only its public key is used here.
	let tbs = leaf.tbs_certificate(&leaf_key, &issuer).unwrap();

	// The private key never leaves the custody service; only the signature comes back.
	let sig = sign_ecdsa_p256(&ca_key, &tbs);
	let cert_der = rcgen::serialize_signed_der(&tbs, alg, &sig);
	let cert = Certificate::from_der(cert_der.into());

	verify_chain(cert.der(), ca_cert.der(), webpki::ring::ECDSA_P256_SHA256);
}
