use ecdsa::signature::Signer;
use p256::ecdsa::DerSignature;
use p256::pkcs8::DecodePrivateKey;
const EC_OID: [u64; 6] = [1, 2, 840, 10045, 2, 1];
const P256_OID: [u64; 7] = [1, 2, 840, 10045, 3, 1, 7];
const ECDSA_SHA256_OID: [u64; 7] = [1, 2, 840, 10045, 4, 3, 2];
pub const HARDCODED_NOT_SO_SECRET_KEY_DER: [u8; 138] = [
    48, 129, 135, 2, 1, 0, 48, 19, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 8, 42, 134, 72, 206, 61, 3,
    1, 7, 4, 109, 48, 107, 2, 1, 1, 4, 32, 12, 22, 255, 142, 5, 15, 191, 57, 206, 150, 228, 195,
    136, 59, 38, 134, 91, 103, 174, 8, 172, 131, 202, 185, 169, 230, 23, 205, 116, 251, 97, 202,
    161, 68, 3, 66, 0, 4, 196, 88, 18, 107, 210, 88, 142, 251, 194, 149, 122, 135, 146, 69, 229,
    87, 109, 122, 2, 138, 24, 153, 47, 168, 201, 186, 245, 240, 215, 120, 162, 150, 195, 15, 120,
    0, 32, 46, 175, 102, 133, 34, 107, 65, 135, 198, 132, 176, 88, 207, 174, 57, 123, 82, 175, 177,
    4, 184, 219, 115, 165, 151, 89, 163,
];
const COMMON_NAME_OID: [u64; 4] = [2, 5, 4, 3];
const SUBJECT_ALT_NAME: [u64; 4] = [2, 5, 29, 17];

pub fn self_signed(name: String, now: i64) -> Result<Vec<u8>, String> {
    let secret_key: ecdsa::SigningKey<p256::NistP256> =
        p256::ecdsa::SigningKey::from_pkcs8_der(&HARDCODED_NOT_SO_SECRET_KEY_DER).unwrap();
    let public_key = secret_key.verifying_key();
    let not_before = now / 1209600 * 1209600;
    let mut ip: Result<Vec<u8>, _> = name.parse::<std::net::IpAddr>().map(|ip| match ip {
        std::net::IpAddr::V4(ip4) => ip4.octets().into(),
        std::net::IpAddr::V6(ip6) => ip6.octets().into(),
    });
    let certificate = simple_x509::X509Builder::new(vec![
        91, 57, 155, 185, 151, 10, 131, 60, 117, 27, 145, 185, 3, 175, 178, 175, 230, 200, 39, 11,
    ])
    .version(2)
    .issuer_utf8(Vec::from(COMMON_NAME_OID), &name)
    .subject_utf8(Vec::from(COMMON_NAME_OID), &name)
    .ext_raw(
        SUBJECT_ALT_NAME.into(),
        false,
        simple_asn1::to_der(&simple_asn1::ASN1Block::Sequence(
            1,
            vec![simple_asn1::ASN1Block::Unknown(
                simple_asn1::ASN1Class::ContextSpecific,
                false,
                ip.as_mut().map_or_else(|_| name.len(), |ip| ip.len()),
                ip.as_mut().map_or_else(|_| 2_u8, |_| 7_u8).into(),
                ip.map_or_else(|_| name.into(), |ip| ip),
            )],
        ))
        .map_err(|e| format!("{e:?}"))?,
    )
    .not_before_utc(not_before)
    .not_after_utc(not_before + 1209600)
    .pub_key_ec(
        Vec::from(EC_OID),
        public_key.to_encoded_point(false).as_bytes().to_owned(),
        Vec::from(P256_OID),
    )
    .sign_oid(Vec::from(ECDSA_SHA256_OID))
    .build()
    .sign(
        |cert, _| {
            let signature: DerSignature = secret_key.sign(cert);
            Some(signature.as_bytes().to_owned())
        },
        &[],
    )
    .map_err(|e| format!("{e:?}"))?;
    return certificate.x509_enc().map_err(|e| format!("{e:?}"));
}
