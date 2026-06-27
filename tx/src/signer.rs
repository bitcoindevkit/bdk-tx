use alloc::collections::BTreeMap;

use bitcoin::{
    psbt::{GetKey, GetKeyError, KeyRequest},
    secp256k1::{self, Secp256k1},
};
use miniscript::bitcoin;
use miniscript::descriptor::{DescriptorSecretKey, KeyMap};

/// A PSBT signer
///
/// This is a simple wrapper type around miniscript [`KeyMap`] that implements [`GetKey`].
#[derive(Debug, Clone)]
pub struct Signer(pub KeyMap);

impl GetKey for Signer {
    type Error = GetKeyError;

    fn get_key<C: secp256k1::Signing>(
        &self,
        key_request: KeyRequest,
        secp: &Secp256k1<C>,
    ) -> Result<Option<bitcoin::PrivateKey>, Self::Error> {
        for entry in &self.0 {
            match entry {
                (_, DescriptorSecretKey::Single(prv)) => {
                    let map: BTreeMap<_, _> =
                        core::iter::once((prv.key.public_key(secp), prv.key)).collect();
                    if let Ok(Some(prv)) = GetKey::get_key(&map, key_request.clone(), secp) {
                        return Ok(Some(prv));
                    }
                }
                (_, desc_sk) => {
                    for desc_sk in desc_sk.clone().into_single_keys() {
                        if let (DescriptorSecretKey::XPrv(k), KeyRequest::Bip32(key_source)) =
                            (desc_sk, &key_request)
                        {
                            // We may hold the xprv for the request directly.
                            if let Ok(Some(prv)) =
                                GetKey::get_key(&k.xkey, key_request.clone(), secp)
                            {
                                return Ok(Some(prv));
                            }
                            // Otherwise let miniscript's `matches` confirm this key
                            // represents the request (handling the key origin and
                            // wildcard); a raw prefix check would also derive paths the
                            // descriptor never declares, e.g. a sibling of the wildcard.
                            if k.matches(key_source, secp).is_some() {
                                // `xkey` is anchored at the origin, so strip the origin
                                // prefix from the master-relative request path; with no
                                // origin the whole path is relative to `xkey`.
                                let (_, derivation) = key_source;
                                let to_derive = match &k.origin {
                                    Some((_, origin)) => &derivation[origin.len()..],
                                    None => derivation.as_ref(),
                                };
                                let derived = k.xkey.derive_priv(secp, &to_derive)?;
                                return Ok(Some(derived.to_priv()));
                            }
                        }
                    }
                }
            }
        }
        Ok(None)
    }
}

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
mod test {
    use crate::bitcoin::bip32::ChildNumber;
    use alloc::string::ToString;
    use core::str::FromStr;
    use std::string::String;

    use bitcoin::bip32::{DerivationPath, Xpriv};
    use miniscript::Descriptor;

    use super::*;

    #[test]
    fn get_key_pubkey() -> anyhow::Result<()> {
        let secp = Secp256k1::new();
        let wif = "cU6BxEezV8FnkEPBCaFtc4WNuUKmgFaAu6sJErB154GXgMUjhgWe";
        let prv = bitcoin::PrivateKey::from_wif(wif)?;
        let pk = prv.public_key(&secp);

        let s = format!("wpkh({wif})");
        let (_, keymap) = Descriptor::parse_descriptor(&secp, &s).unwrap();

        let signer = Signer(keymap);
        let req = KeyRequest::Pubkey(pk);
        let res = signer.get_key(req, &secp);
        assert!(matches!(
            res,
            Ok(Some(k)) if k == prv
        ));

        Ok(())
    }

    #[test]
    fn get_key_x_only_pubkey() -> anyhow::Result<()> {
        let secp = Secp256k1::new();
        let wif = "cU6BxEezV8FnkEPBCaFtc4WNuUKmgFaAu6sJErB154GXgMUjhgWe";
        let prv = bitcoin::PrivateKey::from_wif(wif)?;
        let (x_only_pk, _parity) = prv.inner.x_only_public_key(&secp);

        let s = format!("wpkh({wif})");
        let (_, keymap) = Descriptor::parse_descriptor(&secp, &s).unwrap();

        let signer = Signer(keymap);
        let req = KeyRequest::XOnlyPubkey(x_only_pk);
        let res = signer.get_key(req, &secp);
        assert!(matches!(
            res,
            Ok(Some(k)) if k.inner.x_only_public_key(&secp).0 == x_only_pk
        ));
        Ok(())
    }

    // Test `Signer` can fulfill a bip32 KeyRequest if we know the key origin
    #[test]
    fn get_key_bip32() -> anyhow::Result<()> {
        let secp = Secp256k1::new();

        // master xprv
        let xprv: Xpriv = "tprv8ZgxMBicQKsPdy6LMhUtFHAgpocR8GC6QmwMSFpZs7h6Eziw3SpThFfczTDh5rW2krkqffa11UpX3XkeTTB2FvzZKWXqPY54Y6Rq4AQ5R8L".parse()?;
        let fp = xprv.fingerprint(&secp);
        let path: DerivationPath = "86h/1h/0h".parse()?;
        let derived = xprv.derive_priv(&secp, &path)?;

        struct TestCase {
            name: &'static str,
            desc: String,
            derivation: String,
        }

        let cases = vec![
            TestCase {
                name: "key matches request fingerprint",
                desc: format!("tr({xprv}/{path}/0/*)"),
                derivation: format!("{path}/0/7"),
            },
            TestCase {
                name: "key is derivable from request derivation",
                desc: format!("tr([{fp}/{path}]{derived}/0/*)"),
                derivation: format!("{path}/0/7"),
            },
        ];

        for test in cases {
            let deriv: DerivationPath = test.derivation.parse()?;
            let exp_prv = xprv.derive_priv(&secp, &deriv)?.to_priv();
            let request = KeyRequest::Bip32((fp, deriv));

            let (_, keymap) = Descriptor::parse_descriptor(&secp, &test.desc)?;
            let signer = Signer(keymap);
            let res = signer.get_key(request, &secp);
            assert!(
                matches!(res, Ok(Some(k)) if k == exp_prv),
                "test case failed: {}",
                test.name
            );
        }

        Ok(())
    }

    // `matches` only signs for keys the descriptor actually represents. Requests
    // that share the origin as a prefix but fall outside the declared derivation
    // are rejected: the account-level key itself (request == origin) and a sibling
    // of the wildcard branch (`/9/*` when the descriptor declares `/0/*`).
    #[test]
    fn get_key_bip32_rejects_paths_outside_descriptor() -> anyhow::Result<()> {
        let secp = Secp256k1::new();
        let xprv: Xpriv = "tprv8ZgxMBicQKsPdy6LMhUtFHAgpocR8GC6QmwMSFpZs7h6Eziw3SpThFfczTDh5rW2krkqffa11UpX3XkeTTB2FvzZKWXqPY54Y6Rq4AQ5R8L".parse()?;
        let fp = xprv.fingerprint(&secp);
        let path: DerivationPath = "86h/1h/0h".parse()?;
        let derived = xprv.derive_priv(&secp, &path)?;
        let desc = format!("tr([{fp}/{path}]{derived}/0/*)");

        for derivation in [path.to_string(), format!("{path}/9/7")] {
            let deriv: DerivationPath = derivation.parse()?;
            let req = KeyRequest::Bip32((fp, deriv));
            let (_, keymap) = Descriptor::parse_descriptor(&secp, &desc)?;
            let res = Signer(keymap).get_key(req, &secp);
            assert!(
                matches!(res, Ok(None)),
                "expected None for {derivation}: {res:?}"
            );
        }

        Ok(())
    }

    #[test]
    fn get_key_xpriv_with_key_origin() -> anyhow::Result<()> {
        let secp = Secp256k1::new();
        let s = "wpkh([d34db33f/84h/1h/0h]tprv8ZgxMBicQKsPd3EupYiPRhaMooHKUHJxNsTfYuScep13go8QFfHdtkG9nRkFGb7busX4isf6X9dURGCoKgitaApQ6MupRhZMcELAxTBRJgS/*)";
        let (_, keymap) = Descriptor::parse_descriptor(&secp, s)?;

        let desc_sk = DescriptorSecretKey::from_str("[d34db33f/84h/1h/0h]tprv8ZgxMBicQKsPd3EupYiPRhaMooHKUHJxNsTfYuScep13go8QFfHdtkG9nRkFGb7busX4isf6X9dURGCoKgitaApQ6MupRhZMcELAxTBRJgS/*")?;
        let desc_xkey = match desc_sk {
            DescriptorSecretKey::XPrv(k) => k,
            _ => panic!(),
        };

        let (fp, _) = desc_xkey.origin.clone().unwrap();
        let path = DerivationPath::from_str("84h/1h/0h/7")?;
        let req = KeyRequest::Bip32((fp, path));

        let exp_prv = desc_xkey
            .xkey
            .derive_priv(&secp, &[ChildNumber::from(7)])?
            .to_priv();

        let res = Signer(keymap).get_key(req, &secp);

        assert!(matches!(
            res,
            Ok(Some(k)) if k == exp_prv,
        ));

        Ok(())
    }

    // The origin "84h/1h/0h/1" is a string prefix of "84h/1h/0h/10" even though
    // m/84'/1'/0'/1 is NOT a derivation-path prefix of m/84'/1'/0'/10. The signer
    // must reject this request instead of leaking the key at the origin path.
    #[test]
    fn get_key_bip32_string_prefix_not_path_prefix() -> anyhow::Result<()> {
        let secp = Secp256k1::new();
        let xprv: Xpriv = "tprv8ZgxMBicQKsPdy6LMhUtFHAgpocR8GC6QmwMSFpZs7h6Eziw3SpThFfczTDh5rW2krkqffa11UpX3XkeTTB2FvzZKWXqPY54Y6Rq4AQ5R8L".parse()?;
        let fp = xprv.fingerprint(&secp);

        let origin_path: DerivationPath = "84h/1h/0h/1".parse()?;
        let derived = xprv.derive_priv(&secp, &origin_path)?;
        let desc = format!("wpkh([{fp}/{origin_path}]{derived}/*)");
        let (_, keymap) = Descriptor::parse_descriptor(&secp, &desc)?;

        let request_path: DerivationPath = "84h/1h/0h/10".parse()?;
        let req = KeyRequest::Bip32((fp, request_path));
        let res = Signer(keymap).get_key(req, &secp);

        assert!(matches!(res, Ok(None)), "expected None, got: {res:?}");
        Ok(())
    }
}
