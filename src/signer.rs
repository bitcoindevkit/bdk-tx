use alloc::string::ToString;

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
                    let pk = prv.key.public_key(secp);
                    if key_request == KeyRequest::Pubkey(pk) {
                        return Ok(Some(prv.key));
                    }
                }
                (_, desc_sk) => {
                    for desc_sk in desc_sk.clone().into_single_keys() {
                        if let KeyRequest::Bip32((fingerprint, derivation)) = &key_request {
                            if let DescriptorSecretKey::XPrv(k) = desc_sk {
                                // We have the xprv for the request
                                if let Ok(Some(prv)) =
                                    GetKey::get_key(&k.xkey, key_request.clone(), secp)
                                {
                                    return Ok(Some(prv));
                                }
                                // The key origin is a strict prefix of the request derivation
                                if let Some((fp, path)) = &k.origin {
                                    if fingerprint == fp
                                        && derivation.to_string().starts_with(&path.to_string())
                                    {
                                        let to_derive = &derivation[path.len()..];
                                        let derived = k.xkey.derive_priv(secp, &to_derive)?;
                                        return Ok(Some(derived.to_priv()));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        Ok(None)
    }
}

#[cfg(test)]
mod test {
    use std::string::String;

    use bitcoin::bip32::{DerivationPath, Fingerprint, Xpriv};
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

    // Test `Signer` can fulfill a bip32 KeyRequest if we know the key origin
    #[test]
    fn get_key_bip32() -> anyhow::Result<()> {
        let secp = Secp256k1::new();

        // master xprv
        let xprv: Xpriv = "tprv8ZgxMBicQKsPdy6LMhUtFHAgpocR8GC6QmwMSFpZs7h6Eziw3SpThFfczTDh5rW2krkqffa11UpX3XkeTTB2FvzZKWXqPY54Y6Rq4AQ5R8L".parse()?;
        // derived xprv m/86h/1h/0h
        let derived = "tprv8h3aUwHujoUTC5Mw1bDZqEHRgughz7xCsQmeZsNPkpXYGLzbvKZF6p2E16SqqWkR8SvvRXSJ4H8yehJMvCVPYbB8U6r4KUhbEN5kzSFdkdx";

        struct TestCase {
            name: &'static str,
            desc: String,
            fingerprint: &'static str,
            derivation: &'static str,
        }

        let cases = vec![
            TestCase {
                name: "key matches request fingerprint",
                desc: format!("tr({xprv}/86h/1h/0h/0/*)"),
                fingerprint: "e273fe42",
                derivation: "86h/1h/0h/0/7",
            },
            TestCase {
                name: "key is derivable from request deriv path",
                desc: format!("tr([e273fe42/86h/1h/0h]{derived}/0/*)"),
                fingerprint: "e273fe42",
                derivation: "86h/1h/0h/0/7",
            },
            TestCase {
                name: "key origin matches request derivation",
                desc: format!("tr([e273fe42/86h/1h/0h]{derived}/0/*)"),
                fingerprint: "e273fe42",
                derivation: "86h/1h/0h",
            },
        ];

        for test in cases {
            let fp: Fingerprint = test.fingerprint.parse()?;
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
}
