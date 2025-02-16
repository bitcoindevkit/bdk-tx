use bitcoin::{
    psbt::{GetKey, KeyRequest},
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
    type Error = ();

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
                        if let DescriptorSecretKey::XPrv(k) = desc_sk {
                            if let Ok(Some(prv)) =
                                GetKey::get_key(&k.xkey, key_request.clone(), secp)
                            {
                                return Ok(Some(prv));
                            }
                        }
                    }
                }
            }
        }
        Ok(None)
    }
}
