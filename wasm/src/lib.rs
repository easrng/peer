use sha2::{Digest, Sha256};
use wasm_bindgen::prelude::*;
use web_sys::js_sys::{Array, Uint8Array};

#[wasm_bindgen]
pub fn hashes(name: String, now: i64) -> Result<Array, String> {
    let mut hasher = Sha256::new();
    hasher.update(cert::self_signed(name.clone(), now - 1209600)?);
    let cert1: Uint8Array = hasher.finalize().as_slice().into();

    hasher = Sha256::new();
    hasher.update(cert::self_signed(name.clone(), now)?);
    let cert2: Uint8Array = hasher.finalize().as_slice().into();

    hasher = Sha256::new();
    hasher.update(cert::self_signed(name, now + 1209600)?);
    let cert3: Uint8Array = hasher.finalize().as_slice().into();

    return Ok(Array::of3(&cert1, &cert2, &cert3));
}
