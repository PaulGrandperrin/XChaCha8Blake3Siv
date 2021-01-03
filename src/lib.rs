/*
// encrypt(key:256, iv:192, ad:*, plaintext:*) -> tag:256, ciphertext:*
let tag:256 = blake3::keyed_hash(key:256, iv:192 + ad:* + plaintext:*)
let siv:192 = tag[0..192]
let ciphertext:* = xchacha20(key:256, siv:192, plaintext:*)


//decrypt(key:256, iv:192, tag:256, ad:*, ciphertext:*)
let siv:192 = tag[0..192]
let plaintext:* = xchacha20(key:256, siv:192, ciphertext:*)
let tag2 = blake3::keyed_hash(key:256, iv:192 + ad:* + plaintext:*)
assert!(tag == tag2) // constant time
*/

use aead::{AeadInPlace, Error, NewAead, consts::{U0, U24, U32}, generic_array::GenericArray};
use typenum::Unsigned;
use chacha20::cipher::{NewStreamCipher, SyncStreamCipher};
use zeroize::Zeroize;

type Key = GenericArray<u8, <XChaCha20Blake3Siv as NewAead>::KeySize>;
type Nonce = GenericArray<u8, <XChaCha20Blake3Siv as AeadInPlace>::NonceSize>;
type Tag = GenericArray<u8, <XChaCha20Blake3Siv as AeadInPlace>::TagSize>;

struct XChaCha20Blake3Siv {
    key: Key
}

impl NewAead for XChaCha20Blake3Siv {
    type KeySize = U32;

    fn new(key: &Key) -> Self {
        XChaCha20Blake3Siv { key: *key }
    }
}

impl AeadInPlace for XChaCha20Blake3Siv {
    type NonceSize = U24;
    type TagSize = U32;
    type CiphertextOverhead = U0;

    fn encrypt_in_place_detached(
        &self,
        nonce: &Nonce,
        associated_data: &[u8],
        buffer: &mut [u8],
    ) -> Result<Tag, Error> {
        let mut hasher = blake3::Hasher::new_keyed(self.key.as_ref());
        hasher.update(nonce);
        hasher.update(associated_data);
        hasher.update(buffer);
        let tag: Tag = Into::<[u8; Self::TagSize::USIZE]>::into(hasher.finalize()).into(); // consumes the Hash to avoid copying
        let siv: &Nonce = tag.as_slice()[0..Self::NonceSize::USIZE].into(); // constructs a reference to avoid copying
        chacha20::XChaCha20::new(&self.key,siv).apply_keystream(buffer);
        Ok(tag)
    }

    fn decrypt_in_place_detached(
        &self,
        nonce: &Nonce,
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &Tag,
    ) -> Result<(), Error> {
        let siv: &Nonce = tag.as_slice()[0..Self::NonceSize::USIZE].into(); // constructs a reference to avoid copying
        chacha20::XChaCha20::new(&self.key,siv).apply_keystream(buffer);
        let mut hasher = blake3::Hasher::new_keyed(self.key.as_ref());
        hasher.update(nonce);
        hasher.update(associated_data);
        hasher.update(buffer);
        let hash = hasher.finalize();
        if hash.eq(tag.as_ref() as &[u8; Self::TagSize::USIZE]) { // the PartialEq implementation of blake3::Hash executes in constant time
            Ok(())
        } else {
            Err(Error)
        }
    }
}

impl Drop for XChaCha20Blake3Siv {
    fn drop(&mut self) {
        self.key.as_mut_slice().zeroize();
    }
}

#[cfg(test)]
mod tests {
    use aead::{Aead, NewAead};

    use crate::{Key, Nonce, XChaCha20Blake3Siv};

    #[test]
    fn it_works() {
        let key = Key::from_slice(b"an example very very secret key."); // 32-bytes
        let cipher = XChaCha20Blake3Siv::new(key);
        
        let nonce = Nonce::from_slice(b"extra long unique nonce!"); // 24-bytes; unique per message
        
        let ciphertext = cipher.encrypt(nonce, b"plaintext message".as_ref())
            .expect("encryption failure!");  // NOTE: handle this error to avoid panics!
        let plaintext = cipher.decrypt(nonce, ciphertext.as_ref())
            .expect("decryption failure!");  // NOTE: handle this error to avoid panics!
        
        assert_eq!(&plaintext, b"plaintext message");
    }
}