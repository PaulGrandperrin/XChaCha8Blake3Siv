/*
XChaCha20Blake3Siv is a nonce-reuse misuse-resistant (NRMR) and key-commiting authenticated encryption with associated data (AEAD) algorithm .

XChaCha20Blake3Siv can also be used as a deterministic authenticated encryption (DAE) key-commiting AEAD.

XChaCha20Blake3Siv is inspired by the generic Synthetic Initialization Vector (SIV) construction described in [0].

We assume XChaCha20Blake3Siv is key-commiting and therefore resistant to partitioning oracle attacks based on our understanding of [1].

We believe that using the Mac-then-Encrypt (MtE) is secure because we are not using a block cipher, so there is no padding
and so no padding oracle attack is possible.

We don't perform key separation between the cipher and the PRF because we assume that xchacha20 and blake3 are sufficiently unrelated. 

0: https://datatracker.ietf.org/doc/draft-madden-generalised-siv/
1: https://www.usenix.org/conference/usenixsecurity21/presentation/len

Pseudocode:

fn encrypt(key:256, iv:256, ad:*, plaintext:*) -> tag:256, ciphertext:*
  let tag:256 = blake3::keyed_hash(key:256, iv:256 + ad:* + plaintext:*) 
  let siv = tag
  let subkey:256, subiv:96 = blake3::keyed_hash(key:256, siv:256)
  let ciphertext:* = chacha20(subkey:256, subiv:96, plaintext:*)


fn decrypt(key:256, iv:256, tag:256, ad:*, ciphertext:*)
  let siv = tag
  let subkey:256, subiv:96 = blake3::keyed_hash(key:256, siv:256)
  let plaintext:* = chacha20(subkey:256, subiv:96, ciphertext:*)
  let tag2 = blake3::keyed_hash(key:256, iv:256 + ad:* + plaintext:*)
  assert!(tag == tag2) // constant time

*/

use std::mem::MaybeUninit;

use aead::{AeadInPlace, Error, NewAead, consts::{U0, U12, U24, U32}, generic_array::GenericArray};
use typenum::Unsigned;
use chacha20::{ChaCha20, XChaCha20, cipher::{NewStreamCipher, SyncStreamCipher}};
use zeroize::Zeroize;

pub type Key = GenericArray<u8, <XChaCha20Blake3Siv as NewAead>::KeySize>;
pub type Nonce = GenericArray<u8, <XChaCha20Blake3Siv as AeadInPlace>::NonceSize>;
pub type Tag = GenericArray<u8, <XChaCha20Blake3Siv as AeadInPlace>::TagSize>;

pub struct XChaCha20Blake3Siv {
    key: Key
}

impl NewAead for XChaCha20Blake3Siv {
    type KeySize = U32;

    fn new(key: &Key) -> Self {
        XChaCha20Blake3Siv { key: *key }
    }
}

impl AeadInPlace for XChaCha20Blake3Siv {
    type NonceSize = U32;
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
        let siv: &Nonce = &tag;
        
        let mut hasher = blake3::Hasher::new_keyed(self.key.as_ref());
        hasher.update(siv);
        
        let mut hash = unsafe {MaybeUninit::<[u8; 44]>::uninit().assume_init()}; // i guess that's UB :/
        hasher.finalize_xof().fill(&mut hash);
        
        let subkey: &GenericArray<u8, U32> = hash.as_ref()[0..32].into();
        let subiv:  &GenericArray<u8, U12> = hash.as_ref()[32..44].into();
        
        ChaCha20::new(subkey,subiv).apply_keystream(buffer);
        Ok(tag)
    }
    
    fn decrypt_in_place_detached(
        &self,
        nonce: &Nonce,
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &Tag,
    ) -> Result<(), Error> {
        let siv: &Nonce = &tag;

        let mut hasher = blake3::Hasher::new_keyed(self.key.as_ref());
        hasher.update(siv);
        
        let mut hash = unsafe {MaybeUninit::<[u8; 44]>::uninit().assume_init()}; // i guess that's UB :/
        hasher.finalize_xof().fill(&mut hash);
        
        let subkey: &GenericArray<u8, U32> = hash.as_ref()[0..32].into();
        let subiv:  &GenericArray<u8, U12> = hash.as_ref()[32..44].into();

        ChaCha20::new(subkey,subiv).apply_keystream(buffer);
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
    use aead::{AeadInPlace, NewAead};
    use crate::{Key, Nonce, Tag, XChaCha20Blake3Siv};

    #[test]
    fn it_works() {
        let key = Key::from_slice(b"an example very very secret key."); // 32-bytes
        let cipher = XChaCha20Blake3Siv::new(key);
        let nonce = Nonce::from_slice(b"extra extra long unique nonce!!!"); // 32-bytes; unique per message
        let mut buffer = b"plaintext message".to_owned();

        let tag: Tag = cipher.encrypt_in_place_detached(nonce, b"associated data", &mut buffer)
            .expect("encryption failure!");  // NOTE: handle this error to avoid panics!
        cipher.decrypt_in_place_detached(nonce, b"associated data", &mut buffer, &tag)
            .expect("decryption failure!");  // NOTE: handle this error to avoid panics!
        
        assert_eq!(&buffer, b"plaintext message");
    }
}