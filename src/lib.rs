/*
XChaCha8Blake3Siv is a nonce-reuse misuse-resistant (NRMR) and key-committing authenticated encryption with associated data (AEAD) algorithm .

XChaCha8Blake3Siv can also be used as a deterministic authenticated encryption (DAE) key-commiting AEAD.

XChaCha8Blake3Siv is inspired by the generic Synthetic Initialization Vector (SIV) construction described in [0].

Blake3 is collision-resistant therefore XChaCha8Blake3Siv is key-commiting and therefore resistant to partitioning oracle attacks based ([1] and [2]).

Blake3 being a PRF, it's output is indistinguishable from a random function and therefore can safely be used for generating the SIV.

We believe that using the Mac-then-Encrypt (MtE) is secure because we are not using a block cipher, so there is no padding
and so no padding oracle attack is possible.

We don't perform key separation between the cipher and the PRF because even though xchacha8 and blake3 are related in design, they are
seeded different compression IV constants which makes them domain separated.

We encode the associated data length in the tag/siv to prevent encoding ambiguities with the plaintext.
We do not encode the plaintext length because blake3 is secure to length extention.

We choose the lower round XChaCha8 instead of XChaCha20 based on [3] 

0: https://datatracker.ietf.org/doc/draft-madden-generalised-siv/
1: https://www.usenix.org/conference/usenixsecurity21/presentation/len
2: https://eprint.iacr.org/2020/1153
3: https://eprint.iacr.org/2019/1492

Pseudocode:

fn encrypt(key:256, iv:192, ad:*, plaintext:*) -> tag:256, ciphertext:*
  let tag:256 = blake3::keyed_hash(key:256, iv:192 + len(ad):64 + ad:* + plaintext:*)
  let siv:192 = tag[0..192]
  let ciphertext:* = xchacha8(key:256, siv:192, plaintext:*)


fn decrypt(key:256, iv:192, tag:256, ad:*, ciphertext:*)
  let siv:192 = tag[0..192]
  let plaintext:* = xchacha8(key:256, siv:192, ciphertext:*)
  let tag2 = blake3::keyed_hash(key:256, iv:192 + len(ad):64 + ad:* + plaintext:*)
  assert!(tag == tag2) // constant time

*/

use std::{convert::TryInto, marker::PhantomData};
use aead::{AeadInPlace, Error, NewAead, consts::{U0}, generic_array::GenericArray};
use c2_chacha::{XChaCha8, stream_cipher::{NewStreamCipher, StreamCipher}};
use crypto_mac::{Mac, NewMac};
use typenum::{U32, Unsigned};
use zeroize::Zeroize;

pub type XChaCha8Blake3Siv = AeadSiv<XChaCha8, blake3::Hasher>;

pub struct AeadSiv<C: NewStreamCipher, M> {
    key: GenericArray<u8, <C as NewStreamCipher>::KeySize>,
    _phantom: PhantomData<M>,
}

impl<C: NewStreamCipher, M> NewAead for AeadSiv<C, M>
where GenericArray<u8, <C as NewStreamCipher>::KeySize>: Copy {
    type KeySize = <C as NewStreamCipher>::KeySize;

    fn new(key: &GenericArray<u8, <C as NewStreamCipher>::KeySize>) -> Self {
        AeadSiv { key: *key, _phantom: PhantomData }
    }
}

impl<C: NewStreamCipher + StreamCipher, M: NewMac + Mac> AeadInPlace for AeadSiv<C, M> {
    type NonceSize = <C as NewStreamCipher>::NonceSize;
    type TagSize = <M as Mac>::OutputSize;
    type CiphertextOverhead = U0;

    fn encrypt_in_place_detached(
        &self,
        nonce: &GenericArray<u8, <C as NewStreamCipher>::NonceSize>,
        associated_data: &[u8],
        buffer: &mut [u8],
    ) -> Result<GenericArray<u8, Self::TagSize>, Error> {
        let mut hasher = <M as NewMac>::new(self.key.as_slice().try_into().unwrap());
        hasher.update(nonce);
        hasher.update(&(associated_data.len() as u64).to_le_bytes()); // little-endian
        hasher.update(associated_data);
        hasher.update(buffer);
        let tag  = hasher.finalize().into_bytes(); // consumes the Hash to avoid copying
        let siv = tag[0..Self::NonceSize::USIZE].into(); // constructs a reference to avoid copying
        <C as NewStreamCipher>::new(&self.key,siv).encrypt(buffer);
        Ok(tag)
    }

    fn decrypt_in_place_detached(
        &self,
        nonce: &GenericArray<u8, <C as NewStreamCipher>::NonceSize>,
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &GenericArray<u8, Self::TagSize>,
    ) -> Result<(), Error> {
        let siv  = tag[0..Self::NonceSize::USIZE].into(); // constructs a reference to avoid copying
        <C as NewStreamCipher>::new(&self.key,siv).decrypt(buffer);
        let mut hasher = <M as NewMac>::new(self.key.as_slice().try_into().unwrap());
        hasher.update(nonce);
        hasher.update(&(associated_data.len() as u64).to_le_bytes()); // little-endian
        hasher.update(associated_data);
        hasher.update(buffer);
        let mac = hasher.finalize().into_bytes();
        if subtle::ConstantTimeEq::ct_eq(mac.as_slice(), tag).unwrap_u8() == 1 { // constant time to avoid timing attack
            Ok(())
        } else {
            Err(Error)
        }
    }
}

impl<C: NewStreamCipher, M> Drop for AeadSiv<C, M> {
    fn drop(&mut self) {
        self.key.as_mut_slice().zeroize();
    }
}

pub struct Blake3StreamCipher {
    xof: blake3::OutputReader
}

impl NewStreamCipher for Blake3StreamCipher {
    type KeySize = U32;
    type NonceSize = U32;

    fn new(key: &c2_chacha::stream_cipher::Key<Self>, nonce: &c2_chacha::stream_cipher::Nonce<Self>) -> Self {
        Self {
            xof: blake3::Hasher::new_keyed(key.as_ref()).update(nonce).finalize_xof()
        }
    }
}

impl StreamCipher for Blake3StreamCipher {
    fn encrypt(&mut self, data: &mut [u8]) {
        self.xof.xor(data);
    }

    fn decrypt(&mut self, data: &mut [u8]) {
        self.xof.xor(data);
    }
}

#[cfg(test)]
mod tests {
    use aead::{AeadInPlace, Key, NewAead, Nonce};
    use crate::XChaCha8Blake3Siv;

    #[test]
    fn it_works() {
        let key = Key::<XChaCha8Blake3Siv>::from_slice(b"an example very very secret key."); // 32-bytes
        let cipher = XChaCha8Blake3Siv::new(key);
        let nonce = Nonce::from_slice(b"extra long unique nonce!"); // 24-bytes; unique per message
        let mut buffer = b"plaintext message".to_owned();

        let tag = cipher.encrypt_in_place_detached(nonce, b"associated data", &mut buffer)
            .expect("encryption failure!");  // NOTE: handle this error to avoid panics!
        cipher.decrypt_in_place_detached(nonce, b"associated data", &mut buffer, &tag)
            .expect("decryption failure!");  // NOTE: handle this error to avoid panics!
        
        assert_eq!(&buffer, b"plaintext message");
    }
}