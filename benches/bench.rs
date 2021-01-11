use aead::{AeadInPlace, Key, NewAead, Nonce};
use aes::{Aes128, Aes256};
use aes_gcm_siv::{Aes128GcmSiv, Aes256GcmSiv};
use aes_siv::{Aes128SivAead, Aes256SivAead};
use chacha20poly1305::{ChaChaPoly1305, XChaCha20Poly1305};
use cmac::Cmac;
use criterion::{BenchmarkId, Throughput};
use criterion::Criterion;
use criterion::{criterion_group, criterion_main};
use ctr::Ctr128;
use pmac::Pmac;
use rand::Rng;
use xchacha8blake3siv::{AeadSiv, Blake3StreamCipher};
use typenum::Unsigned;

const KB: usize = 1024;
const MB: usize = 1024 * KB;

fn bench_aead<A: NewAead + AeadInPlace>(c: &mut Criterion, name: &str) {
    let mut buffer = vec![0u8; MB];
    rand::thread_rng().fill(&mut buffer[..]);

    let key = Key::<A>::clone_from_slice(&buffer[0..<A as NewAead>::KeySize::USIZE]);
    let nonce = Nonce::clone_from_slice(&buffer[0..<A as AeadInPlace>::NonceSize::USIZE]);
    let associated_data = b"";
    let aead = <A as NewAead>::new(&key);

    let mut group = c.benchmark_group(name);
    for size in [1, 32, 128, KB, 8 * KB, 64 * KB, MB].iter() {
        group.throughput(Throughput::Bytes(*size as u64));

        group.bench_with_input(BenchmarkId::from_parameter(format!("{: >8}", size)), size, |b, &size| {
            b.iter(|| {
                let tag = aead.encrypt_in_place_detached(&nonce, associated_data, &mut buffer[0..size])
                .   expect("encryption failure!");
                aead.decrypt_in_place_detached(&nonce, associated_data, &mut buffer[0..size], &tag)
                    .expect("decryption failure!");
            });
        });
    }
    group.finish();
}

fn bench(c: &mut Criterion) {
    bench_aead::<XChaCha20Poly1305>(c, "XChaCha20Poly1305");
    bench_aead::<ChaChaPoly1305<c2_chacha::Ietf>>(c, "ChaChaPoly1305<c2_chacha::Ietf>");

    bench_aead::<Aes128GcmSiv>(c, "Aes128GcmSiv");
    bench_aead::<Aes256GcmSiv>(c, "Aes256GcmSiv");
    bench_aead::<Aes128SivAead>(c, "Aes128SivAead");
    bench_aead::<Aes256SivAead>(c, "Aes256SivAead");

    bench_aead::<AeadSiv<Ctr128<Aes128>, Cmac<Aes128>>>(c, "AeadSiv<Ctr128<Aes128>, Cmac<Aes128>>");
    bench_aead::<AeadSiv<Ctr128<Aes256>, Cmac<Aes256>>>(c, "AeadSiv<Ctr128<Aes256>, Cmac<Aes256>>");

    bench_aead::<AeadSiv<Ctr128<Aes128>, Pmac<Aes128>>>(c, "AeadSiv<Ctr128<Aes128>, Pmac<Aes128>>");
    bench_aead::<AeadSiv<Ctr128<Aes256>, Pmac<Aes256>>>(c, "AeadSiv<Ctr128<Aes256>, Pmac<Aes256>>");

    bench_aead::<AeadSiv<Ctr128<Aes256>, blake3::Hasher>>(c, "AeadSiv<Ctr128<Aes256>, blake3::Hasher>");

    bench_aead::<AeadSiv<c2_chacha::Ietf, blake3::Hasher>>(c, "AeadSiv<c2_chacha::Ietf, blake3::Hasher>");
    bench_aead::<AeadSiv<c2_chacha::ChaCha8, blake3::Hasher>>(c, "AeadSiv<c2_chacha::ChaCha8, blake3::Hasher>");
    bench_aead::<AeadSiv<c2_chacha::ChaCha12, blake3::Hasher>>(c, "AeadSiv<c2_chacha::ChaCha12, blake3::Hasher>");
    bench_aead::<AeadSiv<c2_chacha::ChaCha20, blake3::Hasher>>(c, "AeadSiv<c2_chacha::ChaCha20, blake3::Hasher>");
    bench_aead::<AeadSiv<c2_chacha::XChaCha8, blake3::Hasher>>(c, "AeadSiv<c2_chacha::XChaCha8, blake3::Hasher>");
    bench_aead::<AeadSiv<c2_chacha::XChaCha12, blake3::Hasher>>(c, "AeadSiv<c2_chacha::XChaCha12, blake3::Hasher>");
    bench_aead::<AeadSiv<c2_chacha::XChaCha20, blake3::Hasher>>(c, "AeadSiv<c2_chacha::XChaCha20, blake3::Hasher>");
    
    bench_aead::<AeadSiv<Blake3StreamCipher, blake3::Hasher>>(c, "AeadSiv<Blake3StreamCipher, blake3::Hasher>");
}

criterion_group!(benches, bench);
criterion_main!(benches);