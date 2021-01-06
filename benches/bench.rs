use aead::{AeadInPlace, Key, NewAead, Nonce};
use chacha20poly1305::ChaChaPoly1305;
use criterion::{BenchmarkId, Throughput};
use criterion::Criterion;
use criterion::{criterion_group, criterion_main};
use rand::Rng;
use xchacha8blake3siv::XChaCha8Blake3Siv;


fn bench(c: &mut Criterion) {
    const KB: usize = 1024;

    let mut buffer = vec![0u8; 1024 * KB];
    rand::thread_rng().fill(&mut buffer[..]);

    let key = Key::<XChaCha8Blake3Siv>::from_slice(b"an example very very secret key."); // 32-bytes
    let nonce12 = Nonce::from_slice(b"unique nonce"); // 12-bytes; unique per message
    let nonce24 = Nonce::from_slice(b"extra long unique nonce!"); // 24-bytes; unique per message
    let associated_data = b"";
    let cipher_xchacha8blake3siv = XChaCha8Blake3Siv::new(key);
    let cipher_chacha20poly1305 = ChaChaPoly1305::<c2_chacha::Ietf>::new(key.into());

    let mut group_xchacha8blake3siv = c.benchmark_group("xchacha8blake3siv");
    for size in [1, 32, 128, 4 * KB, 64 * KB, 1024 * KB].iter() {
        group_xchacha8blake3siv.throughput(Throughput::Bytes(*size as u64));

        group_xchacha8blake3siv.bench_with_input(BenchmarkId::from_parameter(format!("{: >8}", size)), size, |b, &size| {
            b.iter(|| {
                let tag = cipher_xchacha8blake3siv.encrypt_in_place_detached(nonce24, associated_data, &mut buffer[0..size])
                .   expect("encryption failure!");
                cipher_xchacha8blake3siv.decrypt_in_place_detached(nonce24, associated_data, &mut buffer[0..size], &tag)
                    .expect("decryption failure!");
            });
        });
    }
    group_xchacha8blake3siv.finish();

    let mut group_chacha20poly1305 = c.benchmark_group("chacha20poly1305");
    for size in [1, 32, 128, 4 * KB, 64 * KB, 1024 * KB].iter() {
        group_chacha20poly1305.throughput(Throughput::Bytes(*size as u64));

        group_chacha20poly1305.bench_with_input(BenchmarkId::from_parameter(format!("{: >8}", size)), size, |b, &size| {
            b.iter(|| {
                let tag = cipher_chacha20poly1305.encrypt_in_place_detached(nonce12, associated_data, &mut buffer[0..size])
                .   expect("encryption failure!");
                cipher_chacha20poly1305.decrypt_in_place_detached(nonce12, associated_data, &mut buffer[0..size], &tag)
                    .expect("decryption failure!");
            });
        });
    }
    group_chacha20poly1305.finish();

}

criterion_group!(benches, bench);
criterion_main!(benches);