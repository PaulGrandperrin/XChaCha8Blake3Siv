use aead::{NewAead, AeadInPlace};
use chacha20poly1305::XChaCha20Poly1305;
use criterion::{BenchmarkId, Throughput};
use criterion::Criterion;
use criterion::{criterion_group, criterion_main};
use rand::Rng;
use xchacha20blake3siv::{Key, Nonce, XChaCha20Blake3Siv};


fn bench(c: &mut Criterion) {
    const KB: usize = 1024;

    let mut buffer = vec![0u8; 64 * KB];
    rand::thread_rng().fill(&mut buffer[..]);

    let key = Key::from_slice(b"an example very very secret key."); // 32-bytes
    let nonce = Nonce::from_slice(b"extra long unique nonce!"); // 24-bytes; unique per message
    let associated_data = b"";
    let cipher_xchacha20blake3siv = XChaCha20Blake3Siv::new(key);
    let cipher_xchacha20poly1305 = XChaCha20Poly1305::new(key);

    let mut group_xchacha20blake3siv = c.benchmark_group("xchacha20blake3siv");
    for size in [1, 32, 128, 4 * KB, 64 * KB].iter() {
        group_xchacha20blake3siv.throughput(Throughput::Bytes(*size as u64));

        group_xchacha20blake3siv.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            b.iter(|| {
                let tag = cipher_xchacha20blake3siv.encrypt_in_place_detached(nonce, associated_data, &mut buffer[0..size])
                .   expect("encryption failure!");
                cipher_xchacha20blake3siv.decrypt_in_place_detached(nonce, associated_data, &mut buffer[0..size], &tag)
                    .expect("decryption failure!");
            });
        });
    }
    group_xchacha20blake3siv.finish();

    let mut group_xchacha20poly1305 = c.benchmark_group("xchacha20poly1305");
    for size in [1, 32, 128, 4 * KB, 64 * KB].iter() {
        group_xchacha20poly1305.throughput(Throughput::Bytes(*size as u64));

        group_xchacha20poly1305.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            b.iter(|| {
                let tag = cipher_xchacha20poly1305.encrypt_in_place_detached(nonce, associated_data, &mut buffer[0..size])
                .   expect("encryption failure!");
                cipher_xchacha20poly1305.decrypt_in_place_detached(nonce, associated_data, &mut buffer[0..size], &tag)
                    .expect("decryption failure!");
            });
        });
    }
    group_xchacha20poly1305.finish();

}

criterion_group!(benches, bench);
criterion_main!(benches);