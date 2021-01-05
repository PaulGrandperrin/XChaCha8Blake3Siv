

```sh
RUSTFLAGS="-Ctarget-cpu=native" cargo bench --bench bench -- --sample-size 1000 --measurement-time 5 --warm-up-time 1
critcmp new -g '\w+/(.+)$'
```

```
group       new/chacha20poly1305/                   new/xchacha8blake3siv/
-----       ---------------------                   ----------------------
       1    1.83    794.0±67.32ns  1230.0 KB/sec    1.00   434.4±71.25ns     2.2 MB/sec
      32    1.93    824.2±72.08ns    37.0 MB/sec    1.00   426.5±54.46ns    71.5 MB/sec
     128    1.45  1118.9±105.82ns   109.1 MB/sec    1.00   769.3±88.38ns   158.7 MB/sec
    4096    1.00       8.0±0.89µs   490.2 MB/sec    1.21      9.6±6.33µs   405.6 MB/sec
   65536    1.41     114.7±7.53µs   544.8 MB/sec    1.00     81.1±5.83µs   770.5 MB/sec
 1048576    1.51  1836.5±122.06µs   544.5 MB/sec    1.00  1220.1±93.47µs   819.6 MB/sec
```

```sh
cargo flamegraph --bench bench --  --bench -n --profile-time 10 xchacha8blake3siv
```

