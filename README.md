# boring — Dart Crypto Benchmark Suite

Benchmarks a broad range of Dart cryptographic libraries, with a focus on comparing
hardware-accelerated OpenSSL (AES-NI, SHA-NI) against pure-software implementations.

## Benchmarks

### `bin/speedtest.dart` — full comparison suite

Runs SHA-256, AES-256-CTR, and ChaCha20 across every major Dart crypto library:

| Library | Approach |
|---|---|
| `package:crypto` | Pure Dart software |
| `package:better_cryptography` | Pure Dart, optimised |
| `package:webcrypto` (BoringSSL) | async FFI via Flutter's bundled BoringSSL |
| `package:encrypt` + PointyCastle | Pure Dart |
| `package:fastcrypt` | Rust via FFI |
| `package:sodium` (libsodium) | Native FFI, runtime-loaded |
| OpenSSL FFI (system libcrypto) | Native FFI, hardware-accelerated |
| `package:openssl` (bundled) | Native Assets, no-asm build |

### `bin/opensslbench.dart` — standalone OpenSSL benchmark

Focused comparison of three OpenSSL delivery mechanisms for SHA-256, AES-256-CTR,
and ChaCha20. Designed to run on any hardware to measure accelerator impact:

| Implementation | Description |
|---|---|
| FFI hw-accel | System `libcrypto` — uses AES-NI / SHA-NI where available |
| Pkg naive | `package:openssl` bundled binary, Arena-per-call allocation |
| Pkg opt | `package:openssl` bundled binary, persistent EVP contexts |

The bundled OpenSSL is compiled with `no-asm`, so it always runs in software.
Comparing FFI vs Pkg directly shows how much hardware acceleration is worth on
your specific CPU.

## Results (example — Intel x86_64 with AES-NI + SHA-NI)

```
CPU hw-accel : aes, sha_ni, avx2

┌──────────────────────────────────┬─────────────┬───────────────┐
│ Implementation                   │   Time (ms) │  Speed (mbps) │
├──────────────────────────────────┼─────────────┼───────────────┤
│ FFI  SHA-256 (hw-accel)          │           5 │         16777 │
│ Pkg  SHA-256 naive               │          28 │          2996 │
│ Pkg  SHA-256 opt                 │          27 │          3107 │
├──────────────────────────────────┼─────────────┼───────────────┤
│ FFI  AES-256-CTR (hw-accel)      │          18 │          4660 │
│ Pkg  AES-256-CTR naive           │         106 │           791 │
│ Pkg  AES-256-CTR opt             │         105 │           799 │
├──────────────────────────────────┼─────────────┼───────────────┤
│ FFI  ChaCha20 (hw-accel)         │          23 │          3647 │
│ Pkg  ChaCha20 naive              │          46 │          1824 │
│ Pkg  ChaCha20 opt                │          46 │          1824 │
└──────────────────────────────────┴─────────────┴───────────────┘
```

AES-NI gives ~6× on AES-256-CTR. SHA-NI gives ~5.5× on SHA-256.
ChaCha20 has no dedicated instruction set extension so the gap is smaller (~2×).

## Dependencies

The `openssl` pub package uses Dart Native Assets — it downloads and compiles
OpenSSL 3.5.4 from source at build time. This requires:

- `perl` (macOS/Linux)
- `make` (macOS/Linux)
- `cmake`, `clang`, `llvm`, `nasm` (Windows — see below)

The `webcrypto` package requires a one-time setup step that builds BoringSSL:

```
dart pub run webcrypto:setup
```

**macOS / Linux:** ensure `clang` and `cmake` are installed.

**Windows:** install via [Chocolatey](https://chocolatey.org/):

```powershell
choco install cmake
choco install clang
choco install llvm
choco install nasm
```

Then run `dart pub run webcrypto:setup`.

The `sodium` tests require `libsodium` at runtime:

```
# Ubuntu/Debian
sudo apt-get install libsodium23

# macOS
brew install libsodium
```

## Running

```bash
dart pub get

# Full suite: <size MB> <repeat>
dart run bin/speedtest.dart 1 10

# OpenSSL-only benchmark
dart run bin/opensslbench.dart 1 10
```

## Building native binaries

`opensslbench` uses Native Assets so it requires `dart build cli` rather than
`dart compile exe`:

```bash
# Full suite
dart build cli -t bin/speedtest.dart

# OpenSSL benchmark (recommended for cross-hardware comparison)
dart build cli -t bin/opensslbench.dart -o build/opensslbench
```

Output is a bundle — copy the whole directory to the target machine:

```
build/opensslbench/bundle/
  bin/opensslbench    # AOT binary
  lib/libcrypto.so    # bundled no-asm OpenSSL (loaded automatically)
```

Run on the target:

```bash
./build/opensslbench/bundle/bin/opensslbench 1 20
```

## Library notes

### OpenSSL FFI (lib/src/openssl_ffi.dart)

Hand-crafted FFI bindings using `dart:ffi` + `DynamicLibrary.open()`. Loads the
system `libcrypto` at runtime. Persistent EVP contexts and pre-allocated I/O
buffers mean zero heap allocation in the hot path.

### OpenSSL pkg (lib/src/openssl_pkg.dart)

Two patterns using the `openssl` pub package (Native Assets, build-time compiled):

- **Naive**: `using((arena) {...})` — fresh Arena per call, idiomatic but slower
- **Optimised**: `OpenSslPkgCrypto` — same persistent-context strategy as the FFI class

At identical settings both hit the same C symbols, so any throughput difference
reflects Dart-side allocation overhead rather than crypto speed.

### Timing accuracy

All timing uses `Stopwatch` (nanosecond-resolution CPU counter). `DateTime.now()`
has ~1 ms granularity which inflates results for fast operations like SHA-256
(~0.4 ms/iter rounds to 1 ms → 2× apparent speedup).
