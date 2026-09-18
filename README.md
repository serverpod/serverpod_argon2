# serverpod_argon2

Argon2 password hashing for Dart and Flutter, backed by the Argon2
implementation in the Zig standard library.

- Native platforms load a prebuilt shared library through build hooks
  (native assets).
- The web loads the same code compiled to WebAssembly, embedded in the
  package. This works with both dart2js and dart2wasm.
- No toolchain is needed. Prebuilt libraries ship in the package for every
  supported target.

## Usage

```dart
import 'package:serverpod_argon2/serverpod_argon2.dart';

final argon2 = await Argon2.load();

// $argon2id$v=19$m=19456,t=2,p=1$<salt>$<hash>
final encoded = argon2.hash('correct horse battery staple');

final ok = argon2.verify('correct horse battery staple', encoded);
```

`hash` defaults to `Argon2Parameters.owasp` (argon2id, 19 MiB, 2 iterations)
and a random 16 byte salt. `verify` accepts PHC strings from any Argon2
implementation, as long as they use version 19. `deriveKey` returns raw bytes
and takes the optional RFC 9106 `secret` and `associatedData` inputs.

Hashing runs on the calling thread and is slow by design. On native
platforms, move it off the main isolate:

```dart
final encoded = await Isolate.run(() => argon2.hash(password));
```

### Parallelism

The library is built single-threaded, so the `p` lanes are computed one after
another. Hashes with `p > 1` are still correct and compatible with other
implementations, but take `p` times longer than a multithreaded
implementation would. For more throughput, hash on several isolates.

## Supported targets

| OS      | Architectures                             |
| ------- | ----------------------------------------- |
| macOS   | arm64 (11.0+), x64 (10.15+)               |
| iOS     | arm64 (13.0+), arm64 and x64 simulators   |
| Android | arm64, arm, x64                           |
| Linux   | x64, arm64, arm, riscv64                  |
| Windows | x64, arm64                                |
| Web     | Any browser with WebAssembly              |

The libraries are pure Zig and link no libc. On Linux they run on any glibc or
musl distribution.

## Performance

`benchmark/argon2_benchmark.dart` compares against the pure Dart
implementations in `pointycastle` and `cryptography`, after checking all three
produce identical output. The file header shows how to run it in each mode.
Results on an Intel Mac, argon2id with OWASP parameters, in ms per hash:

| Implementation   | Dart JIT | Dart AOT | JavaScript (Node) |
| ---------------- | -------- | -------- | ----------------- |
| serverpod_argon2 | 43       | 46       | 40                |
| cryptography     | 200      | 183      | 647               |
| pointycastle     | 307      | 274      | 5996              |

## Developing

A git checkout has no prebuilt libraries, so the build hook compiles from
source. That needs the zig version in `build.zig.zon` (`minimum_zig_version`), either installed
directly or through [anyzig](https://github.com/marler8997/anyzig).

- `zig build test` runs the RFC 9106 vectors against the Zig code.
- `dart test -p vm,chrome` runs the Dart tests natively and in the browser.

## Publishing

See [PUBLISH.md](PUBLISH.md).
