// ignore_for_file: avoid_print

// Compares serverpod_argon2 with the pure Dart Argon2 implementations in
// package:pointycastle and package:cryptography. package:crypto has no
// Argon2.
//
// Native, JIT:
//   dart run benchmark/argon2_benchmark.dart
//
// Native, AOT. dart build cli runs the build hook and bundles the library,
// which dart compile exe does not:
//   dart build cli -t benchmark/argon2_benchmark.dart -o /tmp/bench
//   /tmp/bench/bundle/bin/argon2_benchmark
//
// JavaScript, which loads the wasm module through Node's WebAssembly:
//   dart compile js -O2 -o /tmp/bench.js benchmark/argon2_benchmark.dart
//   node -e 'globalThis.self = globalThis; require("/tmp/bench.js")'
import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart' as cryptography;
import 'package:cryptography/dart.dart' as cryptography;
import 'package:pointycastle/export.dart' as pointycastle;
import 'package:serverpod_argon2/serverpod_argon2.dart';

typedef _Hasher = Future<List<int>> Function();

Future<void> main() async {
  final argon2 = await Argon2.load();
  final password = utf8.encode('correct horse battery staple');
  final salt = utf8.encode('0123456789abcdef');

  for (final (name, iterations, memoryKiB) in [
    ('OWASP argon2id', 2, 19 * 1024),
    ('libsodium interactive argon2id', 2, 64 * 1024),
  ]) {
    print('$name (t=$iterations, m=$memoryKiB KiB, p=1, 32 byte hash)');

    final hashers = <String, _Hasher>{
      'serverpod_argon2': () async => argon2.deriveKey(
        password: password,
        salt: salt,
        parameters: Argon2Parameters(
          iterations: iterations,
          memoryKiB: memoryKiB,
        ),
      ),
      'pointycastle': () async {
        final generator = pointycastle.Argon2BytesGenerator()
          ..init(
            pointycastle.Argon2Parameters(
              pointycastle.Argon2Parameters.ARGON2_id,
              Uint8List.fromList(salt),
              desiredKeyLength: 32,
              iterations: iterations,
              memory: memoryKiB,
            ),
          );
        return generator.process(Uint8List.fromList(password));
      },
      'cryptography': () async {
        final key = await cryptography.DartArgon2id(
          parallelism: 1,
          memory: memoryKiB,
          iterations: iterations,
          hashLength: 32,
        ).deriveKey(secretKey: cryptography.SecretKey(password), nonce: salt);
        return key.extractBytes();
      },
    };

    final reference = await hashers['serverpod_argon2']!();
    for (final MapEntry(key: library, value: hasher) in hashers.entries) {
      final output = await hasher();
      if (!_equals(output, reference)) {
        throw StateError('$library disagrees with serverpod_argon2.');
      }
    }

    final timings = {
      for (final MapEntry(key: library, value: hasher) in hashers.entries)
        library: await _measure(hasher),
    };
    final baseline = timings['serverpod_argon2']!;
    for (final MapEntry(key: library, value: micros) in timings.entries) {
      final ms = (micros / 1000).toStringAsFixed(1).padLeft(9);
      final ratio = (micros / baseline).toStringAsFixed(1).padLeft(6);
      print('  ${library.padRight(18)}$ms ms/hash ${ratio}x');
    }
  }
}

/// Mean microseconds per hash, over at least 3 runs and about 2 seconds,
/// after one warm-up run.
Future<double> _measure(_Hasher hasher) async {
  await hasher();
  final stopwatch = Stopwatch()..start();
  var runs = 0;
  while (runs < 3 || stopwatch.elapsedMilliseconds < 2000) {
    await hasher();
    runs++;
  }
  return stopwatch.elapsedMicroseconds / runs;
}

bool _equals(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}
