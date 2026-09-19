import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'module/argon2_module.dart';
import 'module/load.dart';
import 'phc.dart';

/// The Argon2 variant.
enum Argon2Type {
  /// Data-dependent memory access. Fastest and most resistant to GPU
  /// cracking, but open to side-channel timing attacks.
  argon2d,

  /// Data-independent memory access, resistant to side-channel attacks.
  argon2i,

  /// A hybrid of the two, and the recommended choice for password hashing.
  argon2id,
}

/// Cost and output parameters for Argon2.
final class Argon2Parameters {
  /// Creates parameters without checking them. [Argon2.hash] and
  /// [Argon2.deriveKey] throw a [RangeError] for values Argon2 does not
  /// accept.
  const Argon2Parameters({
    this.type = Argon2Type.argon2id,
    required this.iterations,
    required this.memoryKiB,
    this.parallelism = 1,
    this.hashLength = 32,
    this.saltLength = 16,
  });

  /// argon2id with 19 MiB of memory and 2 iterations, as recommended by the
  /// OWASP Password Storage Cheat Sheet.
  static const owasp = Argon2Parameters(iterations: 2, memoryKiB: 19 * 1024);

  /// The Argon2 variant to compute.
  final Argon2Type type;

  /// Number of passes over memory (`t`). At least 1.
  final int iterations;

  /// Memory cost in KiB (`m`). At least 8 * [parallelism].
  final int memoryKiB;

  /// Number of lanes (`p`). Lanes are computed one after another, so a higher
  /// value adds cost rather than using more cores.
  final int parallelism;

  /// Length of the derived hash in bytes. At least 4.
  final int hashLength;

  /// Length of the random salt [Argon2.hash] generates. At least 8.
  final int saltLength;

  void _validate() {
    _checkRange(iterations, 1, _maxUint32, 'iterations');
    _checkRange(parallelism, 1, _maxUint24, 'parallelism');
    _checkRange(memoryKiB, 8 * parallelism, _maxUint32, 'memoryKiB');
    _checkRange(hashLength, 4, _maxUint32, 'hashLength');
    _checkRange(saltLength, 8, _maxUint32, 'saltLength');
  }
}

const _maxUint24 = 0xffffff;
const _maxUint32 = 0xffffffff;

void _checkRange(int value, int min, int max, String name) =>
    RangeError.checkValueInInterval(value, min, max, name);

/// Thrown when the Argon2 computation itself fails, for example when the
/// requested memory cannot be allocated.
final class Argon2Exception implements Exception {
  /// Creates an exception with [message].
  const Argon2Exception(this.message);

  /// What failed.
  final String message;

  @override
  String toString() => 'Argon2Exception: $message';
}

/// Argon2 password hashing and key derivation.
///
/// Obtain an instance with [load]. Hashing is deliberately slow and runs on
/// the calling thread. On native platforms, run it on another isolate to keep
/// the caller responsive, for example with `Isolate.run`.
final class Argon2 {
  Argon2._(this._module);

  final Argon2Module _module;

  static Future<Argon2>? _loading;

  /// Loads the native library, or on the web the wasm module. Repeated calls
  /// return the same instance.
  static Future<Argon2> load() => _loading ??= loadArgon2Module().then(
    Argon2._,
    onError: (Object error, StackTrace stackTrace) {
      _loading = null;
      Error.throwWithStackTrace(error, stackTrace);
    },
  );

  /// Hashes [password] with a random salt and returns a PHC string such as
  /// `$argon2id$v=19$m=19456,t=2,p=1$<salt>$<hash>`, which records everything
  /// [verify] needs except [secret].
  ///
  /// [secret] is an optional key (a "pepper") folded into the hash. It is
  /// not stored in the result, and [verify] must be given the same one.
  ///
  /// [salt] replaces the random salt. Only fix it for tests or when
  /// reproducing a known hash.
  String hash(
    String password, {
    Argon2Parameters parameters = Argon2Parameters.owasp,
    List<int>? secret,
    List<int>? salt,
  }) {
    parameters._validate();
    final saltBytes = salt ?? _randomBytes(parameters.saltLength);
    final hash = deriveKey(
      password: utf8.encode(password),
      salt: saltBytes,
      parameters: parameters,
      secret: secret,
    );
    return PhcHash(
      type: parameters.type,
      iterations: parameters.iterations,
      memoryKiB: parameters.memoryKiB,
      parallelism: parameters.parallelism,
      salt: Uint8List.fromList(saltBytes),
      hash: hash,
    ).encode();
  }

  /// Whether [password] matches [encodedHash], a PHC string from [hash] or
  /// any other Argon2 implementation.
  ///
  /// Throws a [FormatException] when [encodedHash] is not a valid version 19
  /// Argon2 PHC string.
  ///
  /// [encodedHash] sets the memory and time cost, up to 4 TiB and about
  /// 4 billion passes. Only verify hashes from a store you trust. Throws an
  /// [Argon2Exception] when the memory cannot be allocated.
  bool verify(String password, String encodedHash, {List<int>? secret}) {
    final expected = PhcHash.decode(encodedHash);
    final parameters = Argon2Parameters(
      type: expected.type,
      iterations: expected.iterations,
      memoryKiB: expected.memoryKiB,
      parallelism: expected.parallelism,
      hashLength: expected.hash.length,
    );
    // Well-formed, but outside what Argon2 accepts, so still not a valid
    // Argon2 hash.
    try {
      parameters._validate();
      _checkRange(expected.salt.length, 8, _maxUint32, 'salt length');
    } on RangeError catch (error) {
      throw FormatException('Invalid Argon2 hash: $error', encodedHash);
    }

    final actual = deriveKey(
      password: utf8.encode(password),
      salt: expected.salt,
      parameters: parameters,
      secret: secret,
    );
    return _constantTimeEquals(actual, expected.hash);
  }

  /// Derives [Argon2Parameters.hashLength] bytes from [password] and [salt].
  ///
  /// [secret] and [associatedData] are the optional Argon2 inputs `K` and
  /// `X` from RFC 9106.
  Uint8List deriveKey({
    required List<int> password,
    required List<int> salt,
    Argon2Parameters parameters = Argon2Parameters.owasp,
    List<int>? secret,
    List<int>? associatedData,
  }) {
    parameters._validate();
    _checkRange(salt.length, 8, _maxUint32, 'salt.length');

    final buffers = _Buffers(_module);
    try {
      final passwordBuffer = buffers.copy(password);
      final saltBuffer = buffers.copy(salt);
      final secretBuffer = buffers.copy(secret ?? const []);
      final adBuffer = buffers.copy(associatedData ?? const []);
      final out = buffers.allocate(parameters.hashLength);

      final status = _module.kdf(
        parameters.type.index,
        parameters.iterations,
        parameters.memoryKiB,
        parameters.parallelism,
        passwordBuffer.address,
        passwordBuffer.length,
        saltBuffer.address,
        saltBuffer.length,
        secretBuffer.address,
        secretBuffer.length,
        adBuffer.address,
        adBuffer.length,
        out.address,
        out.length,
      );
      if (status != 0) throw Argon2Exception(_describeStatus(status));

      return Uint8List.fromList(_module.view(out.address, out.length));
    } finally {
      buffers.freeAll();
    }
  }
}

/// Mirrors `Status` in src/argon2.zig.
String _describeStatus(int status) => switch (status) {
  1 => 'Parameters are below the Argon2 minimums.',
  2 => 'Requested hash length is too long.',
  3 => 'Out of memory.',
  4 => 'Unknown Argon2 type.',
  _ => 'Unexpected failure (status $status).',
};

final _random = Random.secure();

Uint8List _randomBytes(int length) {
  final bytes = Uint8List(length);
  for (var i = 0; i < length; i++) {
    bytes[i] = _random.nextInt(256);
  }
  return bytes;
}

bool _constantTimeEquals(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  var difference = 0;
  for (var i = 0; i < a.length; i++) {
    difference |= a[i] ^ b[i];
  }
  return difference == 0;
}

typedef _Buffer = ({int address, int length});

/// Module allocations for one call, zeroed and freed together.
final class _Buffers {
  _Buffers(this._module);

  final Argon2Module _module;
  final _allocated = <_Buffer>[];

  /// An empty input needs no memory, and the module accepts address 0 with
  /// length 0.
  _Buffer copy(List<int> bytes) {
    if (bytes.isEmpty) return (address: 0, length: 0);
    final buffer = allocate(bytes.length);
    _module.view(buffer.address, buffer.length).setAll(0, bytes);
    return buffer;
  }

  _Buffer allocate(int length) {
    final address = _module.alloc(length);
    if (address == 0) throw const Argon2Exception('Out of memory.');
    final buffer = (address: address, length: length);
    _allocated.add(buffer);
    return buffer;
  }

  void freeAll() {
    for (final buffer in _allocated) {
      _module.free(buffer.address, buffer.length);
    }
    _allocated.clear();
  }
}
