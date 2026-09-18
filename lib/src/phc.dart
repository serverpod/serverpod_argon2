import 'dart:convert';
import 'dart:typed_data';

import 'argon2.dart';

/// An Argon2 hash in the PHC string format used by the reference
/// implementation:
///
///     $argon2id$v=19$m=19456,t=2,p=1$<salt>$<hash>
///
/// Salt and hash are unpadded standard base64. Only version 19 (0x13) is
/// supported, which is the only version the Zig implementation computes.
final class PhcHash {
  /// Creates a hash from its decoded fields.
  const PhcHash({
    required this.type,
    required this.iterations,
    required this.memoryKiB,
    required this.parallelism,
    required this.salt,
    required this.hash,
  });

  static const _version = 19;

  /// The Argon2 variant, such as `argon2id`.
  final Argon2Type type;

  /// Number of passes over memory (`t`).
  final int iterations;

  /// Memory cost in KiB (`m`).
  final int memoryKiB;

  /// Number of lanes (`p`).
  final int parallelism;

  /// The decoded salt.
  final Uint8List salt;

  /// The decoded hash.
  final Uint8List hash;

  /// The PHC string for this hash, which [decode] reads back.
  String encode() =>
      '\$${type.name}\$v=$_version'
      '\$m=$memoryKiB,t=$iterations,p=$parallelism'
      '\$${_encodeBase64(salt)}\$${_encodeBase64(hash)}';

  /// Throws a [FormatException] for anything but a well-formed version 19
  /// Argon2 hash.
  ///
  /// It does not check the costs against the ranges Argon2 accepts.
  /// [Argon2.verify] does.
  static PhcHash decode(String encoded) {
    FormatException invalid(String reason) =>
        FormatException('Invalid Argon2 hash: $reason', encoded);

    final fields = encoded.split(r'$');
    // A leading '$' yields an empty first field.
    if (fields.length != 6 || fields[0].isNotEmpty) {
      throw invalid(r'expected $type$v=19$m=..,t=..,p=..$salt$hash');
    }
    final [_, typeName, version, costs, salt, hash] = fields;

    final type = Argon2Type.values.asNameMap()[typeName];
    if (type == null) throw invalid('unknown type "$typeName"');
    if (version != 'v=$_version') {
      throw invalid('unsupported version "$version"');
    }

    final costMatch = _costs.firstMatch(costs);
    if (costMatch == null) throw invalid('expected m=..,t=..,p=..');
    final [memoryKiB, iterations, parallelism] = [
      for (var i = 1; i <= 3; i++) int.parse(costMatch.group(i)!),
    ];

    return PhcHash(
      type: type,
      iterations: iterations,
      memoryKiB: memoryKiB,
      parallelism: parallelism,
      salt: _decodeBase64(salt, invalid),
      hash: _decodeBase64(hash, invalid),
    );
  }

  /// Decimal without leading zeros, as the reference implementation writes
  /// them. Each cap allows the digits of the largest value Argon2 accepts.
  static final _costs = RegExp(
    r'^m=([1-9][0-9]{0,9}),t=([1-9][0-9]{0,9}),p=([1-9][0-9]{0,7})$',
  );
}

String _encodeBase64(List<int> bytes) =>
    base64.encode(bytes).replaceAll('=', '');

final _unpaddedBase64 = RegExp(r'^[A-Za-z0-9+/]+$');

Uint8List _decodeBase64(
  String value,
  FormatException Function(String reason) invalid,
) {
  // A length of 1 mod 4 cannot come from any byte count.
  if (!_unpaddedBase64.hasMatch(value) || value.length % 4 == 1) {
    throw invalid('"$value" is not unpadded base64');
  }
  return base64.decode(base64.normalize(value));
}
