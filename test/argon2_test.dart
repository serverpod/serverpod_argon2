import 'dart:convert';
import 'dart:typed_data';

import 'package:serverpod_argon2/serverpod_argon2.dart';
import 'package:test/test.dart';

String _hex(List<int> bytes) =>
    bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

void main() {
  late Argon2 argon2;

  setUpAll(() async {
    argon2 = await Argon2.load();
  });

  // RFC 9106 section 5.
  for (final (type, expected) in [
    (
      Argon2Type.argon2d,
      '512b391b6f1162975371d30919734294f868e3be3984f3c1a13a4db9fabe4acb',
    ),
    (
      Argon2Type.argon2i,
      'c814d9d1dc7f37aa13f0d77f2494bda1c8de6b016dd388d29952a4c4672b6ce8',
    ),
    (
      Argon2Type.argon2id,
      '0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659',
    ),
  ]) {
    test(
      'Given the RFC 9106 ${type.name} inputs with secret and associated data, '
      'when deriving a key, '
      'then the RFC 9106 tag is produced',
      () {
        final key = argon2.deriveKey(
          password: List.filled(32, 0x01),
          salt: List.filled(16, 0x02),
          secret: List.filled(8, 0x03),
          associatedData: List.filled(12, 0x04),
          parameters: Argon2Parameters(
            type: type,
            iterations: 3,
            memoryKiB: 32,
            parallelism: 4,
          ),
        );

        expect(_hex(key), expected);
      },
    );
  }

  // golang.org/x/crypto/argon2 vectors, covering several lane counts.
  for (final (type, iterations, memoryKiB, parallelism, expected) in [
    (
      Argon2Type.argon2id,
      1,
      64,
      1,
      '655ad15eac652dc59f7170a7332bf49b8469be1fdb9c28bb',
    ),
    (
      Argon2Type.argon2i,
      2,
      64,
      3,
      '5cab452fe6b8479c8661def8cd703b611a3905a6d5477fe6',
    ),
    (
      Argon2Type.argon2d,
      2,
      64,
      3,
      '22474a423bda2ccd36ec9afd5119e5c8949798cadf659f51',
    ),
    (
      Argon2Type.argon2id,
      3,
      256,
      6,
      '424436b6ee22a66b04b9d0cf78f190305c5c166bae8baa09',
    ),
    (
      Argon2Type.argon2id,
      4,
      256,
      8,
      'f22802f8ca47be93f9954e4ce20c1e944e938fbd4a125d9d',
    ),
  ]) {
    test(
      'Given password "password" and salt "somesalt" with ${type.name} t=$iterations m=$memoryKiB p=$parallelism, '
      'when deriving a 24 byte key, '
      'then the reference output is produced',
      () {
        final key = argon2.deriveKey(
          password: utf8.encode('password'),
          salt: utf8.encode('somesalt'),
          parameters: Argon2Parameters(
            type: type,
            iterations: iterations,
            memoryKiB: memoryKiB,
            parallelism: parallelism,
            hashLength: 24,
          ),
        );

        expect(_hex(key), expected);
      },
    );
  }

  test('Given a fixed salt and argon2id t=2 m=65536 p=1, '
      'when hashing "password", '
      'then the PHC string matches the reference implementation', () {
    final encoded = argon2.hash(
      'password',
      salt: utf8.encode('somesalt'),
      parameters: const Argon2Parameters(iterations: 2, memoryKiB: 65536),
    );

    expect(
      encoded,
      r'$argon2id$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$'
      'CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc',
    );
  });

  test('Given a reference implementation PHC string for "password", '
      'when verifying "password", '
      'then verification succeeds', () {
    const encoded =
        r'$argon2id$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$'
        'CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc';

    expect(argon2.verify('password', encoded), isTrue);
  });

  test(
    'Given default parameters, '
    'when hashing a password, '
    'then the PHC string records argon2id m=19456 t=2 p=1 with a 16 byte salt and 32 byte hash',
    () {
      final encoded = argon2.hash('correct horse');

      expect(
        encoded,
        matches(
          RegExp(
            r'^\$argon2id\$v=19\$m=19456,t=2,p=1'
            r'\$[A-Za-z0-9+/]{22}\$[A-Za-z0-9+/]{43}$',
          ),
        ),
      );
    },
  );

  test('Given the same password hashed twice, '
      'when comparing the PHC strings, '
      'then they differ because each hash gets a fresh salt', () {
    const parameters = Argon2Parameters(iterations: 1, memoryKiB: 64);

    final first = argon2.hash('password', parameters: parameters);
    final second = argon2.hash('password', parameters: parameters);

    expect(first, isNot(second));
  });

  test('Given a hash of "correct horse", '
      'when verifying "correct horse", '
      'then verification succeeds', () {
    final encoded = argon2.hash(
      'correct horse',
      parameters: const Argon2Parameters(iterations: 1, memoryKiB: 64),
    );

    expect(argon2.verify('correct horse', encoded), isTrue);
  });

  test('Given a hash of "correct horse", '
      'when verifying "battery staple", '
      'then verification fails', () {
    final encoded = argon2.hash(
      'correct horse',
      parameters: const Argon2Parameters(iterations: 1, memoryKiB: 64),
    );

    expect(argon2.verify('battery staple', encoded), isFalse);
  });

  test('Given a hash of a non-ASCII password, '
      'when verifying the same password, '
      'then verification succeeds', () {
    final encoded = argon2.hash(
      'pässwörd 🔑',
      parameters: const Argon2Parameters(iterations: 1, memoryKiB: 64),
    );

    expect(argon2.verify('pässwörd 🔑', encoded), isTrue);
  });

  test('Given a hash made with a secret, '
      'when verifying the right password without the secret, '
      'then verification fails', () {
    final encoded = argon2.hash(
      'password',
      secret: utf8.encode('pepper'),
      parameters: const Argon2Parameters(iterations: 1, memoryKiB: 64),
    );

    expect(argon2.verify('password', encoded), isFalse);
  });

  test('Given a hash made with a secret, '
      'when verifying the right password with the same secret, '
      'then verification succeeds', () {
    final encoded = argon2.hash(
      'password',
      secret: utf8.encode('pepper'),
      parameters: const Argon2Parameters(iterations: 1, memoryKiB: 64),
    );

    expect(
      argon2.verify('password', encoded, secret: utf8.encode('pepper')),
      isTrue,
    );
  });

  test('Given argon2i with a 48 byte hash length, '
      'when hashing and verifying the password, '
      'then the PHC string records argon2i and verification succeeds', () {
    final encoded = argon2.hash(
      'password',
      parameters: const Argon2Parameters(
        type: Argon2Type.argon2i,
        iterations: 1,
        memoryKiB: 64,
        hashLength: 48,
      ),
    );

    expect(encoded, startsWith(r'$argon2i$v=19$m=64,t=1,p=1$'));
    expect(argon2.verify('password', encoded), isTrue);
  });

  test('Given an empty password, '
      'when hashing and verifying it, '
      'then verification succeeds', () {
    final encoded = argon2.hash(
      '',
      parameters: const Argon2Parameters(iterations: 1, memoryKiB: 64),
    );

    expect(argon2.verify('', encoded), isTrue);
  });

  for (final (description, encoded) in [
    (
      'a bcrypt hash',
      r'$2b$12$abcdefghijklmnopqrstuuvwxyzABCDEFGHIJKLMNOPQRSTUVWX',
    ),
    ('an unknown type', r'$argon2x$v=19$m=64,t=1,p=1$c29tZXNhbHQ$AAAAAA'),
    ('version 16', r'$argon2id$v=16$m=64,t=1,p=1$c29tZXNhbHQ$AAAAAA'),
    ('a missing version', r'$argon2id$m=64,t=1,p=1$c29tZXNhbHQ$AAAAAA'),
    ('reordered costs', r'$argon2id$v=19$t=1,m=64,p=1$c29tZXNhbHQ$AAAAAA'),
    ('a zero cost', r'$argon2id$v=19$m=64,t=0,p=1$c29tZXNhbHQ$AAAAAA'),
    ('padded base64', r'$argon2id$v=19$m=64,t=1,p=1$c29tZXNhbHQ=$AAAAAA'),
    ('URL-safe base64', r'$argon2id$v=19$m=64,t=1,p=1$c29tZXNhbHQ$AA-_AA'),
    ('a trailing field', r'$argon2id$v=19$m=64,t=1,p=1$c29tZXNhbHQ$AAAAAA$'),
  ]) {
    test('Given a PHC string with $description, '
        'when verifying a password against it, '
        'then a FormatException is thrown', () {
      expect(
        () => argon2.verify('password', encoded),
        throwsA(isA<FormatException>()),
      );
    });
  }

  for (final (description, parameters) in [
    ('zero iterations', const Argon2Parameters(iterations: 0, memoryKiB: 64)),
    (
      'zero parallelism',
      const Argon2Parameters(iterations: 1, memoryKiB: 64, parallelism: 0),
    ),
    (
      'less than 8 KiB of memory per lane',
      const Argon2Parameters(iterations: 1, memoryKiB: 31, parallelism: 4),
    ),
    (
      'a 3 byte hash length',
      const Argon2Parameters(iterations: 1, memoryKiB: 64, hashLength: 3),
    ),
    (
      'a 7 byte salt length',
      const Argon2Parameters(iterations: 1, memoryKiB: 64, saltLength: 7),
    ),
  ]) {
    test('Given parameters with $description, '
        'when hashing a password, '
        'then a RangeError is thrown', () {
      expect(
        () => argon2.hash('password', parameters: parameters),
        throwsRangeError,
      );
    });
  }

  test('Given a 7 byte salt, '
      'when deriving a key, '
      'then a RangeError is thrown', () {
    expect(
      () => argon2.deriveKey(
        password: utf8.encode('password'),
        salt: Uint8List(7),
      ),
      throwsRangeError,
    );
  });

  test(
    'Given memory beyond what can be allocated, '
    'when deriving a key, '
    'then an Argon2Exception is thrown',
    () {
      expect(
        () => argon2.deriveKey(
          password: utf8.encode('password'),
          salt: utf8.encode('somesalt'),
          parameters: const Argon2Parameters(
            iterations: 1,
            memoryKiB: 0xffffffff,
          ),
        ),
        throwsA(isA<Argon2Exception>()),
      );
    },
    // Asks for 4 TiB, which a machine with overcommit may grant lazily.
    testOn: 'browser',
  );

  test('Given two loads, '
      'when comparing the instances, '
      'then the same instance is returned', () async {
    expect(await Argon2.load(), same(await Argon2.load()));
  });
}
