@DefaultAsset('package:serverpod_argon2/serverpod_argon2.dart')
library;

import 'dart:ffi';
import 'dart:typed_data';

import '../argon2.dart';
import 'argon2_module.dart';

/// Loads the native library bundled by the build hook.
Future<Argon2Module> loadArgon2Module() async {
  // Resolves the bundled library now, so a missing asset fails here rather
  // than on first use.
  final probe = _alloc(1);
  if (probe == nullptr) throw const Argon2Exception('Out of memory.');
  _free(probe, 1);
  return const _NativeArgon2Module();
}

final class _NativeArgon2Module implements Argon2Module {
  const _NativeArgon2Module();

  @override
  int alloc(int length) => _alloc(length).address;

  @override
  void free(int address, int length) {
    assert(
      address != 0,
      'serverpod_argon2_free takes a non-null pointer, even for length 0',
    );
    _free(Pointer.fromAddress(address), length);
  }

  @override
  int kdf(
    int mode,
    int iterations,
    int memoryKiB,
    int parallelism,
    int password,
    int passwordLength,
    int salt,
    int saltLength,
    int secret,
    int secretLength,
    int associatedData,
    int associatedDataLength,
    int out,
    int outLength,
  ) => _kdf(
    mode,
    iterations,
    memoryKiB,
    parallelism,
    Pointer.fromAddress(password),
    passwordLength,
    Pointer.fromAddress(salt),
    saltLength,
    Pointer.fromAddress(secret),
    secretLength,
    Pointer.fromAddress(associatedData),
    associatedDataLength,
    Pointer.fromAddress(out),
    outLength,
  );

  @override
  void write(int address, List<int> bytes) =>
      _bytes(address, bytes.length).setAll(0, bytes);

  @override
  Uint8List read(int address, int length) =>
      Uint8List.fromList(_bytes(address, length));

  Uint8List _bytes(int address, int length) =>
      Pointer<Uint8>.fromAddress(address).asTypedList(length);
}

@Native<Pointer<Uint8> Function(Size)>(
  symbol: 'serverpod_argon2_alloc',
  isLeaf: true,
)
external Pointer<Uint8> _alloc(int length);

@Native<Void Function(Pointer<Uint8>, Size)>(
  symbol: 'serverpod_argon2_free',
  isLeaf: true,
)
external void _free(Pointer<Uint8> address, int length);

// Not a leaf call: hashing is deliberately slow, and a leaf call would hold
// off garbage collection for every isolate in the group meanwhile.
@Native<
  Int32 Function(
    Uint32,
    Uint32,
    Uint32,
    Uint32,
    Pointer<Uint8>,
    Size,
    Pointer<Uint8>,
    Size,
    Pointer<Uint8>,
    Size,
    Pointer<Uint8>,
    Size,
    Pointer<Uint8>,
    Size,
  )
>(symbol: 'serverpod_argon2_kdf')
external int _kdf(
  int mode,
  int iterations,
  int memoryKiB,
  int parallelism,
  Pointer<Uint8> password,
  int passwordLength,
  Pointer<Uint8> salt,
  int saltLength,
  Pointer<Uint8> secret,
  int secretLength,
  Pointer<Uint8> associatedData,
  int associatedDataLength,
  Pointer<Uint8> out,
  int outLength,
);
