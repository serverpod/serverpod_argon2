import 'dart:typed_data';

/// The C ABI of `src/argon2.zig`, loaded as a native library or as a wasm
/// module. Addresses are plain integers so both can share the marshalling in
/// `Argon2`.
abstract interface class Argon2Module {
  /// Allocates [length] bytes in the module's memory. Returns 0 on failure.
  int alloc(int length);

  /// Zeroes and frees memory from [alloc].
  void free(int address, int length);

  /// Returns an `Argon2Status` code.
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
  );

  /// Copies [bytes] into module memory at [address].
  void write(int address, List<int> bytes);

  /// Copies [length] bytes of module memory at [address] into the Dart heap.
  Uint8List read(int address, int length);
}
