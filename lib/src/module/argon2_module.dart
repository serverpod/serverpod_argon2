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

  /// A live view of module memory. On wasm, memory growth detaches earlier
  /// views, so use the view before the next [alloc] or [kdf].
  Uint8List view(int address, int length);
}
