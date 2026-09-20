import 'dart:convert';
import 'dart:js_interop';
import 'dart:typed_data';

import 'argon2_module.dart';
import 'argon2_wasm.g.dart';

/// Loads the wasm module embedded in this package.
///
/// Asynchronous on purpose: browsers refuse to compile wasm modules over 4 KB
/// synchronously on the main thread.
Future<Argon2Module> loadArgon2Module() async {
  final source = await _instantiate(base64Decode(argon2WasmBase64).toJS).toDart;
  return _WebArgon2Module(source.instance.exports);
}

final class _WebArgon2Module implements Argon2Module {
  _WebArgon2Module(this._exports);

  final _Exports _exports;

  // wasm i32 results reach JS signed, so addresses past 2 GiB come back
  // negative.
  @override
  int alloc(int length) => _exports.alloc(length).toUnsigned(32);

  @override
  void free(int address, int length) {
    assert(
      address != 0,
      'serverpod_argon2_free takes a non-null pointer, even for length 0',
    );
    _exports.free(address, length);
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
  ) => _exports.kdf(
    mode,
    iterations,
    memoryKiB,
    parallelism,
    password,
    passwordLength,
    salt,
    saltLength,
    secret,
    secretLength,
    associatedData,
    associatedDataLength,
    out,
    outLength,
  );

  @override
  void write(int address, List<int> bytes) =>
      _bytes(address, bytes.length).setAll(0, bytes);

  @override
  Uint8List read(int address, int length) =>
      Uint8List.fromList(_bytes(address, length));

  // Growing the module's memory detaches earlier views, so every call reads
  // the buffer again.
  Uint8List _bytes(int address, int length) =>
      JSUint8Array(_exports.memory.buffer, address, length).toDart;
}

@JS('WebAssembly.instantiate')
external JSPromise<_InstantiatedSource> _instantiate(JSUint8Array bytes);

extension type _InstantiatedSource._(JSObject _) implements JSObject {
  external _Instance get instance;
}

extension type _Instance._(JSObject _) implements JSObject {
  external _Exports get exports;
}

extension type _Exports._(JSObject _) implements JSObject {
  external _Memory get memory;

  @JS('serverpod_argon2_alloc')
  external int alloc(int length);

  @JS('serverpod_argon2_free')
  external void free(int address, int length);

  @JS('serverpod_argon2_kdf')
  external int kdf(
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
}

extension type _Memory._(JSObject _) implements JSObject {
  external JSArrayBuffer get buffer;
}
