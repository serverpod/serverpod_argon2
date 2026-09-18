import 'argon2_module.dart';

/// Throws an [UnsupportedError], since this platform has neither `dart:ffi`
/// nor a browser.
Future<Argon2Module> loadArgon2Module() =>
    throw UnsupportedError('serverpod_argon2 needs dart:ffi or a browser.');
