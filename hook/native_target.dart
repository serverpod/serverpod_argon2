import 'dart:io';

import 'package:code_assets/code_assets.dart';

/// A target the package ships a prebuilt library for. Shared by
/// `hook/build.dart`, which picks the library for the target being built, and
/// `tool/build_binaries.dart`, which builds all of them before publishing.
final class NativeTarget {
  const NativeTarget._(
    this.os,
    this.architecture,
    this.zigTriple, {
    this.iOSSdk,
  });

  final OS os;
  final Architecture architecture;

  /// Only set for iOS, where device and simulator need separate libraries.
  final IOSSdk? iOSSdk;

  /// The `-Dtarget` passed to `zig build`. Apple triples carry the minimum
  /// OS version, matching Flutter's deployment targets.
  final String zigTriple;

  static final all = [
    const NativeTarget._(OS.macOS, Architecture.arm64, 'aarch64-macos.11.0'),
    const NativeTarget._(OS.macOS, Architecture.x64, 'x86_64-macos.10.15'),
    const NativeTarget._(OS.linux, Architecture.x64, 'x86_64-linux-gnu'),
    const NativeTarget._(OS.linux, Architecture.arm64, 'aarch64-linux-gnu'),
    const NativeTarget._(OS.linux, Architecture.arm, 'arm-linux-gnueabihf'),
    const NativeTarget._(OS.linux, Architecture.riscv64, 'riscv64-linux-gnu'),
    const NativeTarget._(OS.windows, Architecture.x64, 'x86_64-windows-gnu'),
    const NativeTarget._(OS.windows, Architecture.arm64, 'aarch64-windows-gnu'),
    const NativeTarget._(
      OS.android,
      Architecture.arm64,
      'aarch64-linux-android',
    ),
    const NativeTarget._(OS.android, Architecture.arm, 'arm-linux-androideabi'),
    const NativeTarget._(OS.android, Architecture.x64, 'x86_64-linux-android'),
    const NativeTarget._(
      OS.iOS,
      Architecture.arm64,
      'aarch64-ios.13.0',
      iOSSdk: IOSSdk.iPhoneOS,
    ),
    const NativeTarget._(
      OS.iOS,
      Architecture.arm64,
      'aarch64-ios.13.0-simulator',
      iOSSdk: IOSSdk.iPhoneSimulator,
    ),
    const NativeTarget._(
      OS.iOS,
      Architecture.x64,
      'x86_64-ios.13.0-simulator',
      iOSSdk: IOSSdk.iPhoneSimulator,
    ),
  ];

  /// The target matching [code], or null when none is supported.
  static NativeTarget? of(CodeConfig code) {
    final sdk = code.targetOS == OS.iOS ? code.iOS.targetSdk : null;
    for (final target in all) {
      if (target.os == code.targetOS &&
          target.architecture == code.targetArchitecture &&
          target.iOSSdk == sdk) {
        return target;
      }
    }
    return null;
  }

  /// Directory under `binary/` holding this target's prebuilt library.
  String get directory {
    final simulator = iOSSdk == IOSSdk.iPhoneSimulator ? '-simulator' : '';
    return '${os.name}-${architecture.name}$simulator';
  }

  String get libraryName => switch (os) {
    OS.macOS || OS.iOS => 'libserverpod_argon2.dylib',
    OS.windows => 'serverpod_argon2.dll',
    _ => 'libserverpod_argon2.so',
  };

  /// zig installs DLLs to `bin/`, and other shared libraries to `lib/`.
  String get _installSubdirectory => os == OS.windows ? 'bin' : 'lib';

  /// Builds the library for this target from source and returns it.
  Future<File> build({
    required Uri packageRoot,
    required Uri outputDirectory,
    Uri? cacheDirectory,
  }) async {
    final prefix = outputDirectory.resolve('zig-out/$directory/');
    await zigBuild(
      packageRoot: packageRoot,
      zigTriple: zigTriple,
      prefix: prefix,
      cacheDirectory: cacheDirectory,
    );
    final built = File.fromUri(
      prefix.resolve('$_installSubdirectory/$libraryName'),
    );
    if (!built.existsSync()) {
      throw StateError('zig build succeeded but ${built.path} is missing.');
    }
    return built;
  }
}

/// Runs `zig build` for [zigTriple], installing into [prefix].
Future<void> zigBuild({
  required Uri packageRoot,
  required String zigTriple,
  required Uri prefix,
  Uri? cacheDirectory,
}) async {
  final zig = await _zigExecutable(packageRoot);
  final args = [
    'build',
    '-Dtarget=$zigTriple',
    '--release=fast',
    '-Dstrip=true',
    '-p',
    prefix.toFilePath(),
    if (cacheDirectory != null) ...['--cache-dir', cacheDirectory.toFilePath()],
  ];
  final result = await Process.run(
    zig,
    args,
    workingDirectory: packageRoot.toFilePath(),
  );
  if (result.exitCode != 0) {
    throw ProcessException(
      zig,
      args,
      'zig build failed:\n${result.stdout}\n${result.stderr}',
      result.exitCode,
    );
  }
}

/// Resolves a zig matching `minimum_zig_version` in build.zig.zon. The `zig`
/// on PATH may be that version or anyzig
/// (https://github.com/marler8997/anyzig), which reads the same field when
/// run in the package root.
Future<String> _zigExecutable(Uri packageRoot) async {
  final zon = await File.fromUri(
    packageRoot.resolve('build.zig.zon'),
  ).readAsString();
  final pinned = RegExp(
    r'\.minimum_zig_version = "([^"]+)"',
  ).firstMatch(zon)![1]!;

  String? found;
  try {
    final result = await Process.run('zig', [
      'version',
    ], workingDirectory: packageRoot.toFilePath());
    if (result.exitCode == 0) found = (result.stdout as String).trim();
  } on ProcessException {
    // No zig on PATH.
  }
  if (found == pinned) return 'zig';

  throw StateError(
    'Building serverpod_argon2 from source needs zig $pinned '
    '(${found == null ? 'no zig on PATH' : 'found zig $found'}). Install '
    'zig $pinned, or anyzig (https://github.com/marler8997/anyzig), which '
    'selects the version from build.zig.zon.',
  );
}
