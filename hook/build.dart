import 'dart:io';

import 'package:code_assets/code_assets.dart';
import 'package:hooks/hooks.dart';

import 'package:serverpod_argon2/src/native_target.dart';

/// Bundles the native library for the target being built.
///
/// A published package carries a prebuilt library per target under
/// `binary/`, so consumers need no toolchain. A source checkout has no
/// `binary/` and compiles with zig instead.
Future<void> main(List<String> args) async {
  await build(args, (input, output) async {
    if (!input.config.buildCodeAssets) return;

    final code = input.config.code;
    final target = NativeTarget.of(code);
    if (target == null) {
      throw BuildError(
        message:
            'serverpod_argon2 does not support '
            '${code.targetOS}/${code.targetArchitecture}.',
      );
    }

    final packageRoot = input.packageRoot;
    final prebuilt = File.fromUri(
      packageRoot.resolve('binary/${target.directory}/${target.libraryName}'),
    );

    final File library;
    if (prebuilt.existsSync()) {
      library = prebuilt;
      output.dependencies.add(prebuilt.uri);
    } else {
      try {
        library = await target.build(
          packageRoot: packageRoot,
          outputDirectory: input.outputDirectory,
          cacheDirectory: input.outputDirectoryShared.resolve('zig-cache/'),
        );
      } on StateError catch (e, st) {
        throw BuildError(
          message: e.message,
          wrappedException: e,
          wrappedTrace: st,
        );
      } on ProcessException catch (e, st) {
        throw BuildError(
          message: e.message,
          wrappedException: e,
          wrappedTrace: st,
        );
      }
      output.dependencies.addAll([
        packageRoot.resolve('build.zig'),
        packageRoot.resolve('build.zig.zon'),
        packageRoot.resolve('src/argon2.zig'),
      ]);
    }

    output.assets.code.add(
      CodeAsset(
        package: input.packageName,
        name: 'serverpod_argon2.dart',
        linkMode: DynamicLoadingBundled(),
        file: library.uri,
      ),
    );
  });
}
