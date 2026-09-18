@TestOn('vm')
library;

import 'dart:convert';
import 'dart:io';

import 'package:code_assets/code_assets.dart';
import 'package:hooks/hooks.dart';
import 'package:test/test.dart';

typedef _HookRun = ({
  int exitCode,
  String stderr,
  BuildOutputMaybeFailure output,
});

/// Runs `hook/build.dart` in its own process, since a failing hook exits the
/// process it runs in.
Future<_HookRun> _runBuildHook({
  required Directory packageRoot,
  required OS targetOS,
  required Architecture targetArchitecture,
}) async {
  final temp = await Directory.systemTemp.createTemp('serverpod_argon2_hook');
  addTearDown(() => temp.delete(recursive: true));
  final outputFile = temp.uri.resolve('output.json');
  final outputDirectoryShared = temp.uri.resolve('shared/');
  await Directory.fromUri(outputDirectoryShared).create();

  final inputBuilder = BuildInputBuilder()
    ..setupShared(
      packageRoot: packageRoot.uri,
      packageName: 'serverpod_argon2',
      outputFile: outputFile,
      outputDirectoryShared: outputDirectoryShared,
    )
    ..setupBuildInput()
    ..config.setupBuild(linkingEnabled: false);
  CodeAssetExtension(
    targetOS: targetOS,
    targetArchitecture: targetArchitecture,
    linkModePreference: LinkModePreference.dynamic,
  ).setupBuildInput(inputBuilder);
  final inputFile = File.fromUri(temp.uri.resolve('input.json'));
  await inputFile.writeAsString(jsonEncode(inputBuilder.build().json));

  final result = await Process.run(Platform.resolvedExecutable, [
    'hook/build.dart',
    '--config=${inputFile.path}',
  ]);
  final outputJson = jsonDecode(await File.fromUri(outputFile).readAsString());
  return (
    exitCode: result.exitCode,
    stderr: result.stderr as String,
    output: BuildOutputMaybeFailure(outputJson as Map<String, Object?>),
  );
}

void main() {
  group('Given a target the package has no library for (linux ia32), '
      'when the build hook runs,', () {
    late _HookRun run;

    setUpAll(() async {
      run = await _runBuildHook(
        packageRoot: Directory.current,
        targetOS: OS.linux,
        targetArchitecture: Architecture.ia32,
      );
    });

    test('then the hook exits with a build failure', () {
      expect(run.exitCode, 1);
      expect(
        run.output,
        isA<BuildOutputFailure>().having(
          (failure) => failure.type,
          'type',
          FailureType.build,
        ),
      );
    });

    test('then the error names the unsupported target', () {
      expect(
        run.stderr,
        startsWith('serverpod_argon2 does not support linux/ia32.\n'),
      );
    });
  });

  group(
    'Given a source checkout pinned to a zig version that is not installed, '
    'when the build hook runs,',
    () {
      late _HookRun run;

      setUpAll(() async {
        final packageRoot = await Directory.systemTemp.createTemp(
          'serverpod_argon2_source',
        );
        addTearDown(() => packageRoot.delete(recursive: true));
        await File.fromUri(
          packageRoot.uri.resolve('build.zig.zon'),
        ).writeAsString('.{ .minimum_zig_version = "0.0.0" }');

        run = await _runBuildHook(
          packageRoot: packageRoot,
          targetOS: OS.linux,
          targetArchitecture: Architecture.x64,
        );
      });

      test('then the hook exits with a build failure', () {
        expect(run.exitCode, 1);
        expect(
          run.output,
          isA<BuildOutputFailure>().having(
            (failure) => failure.type,
            'type',
            FailureType.build,
          ),
        );
      });

      test('then the error names the zig version it needs', () {
        expect(
          run.stderr,
          startsWith('Building serverpod_argon2 from source needs zig 0.0.0 '),
        );
      });
    },
  );
}
