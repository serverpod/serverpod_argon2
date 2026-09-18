// Builds the serverpod_argon2 native library for one target per invocation:
//
//   zig build -Dtarget=aarch64-macos --release=fast
//   zig build -Dtarget=wasm32-freestanding --release=fast
//
// A native target produces a shared library, wasm32-freestanding a wasm
// module. hook/build.dart and tool/build_binaries.dart drive this for every
// supported target.
//
// The code is pure Zig and never links libc, so every target except iOS
// cross-compiles from any host without a sysroot. iOS needs the SDK because
// zig does not bundle libSystem stubs for it.
const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{
        .preferred_optimize_mode = .ReleaseFast,
    });
    const strip = b.option(bool, "strip", "Strip debug info (used for published binaries)") orelse false;

    const os = target.result.os.tag;
    if (os == .ios and b.sysroot == null) {
        b.sysroot = detectIosSdk(b, target);
    }

    const module = b.createModule(.{
        .root_source_file = b.path("src/argon2.zig"),
        .target = target,
        .optimize = optimize,
        .strip = strip,
        // Lanes run one after another. Spawning threads from a library that
        // does not link libc would bypass the host's TLS setup, and Dart
        // callers parallelise with isolates instead.
        .single_threaded = true,
    });

    if (target.result.cpu.arch.isWasm()) {
        const wasm = b.addExecutable(.{ .name = "serverpod_argon2", .root_module = module });
        wasm.entry = .disabled;
        wasm.rdynamic = true;
        b.installArtifact(wasm);
    } else {
        const lib = b.addLibrary(.{
            .name = "serverpod_argon2",
            .linkage = .dynamic,
            .root_module = module,
        });
        if (os.isDarwin()) {
            // Leaves room for install_name_tool, which the Dart and Flutter
            // native asset tooling runs on Apple dylibs.
            lib.headerpad_max_install_names = true;
        }
        if (target.result.abi.isAndroid()) {
            // Google Play requires 16 KB page alignment from Android 15.
            lib.link_z_max_page_size = 16384;
        }
        if (os == .ios) {
            const sysroot = b.sysroot orelse @panic(
                "iOS targets require --sysroot $(xcrun --sdk iphoneos|iphonesimulator --show-sdk-path)",
            );
            lib.setLibCFile(appleLibcFile(b, sysroot));
        }
        b.installArtifact(lib);
    }

    const tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/argon2.zig"),
            .target = b.graph.host,
            .optimize = optimize,
            .single_threaded = true,
        }),
    });
    b.step("test", "Run the RFC 9106 test vectors").dependOn(&b.addRunArtifact(tests).step);
}

fn detectIosSdk(b: *std.Build, target: std.Build.ResolvedTarget) ?[]const u8 {
    const sdk = if (target.result.abi == .simulator) "iphonesimulator" else "iphoneos";
    const result = std.process.run(b.allocator, b.graph.io, .{
        .argv = &.{ "xcrun", "--sdk", sdk, "--show-sdk-path" },
    }) catch return null;
    if (result.term != .exited or result.term.exited != 0) return null;
    return std.mem.trimEnd(u8, result.stdout, "\n");
}

/// zig bundles no libc headers or stubs for iOS, so point it at the SDK.
fn appleLibcFile(b: *std.Build, sysroot: []const u8) std.Build.LazyPath {
    const wf = b.addWriteFiles();
    return wf.add("apple-libc.txt", b.fmt(
        \\include_dir={[sysroot]s}/usr/include
        \\sys_include_dir={[sysroot]s}/usr/include
        \\crt_dir=
        \\msvc_lib_dir=
        \\kernel32_lib_dir=
        \\gcc_dir=
        \\
    , .{ .sysroot = sysroot }));
}
