//! C ABI over std.crypto.pwhash.argon2, shared by the native libraries and
//! the wasm module.
//!
//! Only the raw KDF is exposed. Salt generation, PHC string encoding and
//! constant-time verification live on the Dart side: freestanding wasm has
//! no entropy source for std's strHash, and std's strVerify compares with
//! mem.eql.
const builtin = @import("builtin");
const std = @import("std");
const argon2 = std.crypto.pwhash.argon2;

/// Keep in sync with `_describeStatus` in lib/src/argon2.dart.
const Status = enum(i32) {
    ok = 0,
    weak_parameters = 1,
    output_too_long = 2,
    out_of_memory = 3,
    invalid_mode = 4,
    unexpected = 5,
};

const allocator = std.heap.page_allocator;

/// The Io for one call from the host. The host enters through the C ABI, so
/// this is where the implementation is chosen. A fresh one per call keeps
/// calls from different Dart isolates independent.
const CallIo = if (builtin.os.tag == .freestanding) struct {
    // std has no OS-backed Io for freestanding wasm. Io.failing runs async
    // and group work inline and fails anything that needs an OS, which
    // Argon2 never asks for.
    const init: CallIo = .{};

    fn io(_: *CallIo) std.Io {
        return .failing;
    }
} else struct {
    // The module is built single-threaded, so Threaded runs lane groups
    // inline.
    threaded: std.Io.Threaded = .init_single_threaded,

    const init: CallIo = .{};

    fn io(call: *CallIo) std.Io {
        return call.threaded.io();
    }
};

fn slice(ptr: ?[*]const u8, len: usize) []const u8 {
    return if (len == 0) &.{} else ptr.?[0..len];
}

/// Derives `out_len` bytes into `out`. `mode` is 0 = argon2d, 1 = argon2i,
/// 2 = argon2id. `secret` and `ad` are optional. Pass a zero length to
/// omit them. Returns a `Status` code.
export fn serverpod_argon2_kdf(
    mode: u32,
    t: u32,
    m: u32,
    p: u32,
    password: ?[*]const u8,
    password_len: usize,
    salt: ?[*]const u8,
    salt_len: usize,
    secret: ?[*]const u8,
    secret_len: usize,
    ad: ?[*]const u8,
    ad_len: usize,
    out: [*]u8,
    out_len: usize,
) i32 {
    const argon2_mode: argon2.Mode = switch (mode) {
        0 => .argon2d,
        1 => .argon2i,
        2 => .argon2id,
        else => return @intFromEnum(Status.invalid_mode),
    };
    const lanes = std.math.cast(u24, p) orelse return @intFromEnum(Status.weak_parameters);
    var call_io: CallIo = .init;

    const params: argon2.Params = .{
        .t = t,
        .m = m,
        .p = lanes,
        .secret = if (secret_len == 0) null else slice(secret, secret_len),
        .ad = if (ad_len == 0) null else slice(ad, ad_len),
    };

    argon2.kdf(
        allocator,
        out[0..out_len],
        slice(password, password_len),
        slice(salt, salt_len),
        params,
        argon2_mode,
        call_io.io(),
    ) catch |err| return @intFromEnum(switch (err) {
        error.WeakParameters => Status.weak_parameters,
        error.OutputTooLong => Status.output_too_long,
        error.OutOfMemory => Status.out_of_memory,
        else => Status.unexpected,
    });
    return @intFromEnum(Status.ok);
}

/// Allocates `len` bytes in the module's own memory, for callers that
/// cannot allocate there themselves (the wasm host). Returns null on
/// failure.
export fn serverpod_argon2_alloc(len: usize) ?[*]u8 {
    const buf = allocator.alloc(u8, len) catch return null;
    return buf.ptr;
}

/// Zeroes and frees a buffer from `serverpod_argon2_alloc`. Zeroing matters
/// on wasm, where freed pages stay in the module's memory.
export fn serverpod_argon2_free(ptr: [*]u8, len: usize) void {
    const buf = ptr[0..len];
    std.crypto.secureZero(u8, buf);
    allocator.free(buf);
}

fn expectKdf(mode: u32, want: []const u8) !void {
    const password = [_]u8{0x01} ** 32;
    const salt = [_]u8{0x02} ** 16;
    const secret = [_]u8{0x03} ** 8;
    const ad = [_]u8{0x04} ** 12;
    var out: [32]u8 = undefined;
    const status = serverpod_argon2_kdf(mode, 3, 32, 4, &password, password.len, &salt, salt.len, &secret, secret.len, &ad, ad.len, &out, out.len);
    try std.testing.expectEqual(@intFromEnum(Status.ok), status);
    try std.testing.expectEqualSlices(u8, want, &out);
}

// RFC 9106 section 5 test vectors.
test "argon2d" {
    try expectKdf(0, &.{ 0x51, 0x2b, 0x39, 0x1b, 0x6f, 0x11, 0x62, 0x97, 0x53, 0x71, 0xd3, 0x09, 0x19, 0x73, 0x42, 0x94, 0xf8, 0x68, 0xe3, 0xbe, 0x39, 0x84, 0xf3, 0xc1, 0xa1, 0x3a, 0x4d, 0xb9, 0xfa, 0xbe, 0x4a, 0xcb });
}

test "argon2i" {
    try expectKdf(1, &.{ 0xc8, 0x14, 0xd9, 0xd1, 0xdc, 0x7f, 0x37, 0xaa, 0x13, 0xf0, 0xd7, 0x7f, 0x24, 0x94, 0xbd, 0xa1, 0xc8, 0xde, 0x6b, 0x01, 0x6d, 0xd3, 0x88, 0xd2, 0x99, 0x52, 0xa4, 0xc4, 0x67, 0x2b, 0x6c, 0xe8 });
}

test "argon2id" {
    try expectKdf(2, &.{ 0x0d, 0x64, 0x0d, 0xf5, 0x8d, 0x78, 0x76, 0x6c, 0x08, 0xc0, 0x37, 0xa3, 0x4a, 0x8b, 0x53, 0xc9, 0xd0, 0x1e, 0xf0, 0x45, 0x2d, 0x75, 0xb6, 0x5e, 0xb5, 0x25, 0x20, 0xe9, 0x6b, 0x01, 0xe6, 0x59 });
}

test "rejects unknown mode" {
    var out: [32]u8 = undefined;
    const status = serverpod_argon2_kdf(3, 1, 64, 1, null, 0, "somesalt", 8, null, 0, null, 0, &out, out.len);
    try std.testing.expectEqual(@intFromEnum(Status.invalid_mode), status);
}

test "rejects short salt" {
    var out: [32]u8 = undefined;
    const status = serverpod_argon2_kdf(2, 1, 64, 1, null, 0, "short", 5, null, 0, null, 0, &out, out.len);
    try std.testing.expectEqual(@intFromEnum(Status.weak_parameters), status);
}
