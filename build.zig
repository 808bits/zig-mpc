const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // secp256k1 backend: bitcoin-core/libsecp256k1 (fast, C) or std.crypto
    // (pure Zig, the only choice for wasm). The protocols are generic over
    // the curve type, so this flag is the entire difference; switching back
    // is `-Dsecp=std`. See src/curve.zig and src/curve_libsecp.zig.
    const SecpBackend = enum { std, glv, libsecp };
    const secp_backend = b.option(SecpBackend, "secp", "secp256k1 backend (default: libsecp)") orelse .libsecp;
    const secp_backend_file: []const u8 = switch (secp_backend) {
        .std => "src/secp_backend/std.zig",
        .glv => "src/secp_backend/glv.zig",
        .libsecp => "src/secp_backend/libsecp.zig",
    };
    const secp_backend_mod = b.createModule(.{ .root_source_file = b.path(secp_backend_file) });
    // wasm cannot link C, so it gets the best pure-Zig backend: GLV.
    const secp_backend_wasm_mod = b.createModule(.{ .root_source_file = b.path("src/secp_backend/glv.zig") });

    // libsecp256k1 itself, compiled once and linked wherever it is needed:
    // into the library when the libsecp backend is selected, and into the
    // interop tests always (they compare against it by definition). The
    // defines mirror the project's CMake defaults; ECDH is the module that
    // provides constant-time arbitrary-point multiplication.
    const secp_dep = b.dependency("secp256k1", .{});
    const secp_c_lib = b.addLibrary(.{
        .name = "secp256k1",
        .linkage = .static,
        .root_module = b.createModule(.{
            .target = target,
            .optimize = .ReleaseFast,
            .link_libc = true,
        }),
    });
    secp_c_lib.root_module.addIncludePath(secp_dep.path("include"));
    secp_c_lib.root_module.addCSourceFiles(.{
        .root = secp_dep.path("src"),
        .files = &.{ "secp256k1.c", "precomputed_ecmult.c", "precomputed_ecmult_gen.c" },
        .flags = &.{
            "-DECMULT_WINDOW_SIZE=15",
            "-DECMULT_GEN_KB=86",
            "-DENABLE_MODULE_SCHNORRSIG=1",
            "-DENABLE_MODULE_EXTRAKEYS=1",
            "-DENABLE_MODULE_ECDH=1",
        },
    });

    const mod = b.addModule("zig_mpc", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "secp_backend", .module = secp_backend_mod }},
    });
    if (secp_backend == .libsecp) {
        mod.link_libc = true;
        mod.linkLibrary(secp_c_lib);
    }

    const mod_tests = b.addTest(.{ .root_module = mod });
    const run_mod_tests = b.addRunArtifact(mod_tests);

    // The DKLs23 tests are compiled optimized regardless of -Doptimize.
    // They run hundreds of endemic OTs and two Fischlin proofs of work, which
    // in a debug build takes minutes and dominates the whole suite; at
    // ReleaseSafe it is seconds, and every safety check is still on, so
    // nothing is traded away except the wait. They are excluded from
    // `mod_tests` (see the `test` block in src/root.zig) to avoid running
    // twice.
    const dkls_mod = b.createModule(.{
        .root_source_file = b.path("src/dkls.zig"),
        .target = target,
        .optimize = .ReleaseSafe,
        .imports = &.{.{ .name = "secp_backend", .module = secp_backend_mod }},
    });
    if (secp_backend == .libsecp) {
        dkls_mod.link_libc = true;
        dkls_mod.linkLibrary(secp_c_lib);
    }
    const dkls_tests = b.addTest(.{ .root_module = dkls_mod });
    const run_dkls_tests = b.addRunArtifact(dkls_tests);
    const dkls_step = b.step("dkls", "Run the DKLs23 tests");
    dkls_step.dependOn(&run_dkls_tests.step);

    // Release builds stamp the tag in (`-Dversion=0.0.1`) and drop debug info;
    // a plain `zig build` keeps the dev version and the symbols.
    const version = b.option([]const u8, "version", "Version reported by `zmpc version`") orelse "0.1.0-dev";
    const strip = b.option(bool, "strip", "Strip debug info from the binary") orelse false;

    const build_options = b.addOptions();
    build_options.addOption([]const u8, "version", version);

    // zmpc CLI: one binary per party, message passing over files or a relay
    const cli_mod = b.createModule(.{
        .root_source_file = b.path("cli/main.zig"),
        .target = target,
        .optimize = optimize,
        .strip = strip,
        .imports = &.{
            .{ .name = "zig_mpc", .module = mod },
            .{ .name = "build_options", .module = build_options.createModule() },
        },
    });
    const cli_exe = b.addExecutable(.{ .name = "zmpc", .root_module = cli_mod });
    b.installArtifact(cli_exe);
    const run_cli = b.addRunArtifact(cli_exe);
    if (b.args) |args| run_cli.addArgs(args);
    const cli_step = b.step("cli", "Run the zmpc CLI");
    cli_step.dependOn(&run_cli.step);

    const cli_tests = b.addTest(.{ .root_module = cli_mod });
    const run_cli_tests = b.addRunArtifact(cli_tests);

    // Interop tests: the same signatures checked against bitcoin-core's
    // libsecp256k1, compiled from source out of the package cache. The
    // defines mirror that project's CMake defaults; schnorrsig (and its
    // dependency extrakeys) is the only optional module the tests need.
    const interop_mod = b.createModule(.{
        .root_source_file = b.path("test/interop.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .imports = &.{.{ .name = "zig_mpc", .module = mod }},
    });
    interop_mod.linkLibrary(secp_c_lib);
    const interop_tests = b.addTest(.{ .root_module = interop_mod });
    const run_interop_tests = b.addRunArtifact(interop_tests);
    const interop_step = b.step("interop", "Run the libsecp256k1 interop tests");
    interop_step.dependOn(&run_interop_tests.step);

    // Multi-process end-to-end test: every party in its own process, frames
    // delivered by copying files. Needs the installed binary.
    const e2e = b.addSystemCommand(&.{ "sh", "test/e2e.sh" });
    if (b.args) |args| e2e.addArgs(args);
    e2e.step.dependOn(b.getInstallStep());
    const e2e_step = b.step("e2e", "Run the multi-process end-to-end test");
    e2e_step.dependOn(&e2e.step);

    // DKLs23 benchmark, always optimized: `zig build bench`, and
    // `zig build bench -Dsecp=std` to measure the backend difference.
    const bench_mpc_mod = b.createModule(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = .ReleaseFast,
        .imports = &.{.{ .name = "secp_backend", .module = secp_backend_mod }},
    });
    if (secp_backend == .libsecp) {
        bench_mpc_mod.link_libc = true;
        bench_mpc_mod.linkLibrary(secp_c_lib);
    }
    const bench_exe = b.addExecutable(.{
        .name = "bench-dkls",
        .root_module = b.createModule(.{
            .root_source_file = b.path("bench/dkls.zig"),
            .target = target,
            .optimize = .ReleaseFast,
            .imports = &.{
                .{ .name = "zig_mpc", .module = bench_mpc_mod },
                .{ .name = "secp_backend", .module = secp_backend_mod },
            },
        }),
    });
    const bench_step = b.step("bench", "Run the DKLs23 benchmark");
    bench_step.dependOn(&b.addRunArtifact(bench_exe).step);

    // Cross-scheme benchmark: FROST on three curves + CGGMP24 ecdsa_fast.
    const fam_exe = b.addExecutable(.{
        .name = "bench-families",
        .root_module = b.createModule(.{
            .root_source_file = b.path("bench/families.zig"),
            .target = target,
            .optimize = .ReleaseFast,
            .imports = &.{
                .{ .name = "zig_mpc", .module = bench_mpc_mod },
                .{ .name = "secp_backend", .module = secp_backend_mod },
            },
        }),
    });
    const fam_step = b.step("bench-families", "Run the cross-scheme benchmark");
    fam_step.dependOn(&b.addRunArtifact(fam_exe).step);

    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&run_mod_tests.step);
    test_step.dependOn(&run_dkls_tests.step);
    test_step.dependOn(&run_cli_tests.step);
    test_step.dependOn(&run_interop_tests.step);

    // WebAssembly build of the C ABI, plus the CGGMP24 signing exports, which
    // speak the CLI's frame format. Consumed by test/smoke.mjs and by the
    // interactive article on 808bits.com, which ships its own copy of the wasm.
    const wasm_target = b.resolveTargetQuery(.{ .cpu_arch = .wasm32, .os_tag = .freestanding });
    const wasm_frame_mod = b.createModule(.{
        .root_source_file = b.path("cli/frame.zig"),
        .target = wasm_target,
        .optimize = .ReleaseSmall,
    });
    const wasm = b.addExecutable(.{
        .name = "zmpc",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/wasm.zig"),
            .target = wasm_target,
            .optimize = .ReleaseSmall,
            .imports = &.{
                .{ .name = "frame", .module = wasm_frame_mod },
                // No C toolchain in the freestanding wasm build: pure Zig.
                .{ .name = "secp_backend", .module = secp_backend_wasm_mod },
            },
        }),
    });
    wasm.entry = .disabled;
    wasm.rdynamic = true;
    const wasm_install = b.addInstallArtifact(wasm, .{});
    const wasm_step = b.step("wasm", "Build the WebAssembly module");
    wasm_step.dependOn(&wasm_install.step);

    // Node-based wasm smoke test
    const wasm_test = b.addSystemCommand(&.{ "node", "test/smoke.mjs" });
    wasm_test.step.dependOn(&wasm_install.step);
    const wasm_test_step = b.step("wasm-test", "Run the wasm smoke test under node");
    wasm_test_step.dependOn(&wasm_test.step);
}
