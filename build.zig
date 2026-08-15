const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const mod = b.addModule("zig_mpc", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    const mod_tests = b.addTest(.{ .root_module = mod });
    const run_mod_tests = b.addRunArtifact(mod_tests);

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

    // Multi-process end-to-end test: every party in its own process, frames
    // delivered by copying files. Needs the installed binary.
    const e2e = b.addSystemCommand(&.{ "sh", "test/e2e.sh" });
    if (b.args) |args| e2e.addArgs(args);
    e2e.step.dependOn(b.getInstallStep());
    const e2e_step = b.step("e2e", "Run the multi-process end-to-end test");
    e2e_step.dependOn(&e2e.step);

    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&run_mod_tests.step);
    test_step.dependOn(&run_cli_tests.step);

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
            .imports = &.{.{ .name = "frame", .module = wasm_frame_mod }},
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
