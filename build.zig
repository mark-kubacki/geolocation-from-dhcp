const std = @import("std");

const targets: []const std.Target.Query = &.{
    .{ .cpu_arch = .x86_64, .os_tag = .linux, .cpu_model = .{ .explicit = &std.Target.x86.cpu.x86_64_v2 } },
    .{ .cpu_arch = .aarch64, .os_tag = .linux, .cpu_model = .{ .explicit = &std.Target.arm.cpu.cortex_a53 } },
    .{ .cpu_arch = .riscv64, .os_tag = .linux, .cpu_model = .{ .explicit = &std.Target.riscv.cpu.baseline_rv64 } },
};

pub fn build(b: *std.Build) !void {
    for (targets) |t| {
        const exe = b.addExecutable(.{
            .name = "geolocation-from-dhcp",
            .root_module = b.createModule(.{
                .root_source_file = b.path("src/main.zig"),
                .target = b.resolveTargetQuery(t),
                .optimize = .ReleaseSmall,
                .single_threaded = true,
                .unwind_tables = .none,
            }),
        });
        if (t.os_tag != .windows) {
            exe.stack_size = 0; // Go with OS defaults, save two syscalls.
        }

        const path_suffix = try t.zigTriple(b.allocator);
        const target_output = b.addInstallArtifact(exe, .{
            .dest_dir = .{
                .override = .{
                    .custom = try std.fs.path.join(b.allocator, &.{ "..", "release", path_suffix }),
                },
            },
        });

        b.getInstallStep().dependOn(&target_output.step);
    }
}
