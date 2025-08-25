const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const pacman_dep = b.dependency("pacman", .{});

    const config_h = b.addConfigHeader(.{
        .style = .{ .cmake = b.path("src/config.h.in") },
        .include_path = "config.h",
    }, .{
        .CACHEDIR = "/var/cache/pacman/pkg/",
        .CONFFILE = "/etc/pacman.conf",
        .DBPATH = "/var/lib/pacman/",
        .ENABLE_NLS = 1,
        .FSSTATSTYPE = .@"struct statvfs",
        .GPGDIR = "/etc/pacman.d/gnupg/",
        .HAVE_GETMNTENT = 1,
        .HAVE_LIBCURL = null,
        .HAVE_LIBGPGME = 1,
        .HAVE_LIBSECCOMP = 1,
        .HAVE_LIBSSL = null,
        .HAVE_LINUX_LANDLOCK_H = 1,
        .HAVE_MNTENT_H = 1,
        .HAVE_STRNDUP = 1,
        .HAVE_STRNLEN = 1,
        .HAVE_STRSEP = 1,
        .HAVE_STRUCT_STATFS_F_FLAGS = null,
        .HAVE_STRUCT_STATVFS_F_FLAG = 1,
        .HAVE_STRUCT_STAT_ST_BLKSIZE = 1,
        .HAVE_SWPRINTF = 1,
        .HAVE_SYS_MOUNT_H = 1,
        .HAVE_SYS_PARAM_H = 1,
        .HAVE_SYS_PRCTL_H = 1,
        .HAVE_SYS_STATVFS_H = 1,
        .HAVE_SYS_TYPES_H = 1,
        .HAVE_TCFLUSH = 1,
        .HAVE_TERMIOS_H = 1,
        .HOOKDIR = "/etc/pacman.d/hooks/",
        .LDCONFIG = "/usr/bin/ldconfig",
        .LIB_VERSION = "15.0.0",
        .LOCALEDIR = "/usr/share/locale",
        .LOGFILE = "/var/log/pacman.log",
        .PACKAGE = "pacman",
        .PACKAGE_VERSION = "7.0.0",
        .ROOTDIR = "/",
        .SCRIPTLET_SHELL = "/usr/bin/bash",
        .SYSHOOKDIR = "/usr/share/libalpm/hooks/",
    });

    const translate_c = b.addTranslateC(.{
        .root_source_file = b.path("src/c.h"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    translate_c.addIncludePath(pacman_dep.path("lib/libalpm"));
    translate_c.addConfigHeader(config_h);

    const c_mod = translate_c.createModule();

    const mod = b.addModule("alpm", .{
        .root_source_file = b.path("src/alpm.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .imports = &.{
            .{ .name = "c", .module = c_mod },
        },
    });
    mod.addConfigHeader(config_h);
    mod.addIncludePath(pacman_dep.path("src/common"));
    mod.addIncludePath(pacman_dep.path("lib/libalpm"));

    const lib = b.addLibrary(.{
        .linkage = .static,
        .name = "alpm",
        .root_module = mod,
    });
    lib.addCSourceFiles(.{
        .root = pacman_dep.path("lib/libalpm"),
        .files = &alpm_src,
        .flags = &.{
            "-std=gnu99",
            "-includeconfig.h",
        },
    });
    lib.addCSourceFiles(.{
        .root = pacman_dep.path("src/common"),
        .files = &common_src,
        .flags = &.{
            "-std=gnu99",
            "-includeconfig.h",
        },
    });
    lib.addCSourceFile(.{
        .file = b.path("src/util.c"),
        .flags = &.{
            "-std=gnu99",
            "-includeconfig.h",
        },
    });
    lib.linkSystemLibrary("archive");
    lib.linkSystemLibrary("gpgme");
    b.installArtifact(lib);

    const mod_tests = b.addTest(.{
        .root_module = mod,
    });

    const run_mod_tests = b.addRunArtifact(mod_tests);

    const lib_tests = b.addTest(.{
        .root_module = lib.root_module,
    });

    const run_lib_tests = b.addRunArtifact(lib_tests);
    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&run_mod_tests.step);
    test_step.dependOn(&run_lib_tests.step);
}

const common_src = [_][]const u8{
    "ini.c",
    "util-common.c",
};

const alpm_src = [_][]const u8{
    "add.c",
    "alpm.c",
    "alpm_list.c",
    "backup.c",
    "base64.c",
    "be_local.c",
    "be_package.c",
    "be_sync.c",
    "conflict.c",
    "db.c",
    "deps.c",
    "diskspace.c",
    "dload.c",
    "error.c",
    "filelist.c",
    "graph.c",
    "group.c",
    "handle.c",
    "hook.c",
    "log.c",
    "package.c",
    "pkghash.c",
    "rawstr.c",
    "remove.c",
    "sandbox.c",
    "sandbox_fs.c",
    "signing.c",
    "sync.c",
    "trans.c",
    //"util.c",
    "version.c",
};
