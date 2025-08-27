const std = @import("std");
const log = std.log;
const mem = std.mem;
const alpm = @import("alpm");

pub fn main() !void {
    var gpa_state: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa_state.deinit();

    var chroot: alpm.Chroot = try .init(gpa_state.allocator());
    defer chroot.deinit();

    const rootfs_path = "rootfs";

    const cachedir = try std.fs.path.joinZ(gpa_state.allocator(), &.{
        rootfs_path,
        mem.span(alpm.defaults.cachedir),
    });
    defer gpa_state.allocator().free(cachedir);

    const dbpath = try std.fs.path.joinZ(gpa_state.allocator(), &.{
        rootfs_path,
        mem.span(alpm.defaults.dbpath),
    });
    defer gpa_state.allocator().free(dbpath);

    const hookdir = try std.fs.path.joinZ(gpa_state.allocator(), &.{
        rootfs_path,
        mem.span(alpm.defaults.hookdir),
    });
    defer gpa_state.allocator().free(hookdir);

    const logfile = try std.fs.path.joinZ(gpa_state.allocator(), &.{
        rootfs_path,
        mem.span(alpm.defaults.logfile),
    });
    defer gpa_state.allocator().free(logfile);

    try chroot.setup(rootfs_path);

    var handle: alpm.Handle = try .init(gpa_state.allocator(), rootfs_path, dbpath);
    defer handle.deinit();

    const gpa = handle.arena.allocator();
    handle.setFetchCallback();
    handle.setEventCallback();
    handle.setDownloadCallback();
    handle.setProgressCallback();
    handle.setParallelDownload(5);

    try handle.setLogFile(logfile);
    try handle.setCacheDirs(try .fromSlice(gpa, &.{cachedir}));
    try handle.setGpgDir(alpm.defaults.gpgdir);
    try handle.addHookDir(hookdir);
    try handle.setDefaultSigLevel(.{
        .package = .{
            .required = true,
            .optional = true,
        },
        .database = .{ .optional = true },
    });
    try handle.addArchitecture("x86_64");
    try handle.setLocalFileSigLevel(.{
        .package = .{ .optional = true },
        .database = .{ .optional = true },
    });
    try handle.setRemoteFileSigLevel(.{
        .package = .{ .required = true },
        .database = .{ .required = true },
    });
    try handle.setDisableSandbox(true);

    var core_db = try handle.registerSyncDb("core", .{});
    try core_db.setUsage(alpm.Database.Usage.all);
    try core_db.addServer("http://mirrors.ustc.edu.cn/archlinux/core/os/x86_64");
    var extra_db = try handle.registerSyncDb("extra", .{});
    try extra_db.setUsage(alpm.Database.Usage.all);
    try extra_db.addServer("http://mirrors.ustc.edu.cn/archlinux/extra/os/x86_64");
    var archlinuxcn_db = try handle.registerSyncDb("archlinuxcn", .{});
    try archlinuxcn_db.addServer("http://mirrors.ustc.edu.cn/archlinuxcn/x86_64");
    try archlinuxcn_db.setUsage(alpm.Database.Usage.all);

    const sync_dbs = handle.getSyncDbs();
    _ = try handle.dbUpdate(sync_dbs, true);

    try handle.transactionInit(.{ .downloadonly = false });
    defer handle.transactionRelease();

    var local_db = handle.getLocalDb();

    if (handle.findDbsSatisfier(sync_dbs, "base")) |pkg| {
        try handle.addPackage(pkg);
    } else {
        var pkgs = sync_dbs.findGroupPackages("base");
        var it = pkgs.iterator();
        while (it.next()) |pkg| {
            try handle.addPackage(pkg);
        }
    }

    try handle.transactionPrepare();
    if (handle.getAddList().empty() and handle.getRemoveList().empty()) {
        log.info("There is nothing to do", .{});
        return;
    } else {
        var add_list = handle.getAddList();
        var it_add = add_list.iterator();
        while (it_add.next()) |pkg| {
            const name_cstr = pkg.getNameSentinel();
            const name = mem.span(name_cstr);
            if (local_db.getPackage(name)) |old_pkg| {
                switch (pkg.compareVersions(old_pkg)) {
                    .lt => {
                        log.debug("downgrading {s}", .{name});
                        try handle.downgrade_map.put(name, .none);
                    },
                    .eq => {
                        log.debug("reinstalling {s}", .{name});
                        try handle.reinstall_map.put(name, .none);
                    },
                    .gt => {
                        log.debug("upgrading {s}", .{name});
                        try handle.upgrade_map.put(name, .none);
                    },
                }
            } else {
                log.debug("installing {s}", .{name});
                try handle.install_map.put(name, .none);
            }
        }

        var remove_list = handle.getRemoveList();
        var it_remove = remove_list.iterator();
        while (it_remove.next()) |pkg| {
            const name_cstr = pkg.getNameSentinel();
            const name = mem.span(name_cstr);
            log.debug("removing {s}", .{name});
            try handle.remove_map.put(name, .none);
        }
    }
    try handle.transactionCommit();
}
