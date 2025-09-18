// A struct to hold the state of our chroot environment
arena: *ArenaAllocator,
active_mounts: std.array_list.Managed([:0]const u8),
active_lazy_mounts: std.array_list.Managed([:0]const u8),
active_files: std.array_list.Managed([:0]const u8),

// Initializes the Chroot struct
pub fn init(allocator: Allocator) !Chroot {
    var chroot: Chroot = .{
        .arena = try allocator.create(ArenaAllocator),
        .active_mounts = .init(allocator),
        .active_lazy_mounts = .init(allocator),
        .active_files = .init(allocator),
    };

    errdefer allocator.destroy(chroot.arena);
    chroot.arena.* = ArenaAllocator.init(allocator);
    errdefer chroot.arena.deinit();

    return chroot;
}

// Deinitializes the Chroot struct, cleaning up resources
pub fn deinit(self: *Chroot) void {
    self.active_mounts.deinit();
    self.active_lazy_mounts.deinit();
    self.active_files.deinit();

    const allocator = self.arena.child_allocator;
    self.arena.deinit();
    allocator.destroy(self.arena);
}

fn prepare(self: *Chroot, newroot: []const u8) !void {
    const allocator = self.arena.child_allocator;
    const dirs_0755 = [_][]const u8{
        "var/cache/pacman/pkg",
        "var/lib/pacman",
        "var/log",
        "dev",
        "run",
        "etc/pacman.d",
    };

    for (dirs_0755) |dir| {
        const full_path = try fs.path.join(allocator, &.{ newroot, dir });
        defer allocator.free(full_path);

        var curr_dir = try fs.cwd().makeOpenPath(full_path, .{ .iterate = true });
        defer curr_dir.close();
        try curr_dir.chmod(0o755);
    }

    const tmp_path = try fs.path.join(allocator, &.{ newroot, "tmp" });
    defer allocator.free(tmp_path);
    var tmp_dir = try fs.cwd().makeOpenPath(tmp_path, .{ .iterate = true });
    try tmp_dir.chmod(0o1777);

    const dirs_0555 = [_][]const u8{
        "sys",
        "proc",
    };

    for (dirs_0555) |dir| {
        const full_path = try fs.path.join(allocator, &.{ newroot, dir });
        defer allocator.free(full_path);

        var curr_dir = try fs.cwd().makeOpenPath(full_path, .{ .iterate = true });
        try curr_dir.chmod(0o555);
    }
}

// Corresponds to chroot_add_mount
fn addMount(self: *Chroot, source: [:0]const u8, target: [:0]const u8, fstype: ?[:0]const u8, flags: u32, data: ?[]const u8) !void {
    const data_raw = if (data) |d| @intFromPtr(d.ptr) else 0;
    const fstype_ptr = if (fstype) |f| f.ptr else null;
    try mountZ(source, target, fstype_ptr, flags, data_raw);
    try self.active_mounts.append(target);
}

// Corresponds to chroot_add_mount_lazy
fn addMountLazy(self: *Chroot, source: [:0]const u8, target: [:0]const u8, fstype: ?[:0]const u8, flags: u32, data: ?[]const u8) !void {
    const data_raw = if (data) |d| @intFromPtr(d.ptr) else 0;
    const fstype_ptr = if (fstype) |f| f.ptr else null;
    try mountZ(source, target, fstype_ptr, flags, data_raw);
    try self.active_lazy_mounts.append(target);
}

// Corresponds to chroot_maybe_add_mount
fn maybeAddMount(self: *Chroot, cond: bool, source: [:0]const u8, target: [:0]const u8, fstype: ?[:0]const u8, flags: u32, data: ?[]const u8) !void {
    if (cond) {
        try self.addMount(source, target, fstype, flags, data);
    }
}

// Corresponds to chroot_bind_device
fn bindDevice(self: *Chroot, source: [:0]const u8, target: [:0]const u8) !void {
    const file = try std.fs.cwd().createFile(target, .{});
    file.close();
    try self.active_files.append(target);
    try self.addMount(source, target, "bind", std.os.linux.MS.BIND, null);
}

// Corresponds to chroot_add_link
fn addLink(self: *Chroot, source: [:0]const u8, target: [:0]const u8) !void {
    try std.posix.symlink(source, target);
    try self.active_files.append(target);
}

// A "less than" function for sorting, but we use it to sort descending.
// It returns true if `a` should come before `b`.
// By comparing `b.len < a.len`, we sort from longest to shortest.
fn pathGreaterThan(context: void, a: [:0]const u8, b: [:0]const u8) bool {
    _ = context;
    return b.len < a.len;
}

// Corresponds to chroot_teardown
pub fn teardown(self: *Chroot) void {
    std.sort.block([:0]const u8, self.active_mounts.items, {}, pathGreaterThan);
    for (self.active_mounts.items) |mount_point| {
        umount2Z(mount_point, 0) catch unreachable;
    }
    self.active_mounts.clearRetainingCapacity();
}

// Corresponds to chroot_setup
pub fn setup(self: *Chroot, chroot_dir: []const u8) !void {
    try self.prepare(chroot_dir);

    const allocator = self.arena.allocator();
    const proc_path = try std.fs.path.joinZ(allocator, &.{ chroot_dir, "proc" });
    const sys_path = try std.fs.path.joinZ(allocator, &.{ chroot_dir, "sys" });
    const efivars_path = try std.fs.path.joinZ(allocator, &.{ chroot_dir, "sys", "firmware", "efi", "efivars" });
    const dev_path = try std.fs.path.joinZ(allocator, &.{ chroot_dir, "dev" });
    const dev_pts_path = try std.fs.path.joinZ(allocator, &.{ chroot_dir, "dev", "pts" });
    const dev_shm_path = try std.fs.path.joinZ(allocator, &.{ chroot_dir, "dev", "shm" });
    const run_path = try std.fs.path.joinZ(allocator, &.{ chroot_dir, "run" });
    const tmp_path = try std.fs.path.joinZ(allocator, &.{ chroot_dir, "tmp" });

    try self.addMount("proc", proc_path, "proc", std.os.linux.MS.NOSUID | std.os.linux.MS.NOEXEC | std.os.linux.MS.NODEV, null);
    try self.addMount("sys", sys_path, "sysfs", std.os.linux.MS.NOSUID | std.os.linux.MS.NOEXEC | std.os.linux.MS.NODEV | std.os.linux.MS.RDONLY, null);

    const efivars_exist = blk: {
        std.fs.cwd().access(efivars_path, .{}) catch |err| {
            if (err == error.FileNotFound) break :blk false else return err;
        };
        break :blk true;
    };
    try self.maybeAddMount(efivars_exist, "efivarfs", efivars_path, "efivarfs", std.os.linux.MS.NOSUID | std.os.linux.MS.NOEXEC | std.os.linux.MS.NODEV, null);

    try self.addMount("udev", dev_path, "devtmpfs", std.os.linux.MS.NOSUID, "mode=0755");
    try self.addMount("devpts", dev_pts_path, "devpts", std.os.linux.MS.NOSUID | std.os.linux.MS.NOEXEC, "mode=0620,gid=5");
    try self.addMount("shm", dev_shm_path, "tmpfs", std.os.linux.MS.NOSUID | std.os.linux.MS.NODEV, "mode=1777");
    try self.addMount("/run", run_path, "bind", std.os.linux.MS.BIND | std.os.linux.MS.PRIVATE, null);
    try self.addMount("tmp", tmp_path, "tmpfs", std.os.linux.MS.NODEV | std.os.linux.MS.NOSUID | std.os.linux.MS.STRICTATIME, "mode=1777");
}

/// Sets up a chroot-like environment using unshare, mirroring the bash script's logic.
pub fn unshareSetup(self: *Chroot, chroot_dir: []const u8) !void {
    try self.prepare(chroot_dir);

    const allocator = self.arena.allocator();

    // Helper to create a null-terminated path inside the chroot
    const ChrootPath = struct {
        gpa: mem.Allocator,
        chroot_dir: []const u8,

        pub fn join(cp: *@This(), parts: []const []const u8) ![:0]const u8 {
            var list: std.ArrayList([]const u8) = try .initCapacity(cp.gpa, parts.len + 1);
            defer list.deinit(cp.gpa);
            list.appendAssumeCapacity(cp.chroot_dir);
            list.appendSliceAssumeCapacity(parts);
            return std.fs.path.joinZ(cp.gpa, list.items);
        }
    };

    var chpath: ChrootPath = .{
        .gpa = allocator,
        .chroot_dir = chroot_dir,
    };

    // chroot_add_mount_lazy "$1" "$1" --bind
    const chroot_dir_z = try allocator.dupeZ(u8, chroot_dir);
    try self.addMountLazy(chroot_dir_z, chroot_dir_z, null, linux.MS.BIND, null);

    // chroot_add_mount proc "$1/proc" -t proc ...
    try self.addMount("proc", try chpath.join(&.{"proc"}), "proc", linux.MS.NOSUID | linux.MS.NOEXEC | linux.MS.NODEV, null);

    // chroot_add_mount_lazy /sys "$1/sys" --rbind
    // --rbind translates to MS_BIND | MS_REC
    try self.addMountLazy("/sys", try chpath.join(&.{"sys"}), null, linux.MS.BIND | linux.MS.REC, null);

    // chroot_add_link /proc/self/fd "$1/dev/fd"
    try self.addLink("/proc/self/fd", try chpath.join(&.{ "dev", "fd" }));
    try self.addLink("/proc/self/fd/0", try chpath.join(&.{ "dev", "stdin" }));
    try self.addLink("/proc/self/fd/1", try chpath.join(&.{ "dev", "stdout" }));
    try self.addLink("/proc/self/fd/2", try chpath.join(&.{ "dev", "stderr" }));

    // chroot_bind_device ...
    try self.bindDevice("/dev/full", try chpath.join(&.{ "dev", "full" }));
    try self.bindDevice("/dev/null", try chpath.join(&.{ "dev", "null" }));
    try self.bindDevice("/dev/random", try chpath.join(&.{ "dev", "random" }));
    try self.bindDevice("/dev/tty", try chpath.join(&.{ "dev", "tty" }));
    try self.bindDevice("/dev/urandom", try chpath.join(&.{ "dev", "urandom" }));
    try self.bindDevice("/dev/zero", try chpath.join(&.{ "dev", "zero" }));

    // chroot_add_mount run "$1/run" -t tmpfs ...
    try self.addMount("run", try chpath.join(&.{"run"}), "tmpfs", linux.MS.NOSUID | linux.MS.NODEV, "mode=0755");

    // chroot_add_mount tmp "$1/tmp" -t tmpfs ...
    try self.addMount("tmp", try chpath.join(&.{"tmp"}), "tmpfs", linux.MS.STRICTATIME | linux.MS.NODEV | linux.MS.NOSUID, "mode=1777");
}

/// Tears down the environment created by `unshareSetup`.
pub fn unshareTeardown(self: *Chroot) void {
    // First, unmount all regular mounts.
    self.teardown();

    // Then, unmount the lazy mounts.
    // We sort to handle nested paths, just in case.
    std.sort.block([:0]const u8, self.active_lazy_mounts.items, {}, pathGreaterThan);
    for (self.active_lazy_mounts.items) |mount_point| {
        // --lazy corresponds to MNT_DETACH
        umount2Z(mount_point, linux.MNT.DETACH) catch |err| {
            std.log.warn("failed to lazy unmount {s}: {s}", .{ mount_point, @errorName(err) });
        };
    }
    self.active_lazy_mounts.clearRetainingCapacity();

    // Finally, remove all created files and symlinks.
    for (self.active_files.items) |file_path| {
        std.fs.cwd().deleteFile(file_path) catch |err| {
            std.log.warn("failed to remove {s}: {s}", .{ file_path, @errorName(err) });
        };
    }
    self.active_files.clearRetainingCapacity();
}

/// A wrapper around the raw `syscall5` to provide a typed error set for the mount(2) syscall.
pub const MountError = error{
    /// EACCES: A component of a path was not searchable, or mounting a read-only
    /// filesystem was attempted without the MS_RDONLY flag.
    Access,
    /// EBUSY: The source is already mounted, or it cannot be remounted read-only
    /// because it still holds files open for writing.
    Busy,
    /// EFAULT: A pointer argument points outside the user address space.
    Fault,
    /// EINVAL: Invalid superblock, invalid remount/move operation, or invalid flags.
    InvalidValue,
    /// ELOOP: Too many links encountered during pathname resolution or a move
    /// operation where the target is a descendant of the source.
    Loop,
    /// EMFILE: The table of dummy devices is full.
    FileTableOverflow,
    /// ENAMETOOLONG: A pathname was longer than MAXPATHLEN.
    NameTooLong,
    /// ENODEV: The filesystem type is not configured in the kernel.
    NoDevice,
    /// ENOENT: A pathname was empty or had a nonexistent component.
    NoEntry,
    /// ENOMEM: The kernel could not allocate memory.
    NoMemory,
    /// ENOTBLK: The source is not a block device when one was required.
    NotBlockDevice,
    /// ENOTDIR: The target, or a prefix of the source, is not a directory.
    NotDirectory,
    /// ENXIO: The major number of the block device source is out of range.
    NoDeviceOrAddress,
    /// EPERM: The caller does not have the required privileges.
    PermissionDenied,
    /// EROFS: An attempt was made to mount a read-only filesystem without the MS_RDONLY flag.
    ReadOnlyFileSystem,
} || posix.UnexpectedError;

/// A wrapper around the raw `syscall2` to provide a typed error set for the umount2(2) syscall.
pub const UmountError = error{
    /// EAGAIN: A call to umount2() with MNT_EXPIRE successfully marked an unbusy filesystem as expired.
    Again,
    /// EBUSY: The target could not be unmounted because it is busy.
    Busy,
    /// EFAULT: The target points outside the user address space.
    Fault,
    /// EINVAL: The target is not a mount point or is locked.
    InvalidValue,
    /// ENAMETOOLONG: A pathname was longer than MAXPATHLEN.
    NameTooLong,
    /// ENOENT: A pathname was empty or had a nonexistent component.
    NoEntry,
    /// ENOMEM: The kernel could not allocate memory.
    NoMemory,
    /// EPERM: The caller does not have the required privileges.
    PermissionDenied,
} || posix.UnexpectedError;

/// Mounts a filesystem.
/// This function wraps the raw `mount` syscall to return a typed `MountError`.
pub fn mountZ(
    special: [*:0]const u8,
    dir: [*:0]const u8,
    fstype: ?[*:0]const u8,
    flags: u32,
    data: usize,
) MountError!void {
    const rc = linux.mount(special, dir, fstype, flags, data);
    return switch (posix.errno(rc)) {
        .SUCCESS => {},
        .ACCES => error.Access,
        .BUSY => error.Busy,
        .FAULT => error.Fault,
        .INVAL => error.InvalidValue,
        .LOOP => error.Loop,
        .MFILE => error.FileTableOverflow,
        .NAMETOOLONG => error.NameTooLong,
        .NODEV => error.NoDevice,
        .NOENT => error.NoEntry,
        .NOMEM => error.NoMemory,
        .NOTBLK => error.NotBlockDevice,
        .NOTDIR => error.NotDirectory,
        .NXIO => error.NoDeviceOrAddress,
        .PERM => error.PermissionDenied,
        .ROFS => error.ReadOnlyFileSystem,
        else => |e| posix.unexpectedErrno(e),
    };
}

/// Unmounts a filesystem with the specified flags.
/// This function wraps the raw `umount2` syscall to return a typed `UmountError`.
pub fn umount2Z(special: [*:0]const u8, flags: u32) UmountError!void {
    const rc = linux.umount2(special, flags);
    return switch (posix.errno(rc)) {
        .SUCCESS => {},
        .AGAIN => error.Again,
        .BUSY => error.Busy,
        .FAULT => error.Fault,
        .INVAL => error.InvalidValue,
        .NAMETOOLONG => error.NameTooLong,
        .NOENT => error.NoEntry,
        .NOMEM => error.NoMemory,
        .PERM => error.PermissionDenied,
        else => |e| posix.unexpectedErrno(e),
    };
}

/// A typed error set for failures from the chroot(2) syscall.
pub const ChrootError = error{
    /// EACCES: Search permission is denied on a component of the path prefix.
    Access,
    /// EFAULT: The path points outside the process's accessible address space.
    Fault,
    /// EIO: An I/O error occurred.
    InputOutput,
    /// ELOOP: Too many symbolic links were encountered in resolving the path.
    Loop,
    /// ENAMETOOLONG: The path is too long.
    NameTooLong,
    /// ENOENT: The path does not exist.
    NoEntry,
    /// ENOMEM: Insufficient kernel memory was available.
    NoMemory,
    /// ENOTDIR: A component of the path is not a directory.
    NotDirectory,
    /// EPERM: The caller has insufficient privilege to perform the operation.
    PermissionDenied,
} || posix.UnexpectedError;

/// Changes the root directory of the calling process to the specified path.
/// This function wraps the raw `chroot` syscall to return a typed `ChrootError`.
pub fn chrootZ(path: [*:0]const u8) ChrootError!void {
    // The chroot syscall returns 0 on success and -1 on error.
    const rc = linux.chroot(path);

    return switch (posix.errno(rc)) {
        .SUCCESS => {}, // Success, return void.
        .ACCES => error.Access,
        .FAULT => error.Fault,
        .IO => error.InputOutput,
        .LOOP => error.Loop,
        .NAMETOOLONG => error.NameTooLong,
        .NOENT => error.NoEntry,
        .NOMEM => error.NoMemory,
        .NOTDIR => error.NotDirectory,
        .PERM => error.PermissionDenied,
        // Forward any other unexpected errno to the caller.
        else => |e| posix.unexpectedErrno(e),
    };
}

const std = @import("std");
const fs = std.fs;
const mem = std.mem;
const posix = std.posix;
const linux = std.os.linux;
const Chroot = @This();
const Allocator = std.mem.Allocator;
const ArenaAllocator = std.heap.ArenaAllocator;
