pub const DownloadPayload = c.dload_payload;
pub const Handle = c.alpm_handle_t;

// Compute the SHA-256 message digest of a file.
// @param path file path of file to compute SHA256 digest of
// @param output string to hold computed SHA256 digest
// @return 0 on success, 1 on file open error, 2 on file read error
export fn sha256_file(path: [*:0]const u8, output: [*:0]u8) c_int {
    var file = std.fs.cwd().openFileZ(path, .{}) catch return -1;
    defer file.close();
    var buf_reader: [buf_size]u8 = undefined;
    var buf_hasher: [buf_size]u8 = undefined;
    var reader = file.reader(&buf_reader);
    var sha256_writer: std.Io.Writer.Hashing(Sha256) = .init(&buf_hasher);
    _ = reader.interface.streamRemaining(&sha256_writer.writer) catch return -1;
    sha256_writer.writer.flush() catch unreachable;
    sha256_writer.hasher.final(output[0..Sha256.digest_length]);
    return 0;
}

// Compute the MD5 message digest of a file.
// @param path file path of file to compute  MD5 digest of
// @param output string to hold computed MD5 digest
// @return 0 on success, 1 on file open error, 2 on file read error
export fn md5_file(path: [*:0]const u8, output: [*:0]u8) c_int {
    var file = std.fs.cwd().openFileZ(path, .{}) catch return -1;
    defer file.close();
    var buf_reader: [buf_size]u8 = undefined;
    var buf_hasher: [buf_size]u8 = undefined;
    var reader = file.reader(&buf_reader);
    var md5_writer: std.Io.Writer.Hashing(Md5) = .init(&buf_hasher);
    _ = reader.interface.streamRemaining(&md5_writer.writer) catch return -1;
    md5_writer.writer.flush() catch unreachable;
    md5_writer.hasher.final(output[0..Md5.digest_length]);
    return 0;
}

export fn alpm_fetch_pkgurl(
    handle: [*c]c.alpm_handle_t,
    urls: [*c]c.alpm_list_t,
    fetched: [*c][*c]c.alpm_list_t,
) c_int {
    var arena: std.heap.ArenaAllocator = .init(std.heap.c_allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    if (handle == null) return -1;
    if (fetched.* == null) {
        handle.*.pm_errno = c.ALPM_ERR_WRONG_ARGS;
        return -1;
    }
    errdefer {
        c.alpm_list_free_inner(fetched.*, c.free);
        c.alpm_list_free(fetched.*);
    }
    const cachedir = c._alpm_filecache_setup(handle);
    const temporary_cachedir = c._alpm_temporary_download_dir_setup(cachedir, handle.*.sandboxuser);
    if (temporary_cachedir == null) {
        handle.*.pm_errno = c.ALPM_ERR_SYSTEM;
        return -1;
    }
    defer {
        c._alpm_remove_temporary_download_dir(temporary_cachedir);
        c.free(temporary_cachedir);
    }

    var payloads: alpm.List(*alpm.DownloadPayload) = .{};
    var urls_list: alpm.StringList = .{ .list = urls };
    var it_urls = urls_list.iterator();
    const siglevel: alpm.SigLevel = @bitCast(handle.*.siglevel);

    while (it_urls.next()) |url_cstr| {
        const url = mem.span(url_cstr);
        const uri = std.Uri.parse(url) catch {
            handle.*.pm_errno = c.ALPM_ERR_WRONG_ARGS;
            return -1;
        };
        var basename_buf: [std.fs.max_name_bytes]u8 = undefined;
        const path_raw = uri.path.toRaw(&basename_buf) catch {
            handle.*.pm_errno = c.ALPM_ERR_WRONG_ARGS;
            return -1;
        };
        const basename = std.fs.path.basenamePosix(path_raw);
        const filepath_maybe = fileCacheFindUrl(gpa, handle, basename) catch {
            return -1;
        };
        if (filepath_maybe) |filepath| {
            _ = c.alpm_list_append(fetched, @ptrCast(@alignCast(filepath.ptr)));
        } else {
            const payload = gpa.create(c.dload_payload) catch {
                handle.*.pm_errno = c.ALPM_ERR_MEMORY;
                return -1;
            };
            payload.fileurl = gpa.dupeZ(u8, url) catch {
                handle.*.pm_errno = c.ALPM_ERR_MEMORY;
                return -1;
            };
            payload.remote_name = gpa.dupeZ(u8, basename) catch {
                handle.*.pm_errno = c.ALPM_ERR_MEMORY;
                return -1;
            };
            payloads.add(gpa, payload) catch {
                handle.*.pm_errno = c.ALPM_ERR_MEMORY;
                return -1;
            };

            if (basename.len > 0 and mem.containsAtLeast(u8, basename, 1, ".pkg")) {
                payload.destfile_name = std.fs.path.joinZ(gpa, &.{
                    mem.span(temporary_cachedir),
                    basename,
                }) catch {
                    handle.*.pm_errno = c.ALPM_ERR_MEMORY;
                    return -1;
                };
                payload.tempfile_name = std.fs.path.joinZ(gpa, &.{
                    mem.span(temporary_cachedir),
                    basename,
                    ".part",
                }) catch {
                    handle.*.pm_errno = c.ALPM_ERR_MEMORY;
                    return -1;
                };
                payload.allow_resume = 1;
            } else {
                // TODO: Support unamed file download
                //payload.unlink_on_fail = 1;
                //payload.tempfile_openmode = "wb";
                handle.*.pm_errno = c.ALPM_ERR_WRONG_ARGS;
                return -1;
            }
            payload.handle = handle;
            payload.download_signature = @intFromBool(siglevel.package.required);
            payload.signature_optional = @intFromBool(siglevel.package.optional);
            payloads.add(gpa, payload) catch {
                handle.*.pm_errno = c.ALPM_ERR_MEMORY;
                return -1;
            };
        }
    }

    if (!payloads.empty()) {
        var event: c.alpm_event_t = .{ .type = c.ALPM_EVENT_PKG_RETRIEVE_START };
        event.pkg_retrieve.num = payloads.count();
        eventCallback(handle, &event);
        alpmDownload(handle, payloads, cachedir, temporary_cachedir) catch {
            handle.*.pm_errno = c.ALPM_ERR_RETRIEVE;
            event.type = c.ALPM_EVENT_PKG_RETRIEVE_FAILED;
            eventCallback(handle, &event);
            return -1;
        };
        event.type = c.ALPM_EVENT_PKG_RETRIEVE_DONE;
        eventCallback(handle, &event);
    }
    return 0;
}

export fn _alpm_dload_payload_reset(payload: [*c]c.dload_payload) void {
    if (payload == null) return;
    freeAndSetNull(&payload.*.remote_name);
    freeAndSetNull(&payload.*.tempfile_name);
    freeAndSetNull(&payload.*.destfile_name);
    freeAndSetNull(&payload.*.fileurl);
    freeAndSetNull(&payload.*.filepath);
    payload.* = mem.zeroes(c.dload_payload);
    return;
}

/// This function prepares for resumable downloads. It scans the cache directory
/// (`localpath`) for partially downloaded files and moves them to the expected
/// temporary file locations that libalpm will use, allowing the download to resume.
fn prepareDownloads(
    allocator: std.mem.Allocator,
    payloads: alpm.List(*alpm.DownloadPayload),
    localpath: []const u8,
    user: [*c]const u8,
) !void {
    const user_info = blk: {
        if (user) |user_str| {
            break :blk std.process.getUserInfo(mem.span(user_str)) catch |err| {
                log.warn("Could not get user info for '{s}': {t}", .{ user_str, err });
                return err;
            };
        } else {
            break :blk null;
        }
    };

    var it_payloads = payloads.iterator();
    while (it_payloads.next()) |payload| {
        // First, check if the *final* destination file already exists in the cache.
        // If it does, we record its modification time. This is used later to
        // determine if a download is needed at all.
        if (payload.destfile_name) |dest_fullname_cstr| {
            const dest_fullname = mem.span(dest_fullname_cstr);
            const filename = std.fs.path.basename(dest_fullname);
            const dest_path = try std.fs.path.join(allocator, &.{ localpath, filename });
            defer allocator.free(dest_path);

            if (std.fs.cwd().statFile(dest_path)) |stat| {
                if (stat.size != 0) {
                    payload.mtime_existing_file = @intCast(stat.mtime);
                }
            } else |_| {
                // File doesn't exist or we can't access it, which is fine.
            }
        }

        // Now, check if a *partial* download for this payload exists in the cache.
        // If it does, move it to the location libalpm expects for resuming.
        const src_partial_path = if (payload.tempfile_name) |p| mem.span(p) else continue;

        const filename = std.fs.path.basename(src_partial_path);
        const cache_path = try std.fs.path.join(allocator, &.{ localpath, filename });
        defer allocator.free(cache_path);

        // Check if the partial file in the cache is valid (exists and is not empty).
        const stat = std.fs.cwd().statFile(cache_path) catch continue;
        if (stat.size == 0) continue;

        // Move the partial file from the cache to the temp location.
        std.fs.cwd().rename(cache_path, src_partial_path) catch |err| {
            std.log.warn("could not move partial download '{s}' for resuming: {}", .{ cache_path, err });
            continue;
        };

        var src_file = try std.fs.cwd().openFile(src_partial_path, .{});
        defer src_file.close();

        // If a user was specified, change ownership of the partial file.
        if (user_info) |info| {
            try src_file.chown(info.uid, info.gid);
        }
    }
}

fn finalizeDownloads(
    allocator: std.mem.Allocator,
    payloads: alpm.List(*alpm.DownloadPayload),
    localpath: []const u8,
) !void {
    // The C code uses `ASSERT`s. We handle null payloads gracefully.
    var it_payloads = payloads.iterator();
    while (it_payloads.next()) |payload| {
        // Case 1: A temporary file (e.g., from a partial download) needs to be
        // moved into the final cache directory.
        if (payload.tempfile_name) |src_path_cstr| {
            const src_path = mem.span(src_path_cstr);
            const filename = std.fs.path.basename(src_path);
            const dest_path = try std.fs.path.join(allocator, &.{ localpath, filename });
            defer allocator.free(dest_path);

            // In Zig, we rename from a full source path to a full destination path.
            // TODO: currently we don't support partial download, once implemented,
            // handle errors here
            std.fs.cwd().rename(src_path, dest_path) catch {};
        }

        // Case 2: A file downloaded directly to a final destination name (but in a
        // temp dir) needs to be moved to the final cache directory.
        if (payload.destfile_name) |src_path_cstr| {
            log.debug("{s}: {s}", .{ @src().fn_name, src_path_cstr });
            const src_path = mem.span(src_path_cstr);
            const filename = std.fs.path.basename(src_path);
            const dest_path = try std.fs.path.join(allocator, &.{ localpath, filename });
            defer allocator.free(dest_path);

            std.fs.cwd().rename(src_path, dest_path) catch |err| {
                // The original C code ignores the error if a file with the same name
                // already existed, assuming it's because only the signature was
                // downloaded for a pre-existing package file.
                switch (err) {
                    error.PathAlreadyExists => |e| {
                        // However, if the file was NOT supposed to exist beforehand
                        // (`mtime_existing_file == 0`), then this is a real error.
                        if (payload.mtime_existing_file == 0) {
                            return e;
                        }
                    },
                    else => |e| {
                        // Any other error is a failure.
                        std.log.err("failed to move file '{s}' to '{s}': {}", .{ src_path, dest_path, err });
                        return e;
                    },
                }
            };

            // If a signature file was also downloaded, move it too.
            if (payload.download_signature > 0) {
                const sig_src_path = try std.fmt.allocPrint(allocator, "{s}.sig", .{src_path});
                defer allocator.free(sig_src_path);

                const sig_filename = try std.fmt.allocPrint(allocator, "{s}.sig", .{filename});
                defer allocator.free(sig_filename);

                const sig_dest_path = try std.fs.path.join(allocator, &.{ localpath, sig_filename });
                defer allocator.free(sig_dest_path);

                // We don't care about errors here, as the signature might not exist.
                try std.fs.cwd().rename(sig_src_path, sig_dest_path);
            }
        }
    }
}

fn alpmDownload(
    handle: [*c]c.alpm_handle_t,
    payloads: alpm.List(*alpm.DownloadPayload),
    localpath: [*c]const u8,
    temporary_localpath: [*c]const u8,
) !void {
    _ = localpath;
    var arena = std.heap.ArenaAllocator.init(std.heap.c_allocator);
    defer arena.deinit();
    var safe_allocator: std.heap.ThreadSafeAllocator = .{
        .child_allocator = arena.allocator(),
    };

    const gpa = safe_allocator.allocator();

    var fetch_files: std.array_list.Managed(*FetchFile) = .init(gpa);

    var thread_pool: std.Thread.Pool = undefined;
    try thread_pool.init(.{
        .allocator = gpa,
        .n_jobs = handle.*.parallel_downloads,
    });

    var wg: std.Thread.WaitGroup = .{};
    defer {
        thread_pool.waitAndWork(&wg);
        thread_pool.deinit();
    }
    var it_payloads = payloads.iterator();

    while (it_payloads.next()) |payload| {
        const fetch_file = try gpa.create(FetchFile);
        fetch_file.* = .{
            .url = null,
            .localpath = temporary_localpath,
            .payload = payload,
            .failure = undefined,
        };
        thread_pool.spawnWg(&wg, fetchWorker, .{
            handle, gpa, fetch_file,
        });
        try fetch_files.append(fetch_file);
    }

    var any_failures: bool = false;
    for (fetch_files.items) |fetch_file| {
        fetch_file.failure catch |err| {
            any_failures = true;
            if (fetch_file.payload.fileurl) |url| {
                log.err("failed to fetch url '{s}': {s}", .{
                    url, @errorName(err),
                });
            } else {
                log.err("failed to fetch path '{s}': {s}", .{
                    fetch_file.payload.filepath, @errorName(err),
                });
            }
        };
    }

    if (any_failures) return error.SomeDownloadsFailed;
}

const FetchFile = struct {
    url: [*c]const u8,
    localpath: [*c]const u8,
    payload: *alpm.DownloadPayload,
    failure: anyerror!void,
};

fn fetchWorker(
    handle: [*c]c.alpm_handle_t,
    gpa: mem.Allocator,
    fetch_file: *FetchFile,
) void {
    // TODO: retry support
    //for (0..5) |_| {
    //    fetchFileFailible(handle, gpa, fetch_file) catch |err| {
    //        fetch_file.failure = err;
    //        continue;
    //    };
    //}
    fetch_file.failure = fetchFileFailible(handle, gpa, fetch_file);
}

fn fetchFileFailible(
    handle: [*c]c.alpm_handle_t,
    gpa: mem.Allocator,
    fetch_file: *FetchFile,
) !void {
    if (fetch_file.payload.fileurl) |fileurl_cstr| {
        const url = try gpa.dupeZ(u8, mem.span(fileurl_cstr));
        try fetchFile(handle, url, fetch_file.localpath, fetch_file.payload.force);
        fetch_file.url = url.ptr;
    } else {
        var servers: alpm.StringList = .{ .list = fetch_file.payload.servers };
        var it_servers = servers.iterator();
        while (it_servers.next()) |server| {
            const url = try std.fmt.allocPrintSentinel(gpa, "{s}/{s}", .{ server, fetch_file.payload.filepath }, 0);
            try fetchFile(handle, url, fetch_file.localpath, fetch_file.payload.force);
            fetch_file.url = url;
            break;
        }
    }

    const is_signature_optional = fetch_file.payload.signature_optional == 1;
    if (fetch_file.payload.download_signature > 0) {
        if (fetch_file.url == null and !is_signature_optional) return error.NoUsableServer;
        const url = try std.fmt.allocPrintSentinel(gpa, "{s}.sig", .{fetch_file.url}, 0);
        fetchFile(handle, url.ptr, fetch_file.localpath, fetch_file.payload.force) catch |err| {
            if (!is_signature_optional) return err;
        };
    }
}

fn fetchFile(
    handle: [*c]c.alpm_handle_t,
    url: [*c]const u8,
    localpath: [*c]const u8,
    force: c_int,
) !void {
    if (handle.*.fetchcb.?(handle.*.fetchcb_ctx, url, localpath, force) != 0) {
        return error.FetchFailed;
    }
}

export fn _alpm_download(
    handle: [*c]c.alpm_handle_t,
    payloads: [*c]c.alpm_list_t,
    localpath: [*c]const u8,
    temporary_localpath: [*c]const u8,
) c_int {
    const payloads_list: alpm.List(*alpm.DownloadPayload) = .{ .list = payloads };
    const gpa = std.heap.c_allocator;
    prepareDownloads(gpa, payloads_list, mem.span(localpath), handle.*.sandboxuser) catch {
        handle.*.pm_errno = c.ALPM_ERR_RETRIEVE;
        return -1;
    };

    alpmDownload(handle, payloads_list, localpath, temporary_localpath) catch |err| {
        log.err("alpm download: {t}", .{err});
        handle.*.pm_errno = c.ALPM_ERR_RETRIEVE;
        return -1;
    };

    finalizeDownloads(gpa, payloads_list, mem.span(localpath)) catch |err| {
        log.err("finalize download: {t}", .{err});
        handle.*.pm_errno = c.ALPM_ERR_RETRIEVE;
        return -1;
    };

    return 0;
}

fn fileCacheFindUrl(gpa: mem.Allocator, handle: [*c]c.alpm_handle_t, filebase: []const u8) !?[:0]u8 {
    var cachedirs_list: alpm.StringList = .{ .list = handle.*.cachedirs };
    var it_cachedirs = cachedirs_list.iterator();
    while (it_cachedirs.next()) |cachedir_cstr| {
        var buf: [std.fs.max_path_bytes]u8 = undefined;
        const cachedir = mem.span(cachedir_cstr);
        const path = std.fmt.bufPrintZ(
            &buf,
            "{f}",
            .{std.fs.path.fmtJoin(&.{ cachedir, filebase })},
        ) catch |err| {
            handle.*.pm_errno = c.ALPM_ERR_WRONG_ARGS;
            return err;
        };
        const stat = std.fs.cwd().statFile(path) catch |err| switch (err) {
            error.FileNotFound => {
                c._alpm_log(
                    handle,
                    c.ALPM_LOG_WARNING,
                    "could not open '%s'\n: %s",
                    path.ptr,
                    @errorName(err).ptr,
                );
                return null;
            },
            error.AccessDenied => |e| {
                handle.*.pm_errno = c.ALPM_ERR_BADPERMS;
                return e;
            },
            else => |e| {
                handle.*.pm_errno = c.ALPM_ERR_SYSTEM;
                return e;
            },
        };
        if (stat.kind != .file) {
            handle.*.pm_errno = c.ALPM_ERR_NOT_A_FILE;
            c._alpm_log(
                handle,
                c.ALPM_LOG_WARNING,
                "cached pkg '%s' is not a regular file: mode=%i\n",
                path.ptr,
                stat.mode,
            );
            return null;
        }
        c._alpm_log(handle, c.ALPM_LOG_DEBUG, "found cached pkg: %s\n", path.ptr);
        const filepath = gpa.dupeZ(u8, path) catch |err| {
            handle.*.pm_errno = c.ALPM_ERR_MEMORY;
            return err;
        };
        return filepath;
    }
    return null;
}

fn freeAndSetNull(ptr: *?*anyopaque) void {
    c.free(ptr.*);
    ptr.* = null;
}

fn eventCallback(h: [*c]c.alpm_handle_t, e: [*c]c.alpm_event_t) void {
    if (h.*.eventcb) |eventcb| {
        eventcb(h.*.eventcb_ctx, e);
    }
}

const buf_size = 8192;
const std = @import("std");
const mem = std.mem;
const log = std.log;
const alpm = @import("alpm.zig");
const c = @import("c");
const Md5 = std.crypto.hash.Md5;
const Sha256 = std.crypto.hash.sha2.Sha256;
