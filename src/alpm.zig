pub const Handle = @import("alpm/Handle.zig");
pub const List = @import("alpm/list.zig").List;
pub const ListWrapper = @import("alpm/list.zig").ListWrapper;
pub const StringList = List([*:0]const u8);
pub const Database = @import("alpm/Database.zig");
pub const File = @import("alpm/File.zig");
pub const FileList = @import("alpm/FileList.zig");
pub const Package = @import("alpm/Package.zig");
pub const Group = @import("alpm/Group.zig");
pub const Depend = @import("alpm/Depend.zig");

const buf_size = 8192;

/// Represents the signature verification level for packages and databases.
/// This is a packed struct to map directly to the alpm_siglevel_t bitmask.
pub const SigLevel = packed struct(c_int) {
    // --- Package Flags ---
    package: packed struct(u4) {
        /// Packages require a signature.
        required: bool = true,

        /// Packages do not require a signature, but check packages that do have signatures.
        optional: bool = false,

        /// Allow packages with signatures that are marginal trust.
        marginal_ok: bool = false,

        /// Allow packages with signatures that are unknown trust.
        unknown: bool = false,
    } = .{},

    /// Padding for unused bits 4 through 9.
    _padding1: u6 = 0,

    // --- Database Flags ---
    database: packed struct(u4) {
        /// Databases require a signature.
        required: bool = false, // bit 10

        /// Databases do not require a signature, but check packages that do have signatures.
        optional: bool = true,

        /// Allow Databases with signatures that are marginal trust.
        marginal_ok: bool = false,

        /// Allow Databases with signatures that are unknown trust.
        unknown: bool = false,
    } = .{},

    /// Padding for unused bits 14 through 29.
    _padding2: u16 = 0,

    // --- Control Flag ---

    /// Use the default siglevel.
    use_default: bool = false, // bit 30

    /// Padding for the final unused bit to align to 32 bits.
    _padding3: u1 = 0,

    // Ensure at compile time that this struct is the size of a u32.
    comptime {
        std.debug.assert(@sizeOf(SigLevel) == @sizeOf(c_int));
    }
};

/// Flags for transaction behavior.
pub const TransactionFlags = packed struct(c_int) {
    no_deps: bool = false,
    _pad1: bool = false,
    no_save: bool = false,
    no_dep_version: bool = false,
    cascade: bool = false,
    recurse: bool = false,
    db_only: bool = false,
    no_hooks: bool = false,
    all_deps: bool = false,
    download_only: bool = false,
    no_scriptlet: bool = false,
    no_conflicts: bool = false,
    _pad12: bool = false,
    needed: bool = false,
    all_explicit: bool = false,
    unneeded: bool = false,
    recurse_all: bool = false,
    no_lock: bool = false,

    // Ensure at compile time that this struct is the size of a u32.
    comptime {
        std.debug.assert(@sizeOf(@This()) == @sizeOf(c_int));
    }
};

pub const Error = error{
    // System
    OutOfMemory,
    SystemFailure,
    PermissionDenied,
    FileNotFound,
    DirectoryNotFound,
    InvalidArgument,
    NotEnoughDiskSpace,

    // Interface
    NotInitialized,
    AlreadyInitialized,
    DatabaseLockFailed,

    // Databases
    DatabaseOpenFailed,
    DatabaseCreateFailed,
    DatabaseNotInitialized,
    DatabaseAlreadyRegistered,
    DatabaseNotFound,
    InvalidDatabase,
    InvalidDatabaseSignature,
    IncorrectDatabaseVersion,
    DatabaseWriteFailed,
    DatabaseRemoveEntryFailed,

    // Servers
    InvalidServerUrl,
    NoServersConfigured,

    // Transactions
    TransactionAlreadyInitialized,
    TransactionNotInitialized,
    DuplicateTarget,
    DuplicateFilename,
    TransactionNotPrepared,
    TransactionAborted,
    IncompatibleTransactionType,
    DatabaseNotLocked,
    TransactionHookFailed,

    // Packages
    PackageNotFound,
    PackageIgnored,
    InvalidPackage,
    InvalidPackageChecksum,
    InvalidPackageSignature,
    PackageMissingSignature,
    PackageOpenFailed,
    PackageRemoveFailed,
    InvalidPackageName,
    InvalidPackageArchitecture,

    // Signatures
    MissingSignature,
    InvalidSignature,

    // Dependencies
    UnsatisfiedDependencies,
    ConflictingDependencies,
    FileConflicts,

    // Miscellaneous
    FileRetrievalFailed,
    InvalidRegex,

    // External Libraries
    LibArchive,
    LibCurl,
    Gpgme,
    ExternalDownloaderFailed,

    // Missing compile-time features
    SignatureSupportNotCompiled,

    Unexpected,
};

/// Converts the C alpm_errno to the corresponding Zig error.
/// This function should only be called when a C function has already indicated failure.
/// Calling this when no error has occurred will result in `unreachable`.
pub fn errnoToError(err: c.alpm_errno_t) Error {
    return switch (err) {
        0 => unreachable,
        // System
        c.ALPM_ERR_MEMORY => error.OutOfMemory,
        c.ALPM_ERR_SYSTEM => error.SystemFailure,
        c.ALPM_ERR_BADPERMS => error.PermissionDenied,
        c.ALPM_ERR_NOT_A_FILE => error.FileNotFound,
        c.ALPM_ERR_NOT_A_DIR => error.DirectoryNotFound,
        c.ALPM_ERR_WRONG_ARGS => error.InvalidArgument,
        c.ALPM_ERR_DISK_SPACE => error.NotEnoughDiskSpace,

        // Interface
        c.ALPM_ERR_HANDLE_NULL => error.NotInitialized,
        c.ALPM_ERR_HANDLE_NOT_NULL => error.AlreadyInitialized,
        c.ALPM_ERR_HANDLE_LOCK => error.DatabaseLockFailed,

        // Databases
        c.ALPM_ERR_DB_OPEN => error.DatabaseOpenFailed,
        c.ALPM_ERR_DB_CREATE => error.DatabaseCreateFailed,
        c.ALPM_ERR_DB_NULL => error.DatabaseNotInitialized,
        c.ALPM_ERR_DB_NOT_NULL => error.DatabaseAlreadyRegistered,
        c.ALPM_ERR_DB_NOT_FOUND => error.DatabaseNotFound,
        c.ALPM_ERR_DB_INVALID => error.InvalidDatabase,
        c.ALPM_ERR_DB_INVALID_SIG => error.InvalidDatabaseSignature,
        c.ALPM_ERR_DB_VERSION => error.IncorrectDatabaseVersion,
        c.ALPM_ERR_DB_WRITE => error.DatabaseWriteFailed,
        c.ALPM_ERR_DB_REMOVE => error.DatabaseRemoveEntryFailed,

        // Servers
        c.ALPM_ERR_SERVER_BAD_URL => error.InvalidServerUrl,
        c.ALPM_ERR_SERVER_NONE => error.NoServersConfigured,

        // Transactions
        c.ALPM_ERR_TRANS_NOT_NULL => error.TransactionAlreadyInitialized,
        c.ALPM_ERR_TRANS_NULL => error.TransactionNotInitialized,
        c.ALPM_ERR_TRANS_DUP_TARGET => error.DuplicateTarget,
        c.ALPM_ERR_TRANS_DUP_FILENAME => error.DuplicateFilename,
        c.ALPM_ERR_TRANS_NOT_INITIALIZED => error.TransactionNotInitialized,
        c.ALPM_ERR_TRANS_NOT_PREPARED => error.TransactionNotPrepared,
        c.ALPM_ERR_TRANS_ABORT => error.TransactionAborted,
        c.ALPM_ERR_TRANS_TYPE => error.IncompatibleTransactionType,
        c.ALPM_ERR_TRANS_NOT_LOCKED => error.DatabaseNotLocked,
        c.ALPM_ERR_TRANS_HOOK_FAILED => error.TransactionHookFailed,

        // Packages
        c.ALPM_ERR_PKG_NOT_FOUND => error.PackageNotFound,
        c.ALPM_ERR_PKG_IGNORED => error.PackageIgnored,
        c.ALPM_ERR_PKG_INVALID => error.InvalidPackage,
        c.ALPM_ERR_PKG_INVALID_CHECKSUM => error.InvalidPackageChecksum,
        c.ALPM_ERR_PKG_INVALID_SIG => error.InvalidPackageSignature,
        c.ALPM_ERR_PKG_MISSING_SIG => error.PackageMissingSignature,
        c.ALPM_ERR_PKG_OPEN => error.PackageOpenFailed,
        c.ALPM_ERR_PKG_CANT_REMOVE => error.PackageRemoveFailed,
        c.ALPM_ERR_PKG_INVALID_NAME => error.InvalidPackageName,
        c.ALPM_ERR_PKG_INVALID_ARCH => error.InvalidPackageArchitecture,

        // Signatures
        c.ALPM_ERR_SIG_MISSING => error.MissingSignature,
        c.ALPM_ERR_SIG_INVALID => error.InvalidSignature,

        // Dependencies
        c.ALPM_ERR_UNSATISFIED_DEPS => error.UnsatisfiedDependencies,
        c.ALPM_ERR_CONFLICTING_DEPS => error.ConflictingDependencies,
        c.ALPM_ERR_FILE_CONFLICTS => error.FileConflicts,

        // Miscellaneous
        c.ALPM_ERR_RETRIEVE => error.FileRetrievalFailed,
        c.ALPM_ERR_INVALID_REGEX => error.InvalidRegex,

        // External Libraries
        c.ALPM_ERR_LIBARCHIVE => error.LibArchive,
        c.ALPM_ERR_LIBCURL => error.LibCurl,
        c.ALPM_ERR_GPGME => error.Gpgme,
        c.ALPM_ERR_EXTERNAL_DOWNLOAD => error.ExternalDownloaderFailed,

        // Missing compile-time features
        c.ALPM_ERR_MISSING_CAPABILITY_SIGNATURES => error.SignatureSupportNotCompiled,

        // Handle any unknown error codes that may appear in future versions.
        else => error.Unexpected,
    };
}

// Compute the SHA-256 message digest of a file.
// @param path file path of file to compute SHA256 digest of
// @param output string to hold computed SHA256 digest
// @return 0 on success, 1 on file open error, 2 on file read error
export fn sha256_file(path: [*:0]const u8, output: [*:0]u8) c_int {
    var file = std.fs.cwd().openFileZ(path, .{}) catch return -1;
    defer file.close();
    var buf_reader: [buf_size]u8 = undefined;
    var reader = file.reader(&buf_reader);
    var output_writer: std.Io.Writer = .fixed(output[0..Sha256.digest_length]);
    var sha256: Sha256 = .init(.{});
    var sha256_writer = std.Io.Writer.hashed(&output_writer, &sha256, &.{});
    _ = reader.interface.streamRemaining(&sha256_writer.writer) catch return -1;
    sha256.final(output_writer.buffered()[0..Sha256.digest_length]);
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
    var reader = file.reader(&buf_reader);
    var output_writer: std.Io.Writer = .fixed(output[0..Sha256.digest_length]);
    var md5: Md5 = .init(.{});
    var md5_writer = std.Io.Writer.hashed(&output_writer, &md5, &.{});
    _ = reader.interface.streamRemaining(&md5_writer.writer) catch return -1;
    md5.final(output_writer.buffered()[0..Md5.digest_length]);
    return 0;
}

const std = @import("std");
const Md5 = std.crypto.hash.Md5;
const Sha256 = std.crypto.hash.sha2.Sha256;
const c = @import("c");

test {
    _ = Handle;
}
