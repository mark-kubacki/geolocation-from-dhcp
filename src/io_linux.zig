const std = @import("std");
const linux = std.os.linux;

// These are for linux.openat2, and in doing so we’re imitating
// my library in Go, specifically os/fs/directory_linux.go
const RESOLVE_NO_XDEV: u64 = 0x01;
const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
const RESOLVE_NO_SYMLINKS: u64 = 0x04;
const RESOLVE_BENEATH: u64 = 0x08;
const RESOLVE_IN_ROOT: u64 = 0x10;
const RESOLVE_CACHED: u64 = 0x20;

const open_how = extern struct {
    flags: u64,
    mode: u64,
    resolve: u64,

    pub fn new(from: struct { flags: linux.O, mode: linux.mode_t, resolve: u64 }) open_how {
        var t = std.mem.zeroes(open_how);
        t.flags = @as(u32, @bitCast(from.flags));
        t.mode = @as(u32, @bitCast(from.mode));
        t.resolve = from.resolve;
        return t;
    }
};

fn openat2(dirfd: linux.fd_t, path: [*:0]const u8, how: *const open_how) usize {
    return linux.syscall4(.openat2, @as(usize, @bitCast(@as(isize, dirfd))), @intFromPtr(path), @intFromPtr(how), @sizeOf(open_how));
}

/// writeFile works like Go’s io.WriteFile.
pub fn writeFile(dirfd: linux.fd_t, basename: [:0]const u8, result: []const u8, mode: linux.mode_t) !void {
    var fd: linux.fd_t = 0;
    {
        const rc = openat2(dirfd, basename, &open_how.new(.{
            .flags = .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true, .CLOEXEC = true },
            .mode = mode,
            .resolve = RESOLVE_BENEATH,
        }));
        if (linux.errno(rc) != .SUCCESS) return error.FileOpenFailed;
        fd = @intCast(rc);
        errdefer _ = linux.close(fd);

        var written: usize = 0;
        while (written < result.len) {
            const w_rc = linux.write(fd, result[written..].ptr, result.len - written);
            switch (linux.errno(w_rc)) {
                .SUCCESS => written += @intCast(w_rc),
                .INTR => continue,
                else => return error.FileWriteFailed,
            }
        }
    }

    switch (linux.errno(linux.close(fd))) {
        .SUCCESS => {},
        .IO => return error.InputOutput,
        .NOSPC => return error.NoSpaceLeft,
        .DQUOT => return error.DiskQuota,
        // I’ve found using this error confuses devs less than a “FileCloseFailed”
        // due to ‘close’ throwing errors that should be attributed to ‘write.’
        else => return error.FileWriteFailed,
    }
}

/// writeFileIfChanged calls writeFile only if the referenced file’s contents are
/// different from what would be written, or if the file is a special file.
///
/// For when you don’t want to wear down a disk, such as on embedded devices or with memory cards.
pub fn writeFileIfChanged(dirname: [:0]const u8, basename: [:0]const u8, result: []const u8, mode: linux.mode_t) !void {
    const dir_rc = linux.openat(linux.AT.FDCWD, dirname.ptr, .{ .PATH = true, .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true }, 0);
    if (linux.errno(dir_rc) != .SUCCESS) return error.DirOpenFailed;
    const dir_fd: linux.fd_t = @intCast(dir_rc);
    defer _ = linux.close(dir_fd);

    // On errors still pass to writeFile because those could be salvageable there.
    const matches = eqlFileContents(dir_fd, basename, result) catch false;
    if (matches) return;

    try writeFile(dir_fd, basename, result, mode);
}

/// eqlFileContents tells whether the file contents match those given by |data|.
pub fn eqlFileContents(dirfd: linux.fd_t, basename: [:0]const u8, data: []const u8) !bool {
    const rc = openat2(dirfd, basename, &open_how.new(.{
        .flags = .{ .ACCMODE = .RDONLY, .CLOEXEC = true },
        .mode = 0,
        .resolve = RESOLVE_BENEATH,
    }));
    switch (linux.errno(rc)) {
        .SUCCESS => {},
        .NOENT => return false, // in Rust ErrorKind::NotFound
        else => return error.FileOpenFailed,
    }
    const fd: linux.fd_t = @intCast(rc);
    defer _ = linux.close(fd);

    // Stat after actually opening the file: to work on its filedesc and thereby avoiding a possible
    // race condition (meanwhile someone could have replaced the file).
    var st: linux.Statx = undefined;
    const stat_rc = linux.statx(fd, "", linux.AT.EMPTY_PATH, .{ .SIZE = true }, &st);
    if (linux.errno(stat_rc) != .SUCCESS) return error.FileStatFailed;
    if (st.size < 0) return error.UnexpectedFileStat;
    const file_size: usize = @intCast(st.size);

    if (file_size != data.len) return false;
    if (file_size == 0) return true;

    // After exhausting these trivial comparisons, go for the actual content.
    // Use mmap to avoid a potentially expensive buffer allocation.
    // XXX(mark): Roll over finite sized chunks doing this, like 32 MiB,
    //   to avoid errors such as NOMEM.
    const mmap_rc = linux.mmap(null, file_size, .{ .READ = true }, .{ .TYPE = .PRIVATE }, fd, 0);
    if (linux.errno(mmap_rc) != .SUCCESS) return error.UnableToMmapFile;
    const mapped_ptr: [*]align(std.heap.page_size_min) const u8 = @ptrFromInt(mmap_rc);
    const mapped_slice = mapped_ptr[0..file_size];
    defer _ = linux.munmap(mapped_ptr, file_size);

    return std.mem.eql(u8, mapped_slice, data);
}
