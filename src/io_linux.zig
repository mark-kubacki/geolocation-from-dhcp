const std = @import("std");
const linux = std.os.linux;

/// writeFile works like Go’s io.WriteFile.
pub fn writeFile(path: [:0]const u8, result: []const u8, mode: linux.mode_t) !void {
    var fd: linux.fd_t = 0;
    {
        const flags: linux.O = .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true, .CLOEXEC = true };
        const rc = linux.openat(linux.AT.FDCWD, path.ptr, flags, mode);
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
pub fn writeFileIfChanged(path: [:0]const u8, result: []const u8, mode: linux.mode_t) !void {
    // On errors still pass to writeFile because those could be salvageable there.
    const matches = eqlFileContents(path, result) catch false;
    if (matches) return;

    try writeFile(path, result, mode);
}

/// eqlFileContents tells whether the file contents match those given by |data|.
pub fn eqlFileContents(path: [:0]const u8, data: []const u8) !bool {
    const flags: linux.O = .{ .ACCMODE = .RDONLY, .CLOEXEC = true };
    const rc = linux.openat(linux.AT.FDCWD, path.ptr, flags, 0);
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
