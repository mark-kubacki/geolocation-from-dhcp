const std = @import("std");
const posix = std.posix;
const linux = std.os.linux;

const dhcp = @import("dhcp.zig");
const geo = @import("dhcp_geo.zig");
const ioutil = @import("io_linux.zig");

// GeoClue expects changes to this filename, see its: gclue-static-source.c
// We will prepend '/etc' to it or whatever is set in envvar CONFIGURATION_DIRECTORY.
const geolocation_filename = "geolocation";

const DHCP_DISCOVER_RETRIES = 3;
// Discard so many unrelated packets before retrying.
// On every packet the timeout is reset and you risk partaking on the traffic flow of
// a busy interface, so keep this value small.
const MAX_UNRELATED_PACKETS = 5;

fn printUsage() void {
    const usage =
        \\(c) 2026 Mark Kubacki
        \\
        \\Usage:
        \\  place this binary in /etc/NetworkManager/dispatcher.d/
        \\
        \\If you want to call it directly, for example under 'strace',
        \\give two arguments:
        \\  - interface name such as 'eth1'
        \\  - "dhcp4-change"
        \\
    ;
    _ = linux.write(posix.STDERR_FILENO, usage.ptr, usage.len);
}

pub fn main(init: std.process.Init.Minimal) u8 {
    var it = init.args.iterate();
    _ = it.skip(); // skip argv[0]
    const ifname = it.next() orelse "";
    const event = it.next() orelse "";
    if (ifname.len == 0 and event.len == 0) {
        printUsage();
        return 1;
    }
    if (ifname.len == 0) {
        // could be a connectivity-change or dns-change
        return 0; // ignore
    }
    if (!std.mem.eql(u8, event, "dhcp4-change")) {
        return 0; // ignore
    }

    // If we get a response, this buffer will hold the text to write.
    var result: [4100]u8 = @splat(0);
    var writer: std.Io.Writer = .fixed(&result);

    var found_any: bool = false;
    {
        // Scope this to close the socket as soon as possible to avoid
        // processing a large amount of network traffic.
        var disco = GeoDiscovery.forInterface(ifname) catch |err| {
            const errname = @errorName(err);
            _ = linux.write(posix.STDERR_FILENO, errname.ptr, errname.len);
            return 2;
        };
        defer _ = disco.close();

        disco.result_buffer = &writer;
        var timeout: isize = 3; // seconds
        for (0..DHCP_DISCOVER_RETRIES) |_| {
            disco.sendDiscover() catch |err| {
                const errname = @errorName(err);
                _ = linux.write(posix.STDERR_FILENO, errname.ptr, errname.len);
                return 3;
            };
            found_any = disco.receiveResponse(timeout) catch |err| {
                const errname = @errorName(err);
                _ = linux.write(posix.STDERR_FILENO, errname.ptr, errname.len);
                return 4;
            };
            timeout = 0; // receiveResponse will retain the old value and skip a syscall.
            if (found_any) {
                break;
            }
        }
    }
    if (!found_any) {
        // I am not sure about whether to return 0 or an error code
        // because most interfaces and setups won’t encounter a DHCP server
        // that serves geodata, or APs that set geodata.
        // Consider this value as subject to change.
        return 1;
    }

    const state_dir = blk: {
        const env = init.environ.getPosix("CONFIGURATION_DIRECTORY") orelse break :blk "/etc";
        break :blk if (env.len > 0) env else "/etc";
    };
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const geolcation_path = std.fmt.bufPrintSentinel(&path_buf, "{s}/{s}", .{ state_dir, geolocation_filename }, 0) catch unreachable;

    ioutil.writeFileIfChanged(geolcation_path, writer.buffered(), 0o644) catch |err| {
        const errname = @errorName(err);
        _ = linux.write(posix.STDERR_FILENO, errname.ptr, errname.len);
        return 6;
    };

    return 0;
}

pub const GeoDiscovery = struct {
    sock: linux.fd_t,
    ifindex: i32,
    src_mac: [6]u8,

    transaction_id: u32,
    result_buffer: ?*std.Io.Writer,

    pub fn forInterface(ifname: []const u8) !GeoDiscovery {
        if (ifname.len == 0 or ifname.len >= linux.IFNAMESIZE) {
            return error.InterfaceNotFound;
        }

        // We could set a protocol here and skip binding, go about to employ 'sendto' and 'recvfrom' our “raw” ethernet frame,
        // but then packages could be queueing up – for all interfaces no less. So, at the expense of another syscall, start with 0.
        const sock_rc = linux.socket(posix.AF.PACKET, linux.SOCK.RAW | linux.SOCK.CLOEXEC, 0);
        if (linux.errno(sock_rc) != .SUCCESS) return error.SocketOpenFailed; // EPERM if CAP_NET_RAW were missing.
        const sock: linux.fd_t = @intCast(sock_rc);
        errdefer _ = linux.close(sock);

        // We’ll need the MAC address of the interface in the DHCP payload.
        var ifr: linux.ifreq = std.mem.zeroes(linux.ifreq);
        @memcpy(ifr.ifrn.name[0..ifname.len], ifname);
        if (linux.ioctl(sock, linux.SIOCGIFINDEX, @intFromPtr(&ifr)) != 0) {
            return error.InterfaceNotFound;
        }
        const ifindex = ifr.ifru.ivalue;
        if (linux.ioctl(sock, linux.SIOCGIFHWADDR, @intFromPtr(&ifr)) != 0) {
            return error.MacAddressNotFound;
        }

        // Now clamp down the socket to the interface and set the protocol,
        // or else we’d be receiving packets meant for other interfaces,
        // unrelated DHCP offers among them.
        var sll = std.mem.zeroes(linux.sockaddr.ll);
        sll.family = linux.AF.PACKET;
        sll.protocol = std.mem.nativeToBig(u16, linux.ETH.P.IP);
        sll.ifindex = ifindex;
        const bind_rc = linux.bind(sock, @ptrCast(&sll), @sizeOf(linux.sockaddr.ll));
        if (linux.errno(bind_rc) != .SUCCESS) return error.SocketBindFailed;

        return .{
            .sock = sock,
            .ifindex = ifindex,
            .src_mac = ifr.ifru.hwaddr.data[0..6].*,
            .transaction_id = 0,
            .result_buffer = null,
        };
    }

    pub fn sendDiscover(self: *GeoDiscovery) !void {
        // Copy the comptime struct onto the stack and assign MAC via named fields.
        var frame = dhcp.template_frame;
        frame.eth.src_mac = self.src_mac;
        frame.dhcp.chaddr[0..6].* = self.src_mac;
        const rc = linux.getrandom(@ptrCast(&frame.dhcp.xid), @sizeOf(u32), 0);
        if (linux.errno(rc) != .SUCCESS) return error.GetRandomFailed;
        self.transaction_id = frame.dhcp.xid; // We will need it to identify the response.

        var sll: linux.sockaddr.ll = .{
            .family = linux.AF.PACKET,
            .protocol = std.mem.nativeToBig(u16, linux.ETH.P.IP),
            .ifindex = self.ifindex,
            .hatype = 0,
            .pkttype = 0,
            .halen = 6,
            .addr = .{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0, 0 },
        };

        // Cast the typed struct directly to a byte slice without serialization overhead.
        const raw_bytes = std.mem.asBytes(&frame);
        const send_rc = linux.sendto(self.sock, raw_bytes, raw_bytes.len, 0, @ptrCast(&sll), @sizeOf(linux.sockaddr.ll));
        if (linux.errno(send_rc) != .SUCCESS) return error.SocketSendToFailed;
    }

    pub fn receiveResponse(self: *GeoDiscovery, timeout: isize) !bool {
        if (timeout > 0) {
            const recv_timeout = posix.timeval{ .sec = 5, .usec = 0 };
            try posix.setsockopt(self.sock, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&recv_timeout));
        }

        var buf: [1500]u8 = undefined; // 1500 is about the size of an entire frame
        var src_ll: linux.sockaddr.ll = undefined;
        var src_len: linux.socklen_t = @sizeOf(linux.sockaddr.ll);
        for (0..MAX_UNRELATED_PACKETS) |_| { // Limit the number of unrelated packets we’re willing to receive.
            const n = linux.recvfrom(self.sock, &buf, buf.len, 0, @ptrCast(&src_ll), &src_len);
            switch (linux.errno(n)) {
                .SUCCESS => {},
                .AGAIN => return false, // Also due to the timeout if no packets were forthcoming.
                else => return error.SocketRecvFromFailed,
            }
            if (n < 282) continue;

            const ip_hdr_len = (@as(usize, buf[14] & 0x0F)) * 4;
            if (buf[23] != 17) continue; // Must be UDP

            const udp_offset = 14 + ip_hdr_len;
            const src_port = std.mem.readInt(u16, buf[udp_offset..][0..2], .big);
            const dst_port = std.mem.readInt(u16, buf[udp_offset + 2 ..][0..2], .big);
            if (src_port != 67 or dst_port != 68) continue;

            const recv = buf[udp_offset + 8 .. n];
            if (recv.len < 240) continue;

            const resp_xid = std.mem.readInt(u32, recv[4..8], .native);
            if (resp_xid != self.transaction_id) continue;

            return try self.parseDhcpOptions(recv[240..]);
        }
        return false;
    }

    fn parseDhcpOptions(self: *GeoDiscovery, opts: []const u8) !bool {
        var i: usize = 0;
        var found_any = false;

        while (i < opts.len) {
            const code = opts[i];
            if (code == 255) break;
            if (code == 0) {
                i += 1;
                continue;
            }
            if (i + 1 >= opts.len) break;

            const len = opts[i + 1];
            if (i + 2 + len > opts.len) break;
            // const val = opts[i + 2 .. i + 2 + len];

            switch (code) {
                99 => {
                    found_any = true;
                    if (self.result_buffer != null) {
                        var w = self.result_buffer.?;
                        try w.writeAll("# Option 99 is present\n");
                    }
                },
                123 => {
                    found_any = true;
                    const geodata = try geo.GeoConf123.parseDhcpOption(opts[i .. i + 2 + len]);
                    if (self.result_buffer != null) {
                        try geodata.format(self.result_buffer.?);
                    }
                },
                144 => {
                    found_any = true;
                    const geodata = try geo.GeoLoc144.parseDhcpOption(opts[i .. i + 2 + len]);
                    if (self.result_buffer != null) {
                        try geodata.format(self.result_buffer.?);
                    }
                },
                else => {},
            }
            i += 2 + len;
        }

        return found_any;
    }

    pub fn close(self: GeoDiscovery) usize {
        return linux.close(self.sock);
    }
};
