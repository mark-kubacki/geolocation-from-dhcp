const std = @import("std");

/// Request these DHCP Options. Must be an even number because the size of
/// Zig’s extern structs are rounded up and are not byte-granular.
const req_opts = [_]u8{ 99, 144 };

const EthHeader = extern struct {
    dst_mac: [6]u8,
    src_mac: [6]u8,
    ethertype: u16, // Big-endian
};

const IpVersionIhl = packed struct(u8) {
    /// Header length, multiply by 4.
    ///
    /// For a list of options see: https://www.iana.org/assignments/ip-parameters#ip-parameters-1
    ihl: u4 = 5,
    /// IPv4, though some jokers used to set this to 5 in attempts to game firewalls.
    version: u4 = 4,
};

const Ipv4Header = extern struct {
    ver_ihl: IpVersionIhl = .{},
    dscp_ecn: u8 = 0,
    total_len: u16, // Big-endian
    id: u16, // Big-endian
    flags_frag: u16 = 0,
    ttl: u8 = 64,
    protocol: u8 = 17, // UDP
    checksum: u16 = 0, // Big-endian
    src_ip: [4]u8 = .{ 0, 0, 0, 0 },
    dst_ip: [4]u8 = .{ 255, 255, 255, 255 },
};

fn ipv4Checksum(header: []const u8) u16 {
    var sum: u32 = 0;
    var i: usize = 0;
    while (i < header.len) : (i += 2) {
        sum += std.mem.readInt(u16, header[i..][0..2], .big);
    }
    while (sum >> 16 != 0) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return @truncate(~sum);
}

const UdpHeader = extern struct {
    src_port: u16, // Big-endian
    dst_port: u16, // Big-endian
    length: u16, // Big-endian
    checksum: u16 = 0,
};

const DhcpFlags = packed struct(u16) {
    reserved: u15 = 0,
    broadcast: u1 = 1,
};

const DhcpOptions = extern struct {
    // Option 53: DHCP Message Type = DISCOVER (1)
    msg_type_code: u8 = 53,
    msg_type_len: u8 = 1,
    msg_type_val: u8 = 1,
    // Option 55: Parameter Request List
    param_req_code: u8 = 55,
    param_req_len: u8 = req_opts.len,
    param_req_vals: [req_opts.len]u8 align(1) = req_opts,
    // Option 255: End
    end: u8 align(1) = 255,
};

const DhcpDiscoverPayload = extern struct {
    op: u8 = 1, // BOOTREQUEST
    htype: u8 = 1, // Ethernet
    hlen: u8 = 6,
    hops: u8 = 0,
    xid: u32, // Big-endian
    secs: u16 = 0,
    flags: u16, // Big-endian bitfield
    ciaddr: [4]u8 = .{ 0, 0, 0, 0 },
    yiaddr: [4]u8 = .{ 0, 0, 0, 0 },
    siaddr: [4]u8 = .{ 0, 0, 0, 0 },
    giaddr: [4]u8 = .{ 0, 0, 0, 0 },
    chaddr: [16]u8 = @splat(0),
    sname: [64]u8 = @splat(0),
    file: [128]u8 = @splat(0),
    magic_cookie: [4]u8 = .{ 99, 130, 83, 99 },
    options: DhcpOptions = .{},
};

const DhcpDiscoverFrame = extern struct {
    eth: EthHeader,
    ip: Ipv4Header align(1),
    udp: UdpHeader align(1),
    dhcp: DhcpDiscoverPayload align(1),

    /// newFrame gets you a DHCP DISCOVER frame, to be sent from the given MAC
    /// address, with a list with options to discover location data (subject to change).
    ///
    /// Use the transaction_id to learn which DHCP OFFER is the matching response.
    pub fn newFrame(transaction_id: u32, src_mac: [6]u8) DhcpDiscoverFrame {
        const ip_total_len: u16 = @sizeOf(Ipv4Header) + @sizeOf(UdpHeader) + @sizeOf(DhcpDiscoverPayload);
        const udp_total_len: u16 = @sizeOf(UdpHeader) + @sizeOf(DhcpDiscoverPayload);

        const flags_be = std.mem.nativeToBig(u16, @bitCast(DhcpFlags{ .broadcast = 1 }));

        var frame = DhcpDiscoverFrame{
            .eth = .{
                .dst_mac = .{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }, // 0xff… for broadcasts
                .src_mac = src_mac,
                .ethertype = std.mem.nativeToBig(u16, 0x0800),
            },
            .ip = .{
                .total_len = std.mem.nativeToBig(u16, ip_total_len),
                .id = std.mem.nativeToBig(u16, 0x1234),
            },
            .udp = .{
                .src_port = std.mem.nativeToBig(u16, 68),
                .dst_port = std.mem.nativeToBig(u16, 67),
                .length = std.mem.nativeToBig(u16, udp_total_len),
            },
            .dhcp = .{
                .xid = transaction_id,
                .flags = flags_be,
            },
        };
        frame.dhcp.chaddr[0..6].* = src_mac;

        // Compute IPv4 header checksum directly over the struct bytes at compile time
        const ip_bytes = std.mem.asBytes(&frame.ip);
        frame.ip.checksum = std.mem.nativeToBig(u16, ipv4Checksum(ip_bytes));

        return frame;
    }
};

// Compile-time layout assertions to guarantee zero unexpected padding
comptime {
    std.debug.assert(@sizeOf(EthHeader) == 14);
    std.debug.assert(@sizeOf(Ipv4Header) == 20);
    std.debug.assert(@sizeOf(UdpHeader) == 8);
    std.debug.assert(@sizeOf(DhcpOptions) == 6 + req_opts.len);
    std.debug.assert(@sizeOf(DhcpDiscoverPayload) == 240 + @sizeOf(DhcpOptions));
    std.debug.assert(@sizeOf(DhcpDiscoverFrame) == 288 + req_opts.len);
}

/// Ethernet frame to broadcast to receive the DHCP Options with location data.
///
/// Some fields need to be changed.
pub const template_frame: DhcpDiscoverFrame = DhcpDiscoverFrame.newFrame(
    0x12345678,
    .{ 0, 0, 0, 0, 0, 0 },
);
