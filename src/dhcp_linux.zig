const std = @import("std");
const posix = std.posix;
const linux = std.os.linux;
const BPF = std.os.linux.BPF;

const SockFilter = extern struct {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
};

const SockFprog = extern struct {
    len: u16,
    filter: [*]const SockFilter,
};

fn statement(code: u16, k: u32) SockFilter {
    return .{ .code = code, .jt = 0, .jf = 0, .k = k };
}

fn jump(code: u16, k: u32, jt: u8, jf: u8) SockFilter {
    return .{ .code = code, .jt = jt, .jf = jf, .k = k };
}

const ETH_HLEN = 14;
const IP_MF_OFFSET_MASK = 0x1fff; // IP fragment mask, to ignore IP fragments.
const DHCP_PORTS: u32 = (67 << 16) | 68; // 67 → 68

// BPF filter for AF_PACKET, for src port 67 and dst port 68.
const dhcp_offer = [_]SockFilter{
    // All jumps are past ACCEPT, to the DROP at the very end.

    // A = ethertype (u16 at offset 12)
    // DROP if (A != ETH_P_IP)
    statement(BPF.LD | BPF.H | BPF.ABS, 12),
    jump(BPF.JMP | BPF.JEQ | BPF.K, linux.ETH.P.IP, 0, 8),

    // A = ip.protocol (u8 at offset 14 + 9)
    // DROP if (A != IPPROTO_UDP)
    statement(BPF.LD | BPF.B | BPF.ABS, ETH_HLEN + 9),
    jump(BPF.JMP | BPF.JEQ | BPF.K, linux.IPPROTO.UDP, 0, 6),

    // A = ip.flags_frag (u16 at offset 14 + 6)
    // DROP if (A & 0x1fff != 0), ignore IP fragments
    statement(BPF.LD | BPF.H | BPF.ABS, ETH_HLEN + 6),
    jump(BPF.JMP | BPF.JSET | BPF.K, IP_MF_OFFSET_MASK, 4, 0),

    // X = ip_header_len = 4 * (buf[14] & 0x0f)
    // A = udp.src_port << 16 | udp.dst_port (u32 at offset 14 + X)
    // DROP if (A != (67 << 16 | 68)), if for a different pair of ports than DHCP_PORTS
    statement(BPF.LDX | BPF.B | BPF.MSH, ETH_HLEN),
    statement(BPF.LD | BPF.W | BPF.IND, ETH_HLEN),
    jump(BPF.JMP | BPF.JEQ | BPF.K, DHCP_PORTS, 0, 1),
    statement(BPF.RET | BPF.K, 1500), // ACCEPT up to 1500 bytes
    statement(BPF.RET | BPF.K, 0), // DROP
};

const SO_ATTACH_FILTER = 26;

/// filterForDhcpResponses attaches a BPF filter on the given socket.
/// It will let DHCP responses (as indicated by source and destination port)
/// pass and filter everything else out.
///
/// Use this before binding the socket.
pub fn filterForDhcpResponses(sock: linux.fd_t) !void {
    const prog = SockFprog{
        .len = dhcp_offer.len,
        .filter = &dhcp_offer,
    };
    const rc = linux.setsockopt(
        sock,
        posix.SOL.SOCKET,
        SO_ATTACH_FILTER,
        std.mem.asBytes(&prog),
        @sizeOf(SockFprog),
    );
    if (linux.errno(rc) != .SUCCESS) return error.SocketFilterFailed;
}
