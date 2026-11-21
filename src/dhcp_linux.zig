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
const IP_HLEN = 20;
const UDP_HLEN = 8;
const DHCP_OFF = ETH_HLEN + IP_HLEN + UDP_HLEN; // 42
/// Minimum size of the packet to have the DHCP OFFER we want
const MIN_DHCP_OFFER_LEN = DHCP_OFF + 244;

const IP_MF_OFFSET_MASK = 0x1fff; // IP fragment mask, to ignore IP fragments.
const DHCP_PORTS: u32 = (67 << 16) | 68; // 67 → 68
const DHCP_MAGIC_COOKIE: u32 = 0x63825363;
const DHCP_OPT_MSG_TYPE_OFFER: u32 = (53 << 16) | (1 << 8) | 2; // Option 53 (Msg Type), Len 1, Value 2 (DHCPOFFER)

/// BPF filter for AF_PACKET, for DHCP OFFER payload (replies)
/// from src port 67 to dst port 68.
const bpf_filter = [_]SockFilter{
    // All jumps are past ACCEPT, to the DROP at the very end.

    // A = skb->len (total captured frame length on the wire)
    // DROP if (A < MIN_DHCP_OFFER_LEN)
    statement(BPF.LD | BPF.W | BPF.LEN, 0),
    jump(BPF.JMP | BPF.JGE | BPF.K, MIN_DHCP_OFFER_LEN, 0, 21),

    // A = ethertype (u16 at offset 12)
    // DROP if (A != ETH_P_IP)
    statement(BPF.LD | BPF.H | BPF.ABS, 12),
    jump(BPF.JMP | BPF.JEQ | BPF.K, linux.ETH.P.IP, 0, 19),

    // A = ip.version_ihl (u8 at offset 14)
    // DROP if (A != 0x45) → IPv4 and header length != 20 bytes, presumably due to Options
    statement(BPF.LD | BPF.B | BPF.ABS, ETH_HLEN),
    jump(BPF.JMP | BPF.JEQ | BPF.K, 0x45, 0, 17),

    // A = ip.tot_len (u16 at offset 14 + 2)
    // DROP if (A < MIN_DHCP_OFFER_LEN - ETH_HLEN) → IP payload must cover UDP + DHCP OFFER
    statement(BPF.LD | BPF.H | BPF.ABS, ETH_HLEN + 2),
    jump(BPF.JMP | BPF.JGE | BPF.K, MIN_DHCP_OFFER_LEN - ETH_HLEN, 0, 15),

    // A = ip.protocol (u8 at offset 14 + 9)
    // DROP if (A != IPPROTO_UDP)
    statement(BPF.LD | BPF.B | BPF.ABS, ETH_HLEN + 9),
    jump(BPF.JMP | BPF.JEQ | BPF.K, linux.IPPROTO.UDP, 0, 13),

    // A = ip.flags_frag (u16 at offset 14 + 6)
    // DROP if (A & 0x1fff != 0) → ignore IP fragments
    statement(BPF.LD | BPF.H | BPF.ABS, ETH_HLEN + 6),
    jump(BPF.JMP | BPF.JSET | BPF.K, IP_MF_OFFSET_MASK, 11, 0),

    // A = udp.src_port << 16 | udp.dst_port (u32 at offset 14 + 20)
    // DROP if (A != (67 << 16 | 68)) → if for a different pair of ports than DHCP_PORTS
    statement(BPF.LD | BPF.W | BPF.ABS, ETH_HLEN + IP_HLEN),
    jump(BPF.JMP | BPF.JEQ | BPF.K, DHCP_PORTS, 0, 9),

    // A = udp.len (u16 at offset 14 + 20 + 4)
    // DROP if (A < MIN_DHCP_OFFER_LEN - ETH_HLEN - IP_HLEN) → UDP payload must cover DHCP OFFER
    statement(BPF.LD | BPF.H | BPF.ABS, ETH_HLEN + IP_HLEN + 4),
    jump(BPF.JMP | BPF.JGE | BPF.K, MIN_DHCP_OFFER_LEN - ETH_HLEN - IP_HLEN, 0, 7),

    // A = dhcp.op (u8 at offset 42 + 0)
    // DROP if (A != 2) → BOOTREPLY
    statement(BPF.LD | BPF.B | BPF.ABS, DHCP_OFF),
    jump(BPF.JMP | BPF.JEQ | BPF.K, 2, 0, 5),

    // A = dhcp.magic_cookie (u32 at offset 42 + 236)
    // DROP if (A != DHCP_MAGIC_COOKIE)
    statement(BPF.LD | BPF.W | BPF.ABS, DHCP_OFF + 236),
    jump(BPF.JMP | BPF.JEQ | BPF.K, DHCP_MAGIC_COOKIE, 0, 3),

    // A = first 3 bytes of DHCP options (u32 >> 8 at offset 42 + 240)
    // DROP if (A != 0x350102) → Option 53 (Message Type), Length 1, Value 2 (DHCPOFFER)
    statement(BPF.LD | BPF.W | BPF.ABS, DHCP_OFF + 240),
    statement(BPF.ALU | BPF.RSH | BPF.K, 8),
    jump(BPF.JMP | BPF.JEQ | BPF.K, DHCP_OPT_MSG_TYPE_OFFER, 0, 1),
    statement(BPF.RET | BPF.K, 1500), // ACCEPT up to 1500 bytes
    statement(BPF.RET | BPF.K, 0), // DROP
};

const filter_for_dhcp_offers = SockFprog{
    .len = bpf_filter.len,
    .filter = &bpf_filter,
};

const SO_ATTACH_FILTER = 26;

/// filterForDhcpResponses attaches a BPF filter on the given socket.
/// It will let DHCP responses (as indicated by source and destination port)
/// pass and filter everything else out.
///
/// Use this before binding the socket.
pub fn filterForDhcpResponses(sock: linux.fd_t) !void {
    const rc = linux.setsockopt(
        sock,
        posix.SOL.SOCKET,
        SO_ATTACH_FILTER,
        std.mem.asBytes(&filter_for_dhcp_offers),
        @sizeOf(SockFprog),
    );
    if (linux.errno(rc) != .SUCCESS) return error.SocketFilterFailed;
}
