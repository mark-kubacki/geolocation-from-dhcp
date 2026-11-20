const std = @import("std");

pub const AltitudeUnit = enum(u4) {
    unknown = 0,
    meters = 1,
    floors = 2,
    _,
};

/// Geodetic system those coordinates are given in.
pub const Reference = enum(u3) {
    reserved = 0,
    wgs84 = 1,
    nad83_navd88 = 2,
    nad83_mllw = 3,
    _,
};

const MetricUncertainty = struct {
    north_south_meters: f64,
    east_west_meters: f64,
};

/// Converts angular uncertainty (in degrees) at a given latitude (in degrees)
/// into meters using the WGS84 reference ellipsoid.
fn degreesToMetersWGS84(uncertainty_deg: f64, latitude_deg: f64) MetricUncertainty {
    // WGS84 defining parameters
    const a: f64 = 6378137.0; // Semi-major axis in meters
    const f: f64 = 1.0 / 298.257223563; // Flattening
    const e2: f64 = 2.0 * f - f * f; // First eccentricity squared

    const lat_rad = std.math.degreesToRadians(latitude_deg);
    const unc_rad = std.math.degreesToRadians(uncertainty_deg);

    const sin_lat = @sin(lat_rad);
    const cos_lat = @cos(lat_rad);

    // Denominator term: 1 - e^2 * sin^2(lat)
    const denom = 1.0 - e2 * sin_lat * sin_lat;
    const sqrt_denom = @sqrt(denom);

    // Meridional radius of curvature (North-South)
    const m = (a * (1.0 - e2)) / (denom * sqrt_denom);

    // Prime vertical radius of curvature (East-West)
    const n = a / sqrt_denom;

    return .{
        .north_south_meters = unc_rad * m,
        .east_west_meters = unc_rad * n * cos_lat,
    };
}

pub const ParseError = error{
    InvalidOptionCode,
    InvalidOptionLength,
    UnsupportedVersion,
    InvalidCoordinates,
};

/// Shared geographic fields common to both DHCP Option 123 and Option 144.
pub const Coordinates = struct {
    latitude: f64,
    longitude: f64,
    altitude: ?f64,
    altitude_unit: AltitudeUnit,
    geo_reference: Reference,

    fn fromRawFields(
        raw_lat: i34,
        raw_lon: i34,
        raw_alt: i30,
        raw_alt_type: u4,
        raw_datum: u3,
    ) ParseError!Coordinates {
        const lat = @as(f64, @floatFromInt(raw_lat)) / @as(f64, 1 << 25);
        const lon = @as(f64, @floatFromInt(raw_lon)) / @as(f64, 1 << 25);

        if (lat < -90.0 or lat > 90.0 or lon < -180.0 or lon > 180.0) {
            return error.InvalidCoordinates;
        }

        const alt_type: AltitudeUnit = @fromBackingInt(raw_alt_type);
        const alt: ?f64 = if (alt_type == .unknown)
            null
        else
            @as(f64, @floatFromInt(raw_alt)) / @as(f64, 1 << 8);

        return .{
            .latitude = lat,
            .longitude = lon,
            .altitude = alt,
            .altitude_unit = alt_type,
            .geo_reference = @fromBackingInt(raw_datum),
        };
    }

    /// format implements the formatter interface as used by *std.Io.Writer.
    ///
    /// The output format is for /etc/geolocation.
    pub fn format(self: Coordinates, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        try writer.print("{d:.6}\n{d:.6}\n{d:.1}", .{ self.latitude, self.longitude, self.altitude orelse @as(f64, 0) });
    }
};

/// DHCPv4 Option 123 (GeoConf) response.
///
/// For details see RFC 6225.
pub const GeoConf123 = struct {
    pub const option_code: u8 = 123;
    pub const payload_len: u8 = 16;

    coords: Coordinates,
    resolution: struct {
        lat_bits: u6,
        lon_bits: u6,
        alt_bits: u6,
    },

    pub fn parseDhcpOption(tlv: []const u8) ParseError!GeoConf123 {
        if (tlv[0] != option_code) return error.InvalidOptionCode;
        if (tlv.len != 18 or tlv[1] != payload_len) return error.InvalidOptionLength;
        return fromPayload(tlv[2..18]);
    }

    pub fn fromPayload(payload: *const [payload_len]u8) ParseError!GeoConf123 {
        const Wire = packed struct(u128) {
            datum: u3,
            reserved: u5,
            altitude: i30,
            alt_res: u6,
            altitude_unit: u4,
            longitude: i34,
            lo_res: u6,
            latitude: i34,
            la_res: u6,
        };

        const raw_be = std.mem.readInt(u128, payload, .big);
        const w: Wire = @bitCast(raw_be);

        return .{
            .coords = try Coordinates.fromRawFields(
                w.latitude,
                w.longitude,
                w.altitude,
                w.altitude_unit,
                w.datum,
            ),
            .resolution = .{
                .lat_bits = w.la_res,
                .lon_bits = w.lo_res,
                .alt_bits = w.alt_res,
            },
        };
    }

    /// format implements the formatter interface as used by *std.Io.Writer.
    ///
    /// The output format is for /etc/geolocation.
    pub fn format(self: GeoConf123, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        const uncertainty = @min(self.resolution.lat_bits, self.resolution.lon_bits);
        try writer.print("{f}\n{d}\n", .{ self.coords, 8 - uncertainty });
    }
};

/// DHCPv4 Option 144 (GeoLoc) response.
///
/// For details see RFC 6225.
pub const GeoLoc144 = struct {
    pub const option_code: u8 = 144;
    pub const payload_len: u8 = 16;

    coords: Coordinates,
    uncertainty: struct {
        lat_deg: ?f64,
        lon_deg: ?f64,
        alt_meters: ?f64,
    },
    version: u2,

    pub fn parseDhcpOption(tlv: []const u8) ParseError!GeoLoc144 {
        if (tlv[0] != option_code) return error.InvalidOptionCode;
        if (tlv.len != 18 or tlv[1] != payload_len) return error.InvalidOptionLength;
        return fromPayload(tlv[2..18]);
    }

    pub fn fromPayload(payload: *const [payload_len]u8) ParseError!GeoLoc144 {
        const Wire = packed struct(u128) {
            datum: u3,
            reserved: u3,
            ver: u2,
            altitude: i30,
            alt_unc: u6,
            altitude_unit: u4,
            longitude: i34,
            long_unc: u6,
            latitude: i34,
            lat_unc: u6,
        };

        const raw_be = std.mem.readInt(u128, payload, .big);
        const w: Wire = @bitCast(raw_be);

        if (w.ver != 1) return error.UnsupportedVersion;

        const coords = try Coordinates.fromRawFields(
            w.latitude,
            w.longitude,
            w.altitude,
            w.altitude_unit,
            w.datum,
        );

        return .{
            .coords = coords,
            .version = w.ver,
            .uncertainty = .{
                .lat_deg = decodeCoordUncertainty(w.lat_unc),
                .lon_deg = decodeCoordUncertainty(w.long_unc),
                .alt_meters = if (coords.altitude_unit == .meters)
                    decodeAltUncertainty(w.alt_unc)
                else
                    null,
            },
        };
    }

    fn decodeCoordUncertainty(unc: u6) ?f64 {
        if (unc == 0 or unc > 34) return null;
        return std.math.ldexp(@as(f64, 1.0), 8 - @as(i32, unc));
    }

    fn decodeAltUncertainty(unc: u6) ?f64 {
        if (unc == 0 or unc > 30) return null;
        return std.math.ldexp(@as(f64, 1.0), 21 - @as(i32, unc));
    }

    /// format implements the formatter interface as used by *std.Io.Writer.
    ///
    /// The output format is for /etc/geolocation.
    pub fn format(self: GeoLoc144, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        var uncertainty: f64 = 0;
        if (self.uncertainty.lat_deg != null) {
            const t = degreesToMetersWGS84(self.uncertainty.lat_deg.?, self.coords.latitude);
            uncertainty = t.east_west_meters;
            if (t.north_south_meters > uncertainty) uncertainty = t.north_south_meters;
        }
        if (self.uncertainty.lon_deg != null) {
            const v = degreesToMetersWGS84(self.uncertainty.lon_deg.?, self.coords.latitude);
            if (v.east_west_meters > uncertainty) uncertainty = v.east_west_meters;
            if (v.north_south_meters > uncertainty) uncertainty = v.north_south_meters;
        }

        try writer.print("{f}\n{d:.1}\n", .{ self.coords, uncertainty });
    }
};

test "parse Option 123" {
    var opt123_buf: [18]u8 = @splat(0);
    opt123_buf[0] = GeoConf123.option_code;
    opt123_buf[1] = GeoConf123.payload_len;
    @memcpy(opt123_buf[2..18], &[_]u8{
        0x48, 0x4D, 0xCB, 0x98,
        0x63, 0x47, 0x65, 0xED,
        0x42, 0xC4, 0x14, 0x40,
        0x00, 0x0F, 0x00, 0x01,
    });

    const loc123 = try GeoConf123.parseDhcpOption(&opt123_buf);
    try std.testing.expectApproxEqAbs(38.897647, loc123.coords.latitude, 1e-5);
    try std.testing.expectApproxEqAbs(-77.0366, loc123.coords.longitude, 1e-5);
    try std.testing.expectEqual(@as(?f64, 15.0), loc123.coords.altitude);
    try std.testing.expectEqual(Reference.wgs84, loc123.coords.geo_reference);
    try std.testing.expectEqual(@as(u6, 18), loc123.resolution.lat_bits);
}

test "parse Option 144" {
    var opt144_buf: [18]u8 = @splat(0);
    opt144_buf[0] = GeoLoc144.option_code;
    opt144_buf[1] = GeoLoc144.payload_len;
    @memcpy(opt144_buf[2..18], &[_]u8{
        0x4B, 0xBC, 0x49, 0x36,
        0x0D, 0x49, 0x2E, 0x6E,
        0x2E, 0xC3, 0x13, 0xC0,
        0x00, 0x21, 0xB3, 0x41,
    });

    const loc144 = try GeoLoc144.parseDhcpOption(&opt144_buf);
    try std.testing.expectApproxEqAbs(-33.8570095003, loc144.coords.latitude, 1e-9);
    try std.testing.expectApproxEqAbs(151.2152005136, loc144.coords.longitude, 1e-9);
    try std.testing.expectApproxEqAbs(33.69921875, loc144.coords.altitude.?, 1e-8);
    try std.testing.expectEqual(Reference.wgs84, loc144.coords.geo_reference);
    try std.testing.expectEqual(@as(u2, 1), loc144.version);
    try std.testing.expectApproxEqAbs(0.0009765625, loc144.uncertainty.lat_deg.?, 1e-10);
    try std.testing.expectEqual(@as(?f64, 64.0), loc144.uncertainty.alt_meters);
}
