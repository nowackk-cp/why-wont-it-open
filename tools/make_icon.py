#!/usr/bin/env python3
"""Generates gui/app.ico: a blue rounded square with a white magnifier that has
a medical cross in its lens. Pure Python (no Pillow); PNG-compressed ICO
entries for 16/24/32/48/256 px.

    python tools/make_icon.py [output.ico]
"""
import math
import struct
import sys
import zlib

SIZES = (16, 24, 32, 48, 256)


def sd_round_rect(px, py, cx, cy, hw, hh, r):
    qx, qy = abs(px - cx) - hw + r, abs(py - cy) - hh + r
    return math.hypot(max(qx, 0), max(qy, 0)) + min(max(qx, qy), 0) - r


def sd_segment(px, py, ax, ay, bx, by):
    dx, dy = bx - ax, by - ay
    t = max(0.0, min(1.0, ((px - ax) * dx + (py - ay) * dy) / (dx * dx + dy * dy)))
    return math.hypot(px - ax - t * dx, py - ay - t * dy)


def shade(u, v):
    """Returns (r, g, b, a) in 0..1 for a point in unit coordinates."""
    out = (0.0, 0.0, 0.0, 0.0)

    def over(c, cov):
        nonlocal out
        a = c[3] * cov
        if a <= 0:
            return
        oa = out[3]
        na = a + oa * (1 - a)
        out = tuple((c[i] * a + out[i] * oa * (1 - a)) / na for i in range(3)) + (na,)

    d = sd_round_rect(u, v, 0.5, 0.5, 0.46, 0.46, 0.2)
    # background gradient
    t = v
    bg = (0.23 + (0.10 - 0.23) * t, 0.51 + (0.30 - 0.51) * t, 0.96 + (0.82 - 0.96) * t, 1.0)
    over(bg, 1.0 if d < 0 else 0.0)
    if d >= 0:
        return out
    white = (1.0, 1.0, 1.0, 1.0)
    cx, cy, rad, th = 0.43, 0.43, 0.245, 0.07
    dist = math.hypot(u - cx, v - cy)
    if dist < rad - th / 2:
        over((1.0, 1.0, 1.0, 0.16), 1.0)
    if abs(dist - rad) < th / 2:
        over(white, 1.0)
    if sd_segment(u, v, 0.62, 0.62, 0.80, 0.80) < 0.052:
        over(white, 1.0)
    arm, w = 0.115, 0.032
    if (abs(u - cx) < w and abs(v - cy) < arm) or (abs(v - cy) < w and abs(u - cx) < arm):
        over(white, 1.0)
    return out


def render(size):
    ss = 4 if size <= 48 else 3
    rows = []
    for y in range(size):
        row = bytearray([0])
        for x in range(size):
            acc = [0.0, 0.0, 0.0, 0.0]
            for sy in range(ss):
                for sx in range(ss):
                    r, g, b, a = shade((x + (sx + .5) / ss) / size, (y + (sy + .5) / ss) / size)
                    acc[0] += r * a; acc[1] += g * a; acc[2] += b * a; acc[3] += a
            a = acc[3] / (ss * ss)
            if acc[3] > 0:
                row += bytes(int(round(255 * acc[i] / acc[3])) for i in range(3))
            else:
                row += b"\0\0\0"
            row.append(int(round(255 * a)))
        rows.append(bytes(row))
    return rows


def png(size, rows):
    def chunk(tag, data):
        c = struct.pack(">I", len(data)) + tag + data
        return c + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0)) +
            chunk(b"IDAT", zlib.compress(b"".join(rows), 9)) + chunk(b"IEND", b""))


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "gui/app.ico"
    images = [(s, png(s, render(s))) for s in SIZES]
    data = struct.pack("<HHH", 0, 1, len(images))
    offset = 6 + 16 * len(images)
    body = b""
    for s, img in images:
        data += struct.pack("<BBBBHHII", s % 256, s % 256, 0, 0, 1, 32, len(img), offset + len(body))
        body += img
    with open(out, "wb") as f:
        f.write(data + body)
    print("wrote", out, len(data + body), "bytes")


if __name__ == "__main__":
    main()
