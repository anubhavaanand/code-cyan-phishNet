#!/usr/bin/env python3
"""Generate the PhishNet README pixel banner recipe (Pixelbolt v1).

Design: night scene, aerial-perspective mountain ranges, dithered sky,
a shield anchoring a cyan net across dark water, envelopes caught in it.
All shapes are generated procedurally so edge widths are exact.
"""
import json
import math
import random

W, H = 480, 160
HORIZON = 96
CX, CY = W // 2, 104

PALETTE = {
    # sky (deep -> nearer horizon)
    "A": "#070a19",
    "B": "#0b1029",
    "C": "#111a3d",
    "D": "#182451",
    "E": "#1f2e66",
    # mountains: far range is hazier/lighter (aerial perspective)
    "F": "#2a3b78",
    "G": "#141c3c",
    # water
    "W0": "#060d1c",
    "W1": "#0a1428",
    "W2": "#0f1e38",
    # net / cyan
    "J": "#146c85",
    "K": "#25a7bd",
    "L": "#5fd7e8",
    "M": "#a8f0ff",
    # accents
    "N": "#f5b301",
    "O": "#ffe066",
    "P": "#f2f7ff",
    "Q": "#9fb0cf",
    # shield: dark steel face lit from the upper left
    "R": "#24406b",
    "S": "#3d5a8a",
    "T": "#6b8fc4",
}

# ---------------------------------------------------------------- symbols


def norm(rows):
    """Pad every row to the widest one. Hand-drawn grids drift by a pixel;
    Pixelbolt rejects ragged rows, so normalise at the source."""
    w = max(len(r) for r in rows)
    return [r.ljust(w, ".") for r in rows]


def shield_grid():
    """A shield: rounded shoulders, straight flanks, curving to a point.

    Drawn by hand at 17x19 — a formula gave a lampshade. Light falls from the
    upper left, so the left flank is lit and the right is in shadow.
    """
    rows = [
        "....MMMMMMMMM....",
        "..MMLLLLLLLMMM...",
        ".MLLLLKLLLLLLLM..",
        ".MLLLKLLLLLLLLM..",
        ".MLLKLLLLLLLLKM..",
        ".MLKLLLLLLLLKKM..",
        ".MLLLLLLLLLKKKM..",
        ".MLLLLLLLLLKKKM..",
        "..MLLLLLLLKKKM...",
        "..MLLLLLLLKKKM...",
        "...MLLLLLKKKM....",
        "...MLLLLLKKKM....",
        "....MLLLKKM......",
        ".....MLLKM.......",
        "......MKM........",
        ".......M........",
    ]
    # gold check: two strokes, thick enough to read at 1x
    for x, y in [(5, 8), (6, 9), (7, 10), (8, 11), (9, 10), (10, 9),
                 (11, 8), (12, 7), (13, 6)]:
        for dx, dy in ((0, 0), (0, 1), (1, 0)):
            xx, yy = x + dx, y + dy
            if 0 <= yy < len(rows) and 0 <= xx < len(rows[yy]):
                r = list(rows[yy])
                if r[xx] not in ".M":
                    r[xx] = "N"
                    rows[yy] = "".join(r)
    return norm(rows)


def envelope_grid():
    """A caught envelope: pale body, darker flap, two fold lines at the top."""
    return norm([
        ".PPPPPPPPPPP.",
        "PLLLLLLLLLLLP",
        "PLLLLLLLLLLLP",
        "PLLKLLLLLKLLP",
        "PLLLKLLLKLLLP",
        "PLLLEKKELLLP.",
        "PLLLLLLLLLLLP",
        "PLLLLLLLLLLLP",
        ".PPPPPPPPPPP.",
    ])


def mountain_rows(seed, base, amp, roughness, color_far, color_ridge, lit=None):
    """A range of sharp peaks: overlapping cones, each with a straight-sided
    falloff, plus small crags. Returns rows plus the per-column top row so a
    caller can light one face of each peak."""
    rnd = random.Random(seed)
    peaks = []
    x = -20
    while x < W + 20:
        peak_h = rnd.uniform(0.45, 1.0) * amp
        peak_w = rnd.uniform(0.10, 0.34) * amp + rnd.uniform(10, 34)
        peaks.append((x, peak_w, peak_h))
        x += rnd.uniform(0.07, 0.20) * amp + 14
    heights = []
    for cx in range(W):
        best = 0.0
        second = 0.0
        for px, pw, ph in peaks:
            d = abs(cx - px)
            if d >= pw:
                continue
            # straight-sided cone with a rounded tip
            v = ph * (1.0 - (d / pw) ** 1.35)
            if v > best:
                second, best = best, v
            elif v > second:
                second = v
        h = max(best, second * 0.82)
        # crags: a small deterministic offset per column
        h += (rnd.random() - 0.5) * 2.4 * roughness
        heights.append(max(0, int(round(h))))
    rows = []
    for y in range(int(max(heights)) + 2):
        row = []
        for cx in range(W):
            top = heights[cx]
            if y < top:
                row.append(color_far)
            elif y == top and top > 3:
                row.append(color_ridge)
            else:
                row.append(".")
        rows.append("".join(row))
    # lit south-east face: recolour the pixels just under each ridge line
    if lit:
        for cx in range(1, W):
            slope = heights[cx] - heights[cx - 1]
            if slope > 0:                      # rising to the right -> left face
                for d in range(1, min(4, heights[cx])):
                    ty = heights[cx] + d
                    if ty < len(rows):
                        r = list(rows[ty])
                        if r[cx] == color_far:
                            r[cx] = lit
                            rows[ty] = "".join(r)
    return rows, heights


# ---------------------------------------------------------------- layers

def sky_layers():
    """Banded sky with dithered seams, then stars."""
    bands = [(0, 30, "A"), (30, 52, "B"), (52, 70, "C"), (70, 84, "D"), (84, HORIZON, "E")]
    ops = []
    for y0, y1, col in bands:
        ops.append({"op": "rect", "x": 0, "y": y0, "w": W, "h": y1 - y0, "color": col})
    # dither the seams so bands dissolve instead of stepping
    for y0, _y1, _c in bands[1:]:
        op = {"op": "dither", "x": 0, "y": y0 - 6, "w": W, "h": 12,
              "color": "B", "density": 0.5, "pattern": "bayer4"}
        if y0 == 30:
            op["over"] = [PALETTE["A"], PALETTE["B"]]
        ops.append(op)
    # horizon glow
    ops.append({"op": "dither", "x": 0, "y": HORIZON - 14, "w": W, "h": 14,
                "color": "E", "density": [0.0, 0.6], "direction": "down",
                "pattern": "bayer4"})
    # stars — upper sky only, sparser so bands read clean
    rnd = random.Random(11)
    for _ in range(58):
        x = rnd.randrange(2, W - 2)
        y = rnd.randrange(2, 52)
        ops.append({"op": "pixel", "x": x, "y": y,
                    "color": "P" if rnd.random() < 0.22 else "Q"})
    for _ in range(6):  # a few bright ones with a cross
        x = rnd.randrange(10, W - 10)
        y = rnd.randrange(4, 34)
        ops.append({"op": "pixel", "x": x, "y": y, "color": "P"})
        ops.append({"op": "pixel", "x": x - 1, "y": y, "color": "Q"})
        ops.append({"op": "pixel", "x": x + 1, "y": y, "color": "Q"})
        ops.append({"op": "pixel", "x": x, "y": y - 1, "color": "Q"})
    return ops


def water_layers():
    ops = [
        {"op": "rect", "x": 0, "y": HORIZON, "w": W, "h": H - HORIZON, "color": "W0"},
        {"op": "dither", "x": 0, "y": HORIZON, "w": W, "h": 22, "color": "W2",
         "density": [0.75, 0.0], "direction": "down", "pattern": "bayer8"},
        {"op": "dither", "x": 0, "y": HORIZON + 8, "w": W, "h": H - HORIZON - 8,
         "color": "W1", "density": [0.45, 0.04], "direction": "down",
         "pattern": "bayer4"},
    ]
    # horizontal glints that suggest still water
    rnd = random.Random(3)
    for _ in range(46):
        x = rnd.randrange(0, W - 6)
        y = rnd.randrange(HORIZON + 2, H - 1)
        ln = rnd.choice([2, 2, 3, 4])
        ops.append({"op": "line", "x": x, "y": y, "x2": x + ln, "y2": y,
                    "color": "W2"})
    return ops


def net_layers():
    """A real web: radial strands, arcs between adjacent strands, and
    cross-links along each strand. Confined to the water so the title
    band stays readable."""
    ops = []
    rays = 18
    rx, ry = 300, 62                      # the web's ellipse, mapped to water
    angs = [(math.pi * 2 * i / rays) + 0.09 for i in range(rays)]

    def pt(a, r):
        return (int(CX + math.cos(a) * r * rx), int(CY + math.sin(a) * r * ry))

    # radial strands
    for a in angs:
        x2, y2 = pt(a, 1.0)
        y2 = max(HORIZON + 2, min(H - 1, y2))
        ops.append({"op": "line", "x": CX, "y": CY, "x2": x2, "y2": y2, "color": "J"})

    # arcs: connect neighbouring strands at several radii
    for r in (0.22, 0.38, 0.55, 0.72, 0.9):
        col = "L" if r < 0.3 else ("K" if r < 0.7 else "J")
        for i in range(rays):
            ax, ay = pt(angs[i], r)
            bx, by = pt(angs[(i + 1) % rays], r)
            if min(ay, by) < HORIZON + 2:
                continue
            ops.append({"op": "line", "x": ax, "y": ay, "x2": bx, "y2": by, "color": col})

    # bright hub
    ops.append({"op": "ellipse", "x": CX - 14, "y": CY - 5, "w": 28, "h": 10,
                "color": "M", "filled": False})
    return ops


def envelope_ops():
    """Envelopes snagged in the web: each sits on a strand with a shadow."""
    ops = []
    for ex, ey, flip in [(102, 104, True), (372, 122, False), (416, 100, True)]:
        ops.append({"op": "ellipse", "x": ex - 2, "y": ey + 11, "w": 30, "h": 5,
                    "color": "W0", "filled": True})
        ops.append({"op": "stamp", "symbol": "envelope", "x": ex, "y": ey,
                    "scale": 2, "flipX": flip})
    return ops


def main():
    far_rows, _ = mountain_rows(7, 0, 24.0, 0.45, "F", "D", lit="E")
    near_rows, _ = mountain_rows(23, 0, 38.0, 0.7, "G", "F", lit="F")

    def grid_ops(rows, y, x0=0, chunk=240):
        """Grid rows are capped at 256 chars, so a 480-wide range is emitted
        in slices whose columns are relative to each slice's x."""
        out = []
        total = len(rows[0]) if rows else 0
        for sx in range(0, total, chunk):
            sl = [r[sx:sx + chunk] for r in rows]
            out.append({"op": "grid", "x": x0 + sx, "y": y, "rows": sl})
        return out

    layers = [
        {"name": "sky", "ops": sky_layers()},
        {"name": "mountains-far", "ops": grid_ops(far_rows, HORIZON - len(far_rows)) + [
            {"op": "dither", "x": 0, "y": HORIZON - len(far_rows),
             "w": W, "h": len(far_rows), "color": "E", "density": [0.35, 0.0],
             "direction": "down", "pattern": "bayer4"},
        ]},
        {"name": "mountains-near", "ops": grid_ops(near_rows, HORIZON - len(near_rows) + 4)},
        {"name": "water", "ops": water_layers()},
        {"name": "net", "ops": net_layers()},
        {"name": "catches", "ops": envelope_ops()},
        {"name": "shield", "ops": [
            {"op": "ellipse", "x": CX - 34, "y": CY + 20, "w": 68, "h": 14,
             "color": "W0", "filled": True},
            {"op": "stamp", "symbol": "shield", "x": CX - 26, "y": CY - 52, "scale": 3},
        ]},
        {"name": "titles", "ops": [
            {"op": "text", "text": "PHISHNET", "x": CX, "y": 12, "color": "P",
             "align": "center", "spacing": 4, "scale": 3},
            {"op": "text", "text": "ON-DEVICE AI EMAIL SECURITY", "x": CX, "y": 46,
             "color": "K", "align": "center", "spacing": 3, "scale": 1},
        ]},
    ]

    recipe = {
        "version": 1,
        "name": "phishnet-banner-v3",
        "width": W,
        "height": H,
        "palette": PALETTE,
        "symbols": {
            "shield": shield_grid(),
            "envelope": envelope_grid(),
        },
        "frames": [{"name": "banner", "duration": 400, "layers": layers}],
        "animations": {"still": {"frames": ["banner"], "loop": False}},
        "sheet": {"columns": 1, "padding": 0, "scale": 1},
    }
    with open("phishnet-banner-v3.json", "w") as f:
        json.dump(recipe, f, indent=1)
    print("ok")


if __name__ == "__main__":
    main()
