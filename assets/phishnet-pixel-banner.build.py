#!/usr/bin/env python3
"""Generate the PhishNet README pixel banner (Pixelbolt v1 recipe, animated).

Constraints that shape this file:
  * An animated recipe may be at most 256x256 per frame, so the scene is
    authored at 256x96 and exported with --scale 4 (1024x384). Integer
    scaling keeps every pixel on the grid.
  * The recipe is the source of truth; this script exists so the procedural
    parts (mountains, stars, web) stay reproducible and editable.

Scene: dithered night sky, two aerial-perspective mountain ranges, dark water
with depth dither, and a shield casting a web that catches envelopes.
Animation: stars twinkle, water glints drift, the web pulses, envelopes bob.
"""
import json
import math
import random

W, H = 256, 96
HORIZON = 58
CX, CY = W // 2, 64
FRAMES = 12

PALETTE = {
    # sky, deepest to horizon
    "A": "#070a19",
    "B": "#0b1029",
    "C": "#111a3d",
    "D": "#182451",
    "E": "#1f2e66",
    # mountains: the far range is lighter, which is aerial perspective
    "F": "#2a3b78",
    "G": "#141c3c",
    # water
    "W0": "#060d1c",
    "W1": "#0a1428",
    "W2": "#0f1e38",
    # web / cyan
    "J": "#146c85",
    "K": "#25a7bd",
    "L": "#5fd7e8",
    "M": "#a8f0ff",
    # accents
    "N": "#f5b301",
    "O": "#ffe066",
    "P": "#f2f7ff",
    "Q": "#9fb0cf",
}

# Per-frame web pulse: same shape, different brightness, so the web breathes.
# Palettes keep the pulse inside the palette instead of adding new colours.
WEB_PULSE = [
    {"J": "#125f77", "K": "#2094aa", "L": "#55cde0"},
    {"J": "#146c85", "K": "#25a7bd", "L": "#5fd7e8"},
    {"J": "#17748e", "K": "#2bb4cb", "L": "#6fdef0"},
    {"J": "#1a7d97", "K": "#31c0d7", "L": "#7fe6f5"},
    {"J": "#17748e", "K": "#2bb4cb", "L": "#6fdef0"},
    {"J": "#146c85", "K": "#25a7bd", "L": "#5fd7e8"},
    {"J": "#125f77", "K": "#2094aa", "L": "#55cde0"},
    {"J": "#0f5b72", "K": "#1c8ba0", "L": "#4cc3d6"},
]

STAR_DIM = ["#5d6b8c", "#3d4866", "#2a3350"]


def norm(rows):
    """Pad every row to the widest one: Pixelbolt rejects ragged grids."""
    w = max(len(r) for r in rows)
    return [r.ljust(w, ".") for r in rows]


def shield_grid():
    """A shield: rounded shoulders, straight flanks, curving to a point.

    Hand-drawn at 17px because a taper formula produced a lampshade. Light
    falls from the upper left, so the left flank is lit and the right is not.
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
        ".......M.........",
    ]
    # gold check: stamped three pixels thick so it survives the integer scale
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
    """A caught envelope: pale body, darker flap, a V crease on the lid."""
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


def mountain_rows(seed, amp, roughness, color_far, color_ridge, lit=None):
    """A range of sharp peaks: overlapping straight-sided cones, plus crags.

    A gaussian sum gave rolling hills; a cone falloff gives the hard ridge
    line that reads as a mountain at this size.
    """
    rnd = random.Random(seed)
    peaks = []
    x = -20.0
    while x < W + 20:
        peaks.append((x,
                      rnd.uniform(0.10, 0.34) * amp + rnd.uniform(6, 18),
                      rnd.uniform(0.45, 1.0) * amp))
        x += rnd.uniform(0.07, 0.20) * amp + 9
    heights = []
    for cx in range(W):
        best = second = 0.0
        for px, pw, ph in peaks:
            d = abs(cx - px)
            if d >= pw:
                continue
            v = ph * (1.0 - (d / pw) ** 1.35)
            if v > best:
                second, best = best, v
            elif v > second:
                second = v
        h = max(best, second * 0.82) + (rnd.random() - 0.5) * 2.4 * roughness
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
    # lit faces: the slope that rises to the right is lit from the upper left
    if lit:
        for cx in range(1, W):
            if heights[cx] - heights[cx - 1] > 0:
                for d in range(1, min(4, heights[cx])):
                    ty = heights[cx] + d
                    if ty < len(rows):
                        r = list(rows[ty])
                        if r[cx] == color_far:
                            r[cx] = lit
                            rows[ty] = "".join(r)
    return rows


def grid_ops(rows, y, chunk=240):
    """Grid rows cap at 256 chars; emit wide ranges in slices."""
    out = []
    total = len(rows[0]) if rows else 0
    for sx in range(0, total, chunk):
        out.append({"op": "grid", "x": sx, "y": y,
                    "rows": [r[sx:sx + chunk] for r in rows]})
    return out


def sky_ops(t):
    bands = [(0, 18, "A"), (18, 31, "B"), (31, 42, "C"), (42, 50, "D"), (50, HORIZON, "E")]
    ops = [{"op": "rect", "x": 0, "y": y0, "w": W, "h": y1 - y0, "color": c}
           for y0, y1, c in bands]
    for y0, _y1, _c in bands[1:]:
        ops.append({"op": "dither", "x": 0, "y": y0 - 4, "w": W, "h": 8,
                    "color": "B", "density": 0.5, "pattern": "bayer4"})
    ops.append({"op": "dither", "x": 0, "y": HORIZON - 9, "w": W, "h": 9,
                "color": "E", "density": [0.0, 0.6], "direction": "down",
                "pattern": "bayer4"})
    # stars: a fixed field whose brightness steps, so they twinkle in place
    rnd = random.Random(11)
    for _ in range(34):
        x = rnd.randrange(2, W - 2)
        y = rnd.randrange(2, 34)
        bright = rnd.random() < 0.28
        phase = rnd.randrange(0, FRAMES)
        step = (t + phase) % FRAMES
        if step == 0:
            col = STAR_DIM[0]
        elif step in (3, 4):
            col = STAR_DIM[1]
        else:
            col = "P" if bright else "Q"
        ops.append({"op": "pixel", "x": x, "y": y, "color": col})
    return ops


def water_ops(t):
    ops = [
        {"op": "rect", "x": 0, "y": HORIZON, "w": W, "h": H - HORIZON, "color": "W0"},
        {"op": "dither", "x": 0, "y": HORIZON, "w": W, "h": 14, "color": "W2",
         "density": [0.75, 0.0], "direction": "down", "pattern": "bayer8"},
        {"op": "dither", "x": 0, "y": HORIZON + 6, "w": W, "h": H - HORIZON - 6,
         "color": "W1", "density": [0.45, 0.04], "direction": "down",
         "pattern": "bayer4"},
    ]
    # glints drift left between frames; the modulo wraps them around
    rnd = random.Random(3)
    shift = t * 3
    for _ in range(20):
        x = (rnd.randrange(0, W) - shift) % W
        y = rnd.randrange(HORIZON + 2, H - 1)
        ln = rnd.choice([2, 2, 3, 4])
        ops.append({"op": "line", "x": x, "y": y, "x2": min(W - 1, x + ln),
                    "y2": y, "color": "W2"})
    return ops


def net_ops():
    """Radial strands plus arcs between neighbours: a web, not a target."""
    ops = []
    rays = 18
    rx, ry = 150, 30
    angs = [(math.pi * 2 * i / rays) + 0.09 for i in range(rays)]

    def pt(a, r):
        return (int(CX + math.cos(a) * r * rx), int(CY + math.sin(a) * r * ry))

    for a in angs:
        x2, y2 = pt(a, 1.0)
        ops.append({"op": "line", "x": CX, "y": CY, "x2": x2,
                    "y2": max(HORIZON + 2, min(H - 1, y2)), "color": "J"})
    for r in (0.22, 0.38, 0.55, 0.72, 0.9):
        col = "L" if r < 0.3 else ("K" if r < 0.7 else "J")
        for i in range(rays):
            ax, ay = pt(angs[i], r)
            bx, by = pt(angs[(i + 1) % rays], r)
            if min(ay, by) < HORIZON + 2:
                continue
            ops.append({"op": "line", "x": ax, "y": ay, "x2": bx, "y2": by, "color": col})
    ops.append({"op": "ellipse", "x": CX - 12, "y": CY - 4, "w": 24, "h": 8,
                "color": "M", "filled": False})
    return ops


def hub_glow_ops(t):
    """The web's bright hub breathes with the pulse, so the eye has a beat."""
    k = (t % len(WEB_PULSE))
    width = 22 + (k * 2) if k <= 4 else 22 + (8 - k) * 2
    height = max(4, width // 3)
    return [{"op": "ellipse", "x": CX - width // 2, "y": CY - height // 2,
             "w": width, "h": height,
             "color": "L" if k % 2 else "M", "filled": False}]


def envelope_ops(t):
    """Each envelope bobs on its own phase, one pixel a step."""
    ops = []
    for ex, ey, flip, phase in [(54, 66, True, 0), (196, 78, False, 3), (222, 64, True, 5)]:
        bob = int(round(2 * math.sin((t + phase) / FRAMES * math.tau)))
        ops.append({"op": "ellipse", "x": ex - 1, "y": ey + 10 + bob, "w": 16, "h": 3,
                    "color": "W0", "filled": True})
        ops.append({"op": "stamp", "symbol": "envelope", "x": ex, "y": ey + bob,
                    "flipX": flip})
    return ops


def main():
    far = mountain_rows(7, 14.0, 0.45, "F", "D", lit="E")
    near = mountain_rows(23, 22.0, 0.7, "G", "F", lit="F")

    frames = []
    for t in range(FRAMES):
        frames.append({
            "name": f"f{t}",
            "duration": 110,
            "layers": [
                {"name": "sky", "ops": sky_ops(t)},
                {"name": "mountains-far",
                 "ops": grid_ops(far, HORIZON - len(far)) + [
                     {"op": "dither", "x": 0, "y": HORIZON - len(far), "w": W,
                      "h": len(far), "color": "E", "density": [0.35, 0.0],
                      "direction": "down", "pattern": "bayer4"}]},
                {"name": "mountains-near", "ops": grid_ops(near, HORIZON - len(near) + 3)},
                {"name": "water", "ops": water_ops(t)},
                {"name": "net", "palette": WEB_PULSE[t % len(WEB_PULSE)], "ops": net_ops()},
                {"name": "hub-glow", "palette": WEB_PULSE[t % len(WEB_PULSE)],
                 "ops": hub_glow_ops(t)},
                {"name": "catches", "ops": envelope_ops(t)},
                {"name": "shield", "ops": [
                    {"op": "ellipse", "x": CX - 24, "y": CY + 14, "w": 48, "h": 10,
                     "color": "W0", "filled": True},
                    {"op": "stamp", "symbol": "shield", "x": CX - 17, "y": CY - 32,
                     "scale": 2},
                ]},
                {"name": "titles", "ops": [
                    {"op": "text", "text": "PHISHNET", "x": CX, "y": 4, "color": "P",
                     "align": "center", "spacing": 3, "scale": 2},
                    {"op": "text", "text": "ON-DEVICE AI EMAIL SECURITY", "x": CX,
                     "y": 24, "color": "K", "align": "center", "spacing": 2},
                ]},
            ],
        })

    recipe = {
        "version": 1,
        "name": "phishnet-banner",
        "width": W,
        "height": H,
        "palette": PALETTE,
        "symbols": {"shield": shield_grid(), "envelope": envelope_grid()},
        "frames": frames,
        "animations": {"loop": {"frames": [f"f{t}" for t in range(FRAMES)]}},
        "sheet": {"columns": FRAMES, "padding": 0, "scale": 1},
    }
    with open("phishnet-banner-anim.json", "w") as f:
        json.dump(recipe, f, indent=1)
    print("ok")


if __name__ == "__main__":
    main()
