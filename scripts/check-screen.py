#!/usr/bin/env python3
"""Assert on a QEMU screendump of the framebuffer console.

A serial log cannot tell a blank display from a full one, so every mistake that
belongs to the framebuffer alone is invisible in it: a wrong stride, a wrong
channel order, or nothing drawn at all. This reads the PPM the monitor produced
and checks the three things the log cannot.

Usage: check-screen.py <screendump.ppm>
Prints a one-line summary on success; exits non-zero with a reason otherwise.
"""

import sys
from collections import Counter

# The console draws Rgb::GREEN on black. GREEN is 0x33FF66 — the one stock colour
# whose red and blue channels differ, and that asymmetry is the whole point: if
# the GOP-to-drawing-crate pixel-format mapping were inverted, every glyph would
# come out 0x66FF33 and nothing else in the system would ever notice.
EXPECTED_FG = bytes((0x33, 0xFF, 0x66))
BLACK = bytes(3)

# A screenful of the boot log plus the ASCII self-test lights several thousand
# pixels. Well under that means the console attached but drew nothing.
MIN_LIT = 2000


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    path = sys.argv[1]

    data = open(path, "rb").read()
    if not data.startswith(b"P6"):
        print(f"{path} is not a binary PPM", file=sys.stderr)
        return 1
    # P6\n<width> <height>\n<maxval>\n<pixels>. QEMU always writes maxval 255.
    marker = b"255\n"
    if marker not in data:
        print(f"{path} has no PPM maxval header", file=sys.stderr)
        return 1
    body = data[data.index(marker) + len(marker):]

    pixels = Counter(bytes(body[i:i + 3]) for i in range(0, len(body), 3))
    lit = sum(n for colour, n in pixels.items() if colour != BLACK)
    if lit < MIN_LIT:
        print(f"screen is (nearly) blank: {lit} lit pixels", file=sys.stderr)
        return 1

    foreground = max((c for c in pixels if c != BLACK), key=lambda c: pixels[c])
    if foreground != EXPECTED_FG:
        print(
            f"foreground is {foreground.hex()}, expected {EXPECTED_FG.hex()}"
            " - red and blue swapped?",
            file=sys.stderr,
        )
        return 1

    print(f"{lit} lit pixels, foreground {foreground.hex()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
