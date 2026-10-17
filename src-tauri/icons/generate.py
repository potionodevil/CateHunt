#!/usr/bin/env python3
# CateHunt Maskottchen-Generator (Sprint 3) — erzeugt Tauri-Icons aus dem NEU
# gezeichneten 16x16-Pixel-Katzenkopf (eigene Zeichnung, NICHT aus E:/HermesHarness
# kopiert). Akzentfarbe: Jagd-Gruen #3fa46a (Augen).
#
# Aufruf:  python generate.py            (Arbeitsverzeichnis = dieses icons/-Verzeichnis)
# Ausgabe: icon.png (256x256 Vollfarb-Kachel dunkel), icon.ico (16/32/48/256),
#          sprite.svg.txt (Pfad-Fragmente zum Einbetten in ui/dist/index.html),
#          favicon.txt (16x16 data:-URI).
# Quelle:  dieses Skript (MAP + PALETTE unten) — Icons sind daraus abgeleitet.
MAP = [
    ".KK..........KK.",
    ".KJK........KJK.",
    ".KJJKKKKKKKKJJK.",
    "..KFFFFFFFFFFK..",
    "..KFFFFFFFFFFK..",
    "..KFFFFFFFFFFK..",
    "..KFEEFFFFEEFK..",
    "..KFEPFFFFPEFK..",
    "..KFFFFFFFFFFK..",
    "..KFFFFNNFFFFK..",
    "..KFFFWNNWFFFK..",
    "...KFFWNNWFFK...",
    "...KFFFFFFFFK...",
    "....KFFFFFFK....",
    "....KKKKKKKK....",
    "................",
]
PALETTE = {
    "K": "#232329",  # Umriss (Kohle, auf dunkel + hell lesbar)
    "F": "#f5f0e4",  # Fell (Creme)
    "J": "#e8a0a0",  # Innenohr (Rosa)
    "E": "#3fa46a",  # Augen (Jagd-Gruen, Akzent)
    "P": "#0e2a1c",  # Pupillen (tiefes Gruen-Schwarz)
    "N": "#c04357",  # Nase (Beerenrot)
    "W": "#f2b8c0",  # Wangen (Rosa)
}
TILE = "#1b1b1f"  # Kachel-Hintergrund (dunkel, Vollfarb-Kachel)

assert len(MAP) == 16 and all(len(r) == 16 for r in MAP), "MAP muss 16x16 sein"
assert set("".join(MAP)) <= set(PALETTE) | {"."}, "Unbekanntes Zeichen in MAP"


def runs(color):
    """Horizontale Pixel-Runs einer Farbe als SVG-Pfad (1x1-Raster, lueckenlos)."""
    d = []
    for y, row in enumerate(MAP):
        x = 0
        while x < 16:
            if row[x] == color:
                x0 = x
                while x < 16 and row[x] == color:
                    x += 1
                d.append(f"M{x0} {y}h{x - x0}v1h{x0 - x}Z")
            else:
                x += 1
    return "".join(d)


def svg_paths(indent="      "):
    """Innere <path>-Elemente des Sprites (ohne <svg>-Huelfe)."""
    order = ["K", "F", "J", "E", "P", "N", "W"]
    lines = []
    eye_e = f'<path d="{runs("E")}" fill="{PALETTE["E"]}"/>'
    eye_p = f'<path d="{runs("P")}" fill="{PALETTE["P"]}"/>'
    for c in order:
        if c in ("E", "P"):
            continue
        lines.append(f'{indent}<path d="{runs(c)}" fill="{PALETTE[c]}"/>')
    lines.append(f'{indent}<g class="cate-eyes">{eye_e}{eye_p}</g>')
    return "\n".join(lines)


def main():
    import base64
    import io
    import os
    from PIL import Image, ImageDraw

    here = os.path.dirname(os.path.abspath(__file__))
    # --- Sprite-Pfade + Favicon ---
    with open(os.path.join(here, "sprite.svg.txt"), "w", encoding="utf-8") as f:
        f.write(svg_paths() + "\n")
    img16 = Image.new("RGBA", (16, 16), (0, 0, 0, 0))
    px = img16.load()
    for y, row in enumerate(MAP):
        for x, ch in enumerate(row):
            if ch != ".":
                px[x, y] = Image.new("RGBA", (1, 1), PALETTE[ch]).getpixel((0, 0))
    buf = io.BytesIO()
    img16.save(buf, format="PNG")
    fav = "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()
    with open(os.path.join(here, "favicon.txt"), "w", encoding="utf-8") as f:
        f.write(fav)

    # --- icon.png: 256x256 Vollfarb-Kachel dunkel, Sprite 12x zentriert ---
    S, SCALE, OFF = 256, 12, (256 - 16 * 12) // 2
    layer = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    d = ImageDraw.Draw(layer)
    for y, row in enumerate(MAP):
        for x, ch in enumerate(row):
            if ch != ".":
                d.rectangle([OFF + x * SCALE, OFF + y * SCALE,
                             OFF + (x + 1) * SCALE - 1, OFF + (y + 1) * SCALE - 1],
                            fill=PALETTE[ch] + "FF")
    mask = Image.new("L", (S, S), 0)
    ImageDraw.Draw(mask).rounded_rectangle([0, 0, S - 1, S - 1], radius=56, fill=255)
    bg = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    bg.paste(Image.new("RGBA", (S, S), TILE + "FF"), mask=mask)
    bg.alpha_composite(layer, dest=(0, 0))
    bg.save(os.path.join(here, "icon.png"))
    # --- icon.ico: Multi-Size aus derselben Kachel ---
    big = Image.new("RGBA", (256, 256), TILE + "FF")
    db = ImageDraw.Draw(big)
    for y, row in enumerate(MAP):
        for x, ch in enumerate(row):
            if ch != ".":
                db.rectangle([OFF + x * SCALE, OFF + y * SCALE,
                              OFF + (x + 1) * SCALE - 1, OFF + (y + 1) * SCALE - 1],
                             fill=PALETTE[ch] + "FF")
    big.save(os.path.join(here, "icon.ico"), sizes=[(16, 16), (32, 32), (48, 48), (256, 256)])
    print("OK: icon.png, icon.ico, sprite.svg.txt, favicon.txt")
    print(svg_paths())


if __name__ == "__main__":
    main()
