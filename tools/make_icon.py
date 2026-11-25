"""生成反向代理主题的应用图标（v2，优化版）。

设计：
  左侧「请求入口」圆点  →  中间「路由中枢」方块（内含分流箭头）→  右侧两个「后端」圆点
  蓝紫渐变背景，圆角方形，符合 fnOS 图标风格。
"""

import os

from PIL import Image, ImageDraw, ImageFilter

# 配色
C_BG_TOP = (34, 58, 132)
C_BG_BOT = (78, 126, 224)
C_LINE = (214, 232, 255)
C_HUB = (255, 255, 255)
C_ARROW = (46, 88, 178)
C_IN = (255, 255, 255)
C_OUT = (118, 218, 255)


def rounded_mask(size: int, radius: int) -> Image.Image:
    m = Image.new("L", (size, size), 0)
    ImageDraw.Draw(m).rounded_rectangle(
        [0, 0, size - 1, size - 1], radius=radius, fill=255)
    return m


def gradient_bg(size: int) -> Image.Image:
    img = Image.new("RGB", (size, size))
    d = ImageDraw.Draw(img)
    for y in range(size):
        t = y / max(1, size - 1)
        # 轻微偏心的渐变，更有质感
        t2 = t ** 0.85
        d.line([(0, y), (size, y)], fill=(
            int(C_BG_TOP[0] + (C_BG_BOT[0] - C_BG_TOP[0]) * t2),
            int(C_BG_TOP[1] + (C_BG_BOT[1] - C_BG_TOP[1]) * t2),
            int(C_BG_TOP[2] + (C_BG_BOT[2] - C_BG_TOP[2]) * t2),
        ))
    return img


def draw(size: int, ss: int = 4) -> Image.Image:
    S = size * ss
    img = gradient_bg(S).convert("RGBA")
    d = ImageDraw.Draw(img)

    def sc(v):
        return int(v * S / 256)

    # ---- 布局 ----
    in_pt = (sc(52), sc(128))
    in_r = sc(19)

    hub_cx, hub_cy = sc(126), sc(128)
    hub_w, hub_h = sc(72), sc(104)
    hub_r = sc(18)

    out1 = (sc(206), sc(84))
    out2 = (sc(206), sc(172))
    out_r = sc(16)

    hx0, hy0 = hub_cx - hub_w // 2, hub_cy - hub_h // 2
    hx1, hy1 = hub_cx + hub_w // 2, hub_cy + hub_h // 2

    # ---- 连线：从节点边缘连到中枢边缘 ----
    link = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    ld = ImageDraw.Draw(link)
    lw = sc(8)

    ld.line([(in_pt[0] + in_r + sc(2), in_pt[1]), (hx0, hub_cy)],
            fill=C_LINE + (200,), width=lw)
    ld.line([(hx1, hub_cy - sc(20)), (out1[0] - out_r - sc(2), out1[1])],
            fill=C_LINE + (200,), width=lw)
    ld.line([(hx1, hub_cy + sc(20)), (out2[0] - out_r - sc(2), out2[1])],
            fill=C_LINE + (200,), width=lw)

    # 发光
    img = Image.alpha_composite(
        img, link.filter(ImageFilter.GaussianBlur(sc(6))))
    img = Image.alpha_composite(img, link)
    d = ImageDraw.Draw(img)

    # ---- 中枢阴影 ----
    sh = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    ImageDraw.Draw(sh).rounded_rectangle(
        [hx0, hy0 + sc(5), hx1, hy1 + sc(5)],
        radius=hub_r, fill=(0, 0, 0, 70))
    img = Image.alpha_composite(
        img, sh.filter(ImageFilter.GaussianBlur(sc(5))))
    d = ImageDraw.Draw(img)

    # ---- 中枢方块 ----
    d.rounded_rectangle([hx0, hy0, hx1, hy1], radius=hub_r, fill=C_HUB)

    # 方块内三条分流箭头（左进右出，表示路由分发）
    pad_l = hx0 + sc(13)
    arrow_len = sc(30)
    tail = sc(9)
    ys = [hub_cy - sc(30), hub_cy, hub_cy + sc(30)]
    th = sc(5)

    for y in ys:
        # 主干
        d.line([(pad_l, y), (pad_l + arrow_len - tail, y)],
               fill=C_ARROW + (255,), width=th)
        # 箭头
        tip = pad_l + arrow_len
        d.polygon([
            (tip - tail, y - sc(7)),
            (tip, y),
            (tip - tail, y + sc(7)),
        ], fill=C_ARROW + (255,))

    # ---- 节点 ----
    def node(cx, cy, r, fill):
        # 外环（柔光）
        d.ellipse([cx - r - sc(5), cy - r - sc(5),
                   cx + r + sc(5), cy + r + sc(5)],
                  fill=(255, 255, 255, 55))
        d.ellipse([cx - r, cy - r, cx + r, cy + r], fill=fill)

    node(out1[0], out1[1], out_r, C_OUT)
    node(out2[0], out2[1], out_r, C_OUT)
    node(in_pt[0], in_pt[1], in_r, C_IN)

    return img.resize((size, size), Image.LANCZOS)


def main():
    root = "/mnt/c/work/dsh-workspace/DNS-RP"
    size = 256

    icon = draw(size)
    icon.putalpha(rounded_mask(size, radius=int(size * 0.23)))

    targets = [
        (f"{root}/ICON.PNG", 256),
        (f"{root}/ICON_256.PNG", 256),
        (f"{root}/app/ui/images/icon_256.png", 256),
        (f"{root}/app/ui/images/icon_64.png", 64),
    ]
    for path, sz in targets:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        im = icon if sz == size else icon.resize((sz, sz), Image.LANCZOS)
        im.save(path, "PNG", optimize=True)
        print(f"  {path}  ({sz}x{sz}, {os.path.getsize(path)} 字节)")


if __name__ == "__main__":
    main()
