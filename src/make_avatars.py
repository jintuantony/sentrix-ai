"""Run once from the project root: python src/make_avatars.py"""
import math
import os
from PIL import Image, ImageDraw, ImageFilter

S, OUT = 512, 128
RED, DARK, MID = (255, 59, 59), (14, 8, 9), (58, 16, 16)


def glow(img, strength=10):
    g = img.filter(ImageFilter.GaussianBlur(strength))
    return Image.alpha_composite(g, img)


def base():
    im = Image.new("RGBA", (S, S), DARK + (255,))
    d = ImageDraw.Draw(im)
    d.rounded_rectangle([6, 6, S - 6, S - 6], 70, outline=MID, width=8)
    return im


def bot():
    im = base()
    fx = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    d = ImageDraw.Draw(fx)
    c, r = S // 2, 170
    hexp = [(c + r * math.cos(math.radians(60 * i + 30)), c + r * math.sin(math.radians(60 * i + 30))) for i in range(6)]
    d.polygon(hexp, outline=RED + (255,), width=12)
    d.ellipse([c - 78, c - 78, c + 78, c + 78], outline=RED + (255,), width=10)
    d.ellipse([c - 30, c - 30, c + 30, c + 30], fill=RED + (255,))
    for a in (0, 90, 180, 270):
        x, y = c + 112 * math.cos(math.radians(a)), c + 112 * math.sin(math.radians(a))
        d.ellipse([x - 9, y - 9, x + 9, y + 9], fill=RED + (255,))
    return Image.alpha_composite(im, glow(fx, 8))


def user():
    im = base()
    fx = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    d = ImageDraw.Draw(fx)
    c = S // 2
    d.polygon([(c, 70), (c + 150, 250), (c + 190, 450), (c - 190, 450), (c - 150, 250)], fill=(30, 12, 14, 255), outline=RED + (255,))
    d.line([(c, 70), (c + 150, 250), (c + 190, 450)], fill=RED + (255,), width=10)
    d.line([(c, 70), (c - 150, 250), (c - 190, 450)], fill=RED + (255,), width=10)
    d.ellipse([c - 95, 190, c + 95, 380], fill=(4, 2, 3, 255))
    for x in (c - 42, c + 42):
        d.polygon([(x - 26, 275), (x + 26, 275), (x + 18, 300), (x - 18, 300)], fill=RED + (255,))
    return Image.alpha_composite(im, glow(fx, 7))


os.makedirs("assets", exist_ok=True)
bot().resize((OUT, OUT), Image.LANCZOS).save("assets/bot.png")
user().resize((OUT, OUT), Image.LANCZOS).save("assets/user.png")
print("saved assets/bot.png and assets/user.png")