from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).parents[1]
DOCS = ROOT / "docs"
WIDTH = 1600
HEIGHT = 900
BACKGROUND = "#0b0d10"
PANEL = "#161a20"
LINE = "#7d8793"
TEXT = "#f3f5f7"
MUTED = "#a7b0ba"
WHITE = "#ffffff"
AMBER = "#f0b44d"
RED = "#ef5b5b"
GREEN = "#56c48b"


def font(size: int, bold: bool = False) -> ImageFont.FreeTypeFont:
    candidates = [
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"
        if bold
        else "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "/usr/share/fonts/truetype/liberation2/LiberationSans-Bold.ttf"
        if bold
        else "/usr/share/fonts/truetype/liberation2/LiberationSans-Regular.ttf",
    ]
    for candidate in candidates:
        if Path(candidate).exists():
            return ImageFont.truetype(candidate, size)
    return ImageFont.load_default()


def rounded_box(
    draw: ImageDraw.ImageDraw,
    bounds: tuple[int, int, int, int],
    title: str,
    lines: list[str],
    accent: str = WHITE,
) -> None:
    draw.rounded_rectangle(bounds, radius=24, fill=PANEL, outline=accent, width=3)
    x1, y1, _, _ = bounds
    draw.text((x1 + 28, y1 + 24), title, font=font(28, True), fill=TEXT)
    y = y1 + 75
    for line in lines:
        draw.text((x1 + 28, y), line, font=font(20), fill=MUTED)
        y += 32


def arrow(
    draw: ImageDraw.ImageDraw,
    start: tuple[int, int],
    end: tuple[int, int],
    color: str = LINE,
) -> None:
    draw.line([start, end], fill=color, width=5)
    x, y = end
    draw.polygon([(x, y), (x - 16, y - 10), (x - 16, y + 10)], fill=color)


def interactions() -> None:
    image = Image.new("RGB", (WIDTH, HEIGHT), BACKGROUND)
    draw = ImageDraw.Draw(image)
    draw.text((70, 50), "Lil Tweak — Phase 3 Interactions", font=font(42, True), fill=TEXT)
    draw.text(
        (70, 108),
        "Owner-approved recovery is encrypted and source-preserving. Execution stays disconnected.",
        font=font(23),
        fill=MUTED,
    )

    rounded_box(
        draw,
        (55, 245, 305, 515),
        "Owner",
        ["Submit task", "Review plan", "Approve capture"],
    )
    rounded_box(
        draw,
        (365, 210, 650, 550),
        "API Control",
        ["Owner auth", "Job + recovery state", "Idempotency checks", "Emergency stop"],
        GREEN,
    )
    rounded_box(
        draw,
        (715, 190, 1015, 500),
        "Repo Inspector",
        ["Filter-free plumbing", "Byte snapshot", "Secret redaction", "Before / after proof"],
        GREEN,
    )
    rounded_box(
        draw,
        (1080, 190, 1375, 430),
        "Planning Agent",
        ["Sanitized facts only", "Structured plan", "No tools"],
        WHITE,
    )
    rounded_box(
        draw,
        (1065, 515, 1375, 755),
        "Policy + Approval",
        ["Exact digest", "Owner identity", "Atomic one-use + expiry"],
        AMBER,
    )
    rounded_box(
        draw,
        (715, 555, 1015, 805),
        "Encrypted Recovery",
        ["Object-to-byte patches", "Scoped non-index TAR", "AES-256-GCM", "Ciphertext only"],
        GREEN,
    )
    rounded_box(
        draw,
        (1395, 285, 1570, 595),
        "Evidence",
        ["Digests", "Hash chain", "HMAC anchor"],
        GREEN,
    )

    arrow(draw, (305, 380), (365, 380))
    arrow(draw, (650, 300), (715, 300))
    arrow(draw, (1015, 300), (1080, 300))
    arrow(draw, (865, 500), (865, 555), GREEN)
    arrow(draw, (1065, 620), (650, 470))
    arrow(draw, (1015, 680), (1065, 630), GREEN)
    arrow(draw, (1375, 360), (1395, 400))
    arrow(draw, (1375, 630), (1395, 510))

    draw.rounded_rectangle((365, 675, 715, 790), radius=20, fill=PANEL, outline=RED, width=3)
    draw.text((395, 700), "Runner: DISCONNECTED", font=font(22, True), fill=RED)
    draw.text((395, 742), "No writes, tests, or deploys", font=font(19), fill=MUTED)

    image.save(DOCS / "agent-interactions.png")


def sequence() -> None:
    image = Image.new("RGB", (WIDTH, HEIGHT), BACKGROUND)
    draw = ImageDraw.Draw(image)
    draw.text((70, 45), "Lil Tweak — Phase 3 Recovery Sequence", font=font(42, True), fill=TEXT)
    columns = [
        (120, "Owner"),
        (420, "API + State"),
        (730, "Repo Inspector"),
        (1040, "Planning Agent"),
        (1370, "Recovery + Evidence"),
    ]
    for x, name in columns:
        draw.text((x - 60, 135), name, font=font(24, True), fill=TEXT)
        draw.line((x, 185, x, 825), fill=LINE, width=2)

    events = [
        (220, 120, 420, "Create job + idempotency key", GREEN),
        (300, 420, 730, "Resolve registered repository", GREEN),
        (380, 730, 420, "Return sanitized facts + snapshot digest", GREEN),
        (460, 420, 1040, "Send sanitized facts only", WHITE),
        (540, 1040, 420, "Return PlanResult", WHITE),
        (620, 420, 1370, "Bind exact snapshot + recovery digest", AMBER),
        (700, 120, 1370, "Owner approves exact capture", AMBER),
        (780, 1370, 420, "Encrypted artifacts + manifest", GREEN),
    ]
    for y, start_x, end_x, label, color in events:
        direction = 1 if end_x > start_x else -1
        draw.line((start_x, y, end_x, y), fill=color, width=4)
        draw.polygon(
            [
                (end_x, y),
                (end_x - 14 * direction, y - 9),
                (end_x - 14 * direction, y + 9),
            ],
            fill=color,
        )
        label_x = min(start_x, end_x) + 12
        draw.text((label_x, y - 32), label, font=font(19), fill=TEXT)

    draw.text(
        (70, 842),
        "Approved source scope stays unchanged. No path enters EXECUTING in Phase 3.",
        font=font(21),
        fill=RED,
    )
    image.save(DOCS / "agent-sequence.png")


if __name__ == "__main__":
    DOCS.mkdir(parents=True, exist_ok=True)
    interactions()
    sequence()
