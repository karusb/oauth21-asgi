"""Check published Markdown's local file links and heading anchors."""

from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]


def anchors(text: str) -> set[str]:
    counts: dict[str, int] = {}
    result: set[str] = set()
    for heading in re.findall(r"^#{1,6}\s+(.+)$", text, re.MULTILINE):
        heading = re.sub(r"[^\w\- ]", "", heading.lower()).replace(" ", "-")
        number = counts.get(heading, 0)
        counts[heading] = number + 1
        result.add(f"{heading}-{number}" if number else heading)
    return result


def main() -> None:
    failures: list[str] = []
    documents = sorted([*ROOT.glob("*.md"), *ROOT.joinpath("docs").rglob("*.md")])
    for document in documents:
        text = document.read_text(encoding="utf-8")
        for link in re.findall(r"\]\(([^)\s]+)\)", text):
            repository_prefix = "https://github.com/karusb/oauth21-asgi/blob/main/"
            repository_link = link.startswith(repository_prefix)
            parsed = urlsplit(link.removeprefix(repository_prefix))
            if parsed.scheme or parsed.netloc:
                continue
            base = ROOT if repository_link else document.parent
            target = (base / unquote(parsed.path)).resolve() if parsed.path else document
            if not target.is_relative_to(ROOT) or not target.is_file():
                failures.append(f"{document.relative_to(ROOT)}: missing file {link}")
            elif target.suffix == ".md" and parsed.fragment:
                if unquote(parsed.fragment) not in anchors(target.read_text(encoding="utf-8")):
                    failures.append(f"{document.relative_to(ROOT)}: missing heading {link}")
    if failures:
        raise SystemExit("\n".join(failures))
    print(f"Validated local links and heading anchors in {len(documents)} documents")


if __name__ == "__main__":
    main()
