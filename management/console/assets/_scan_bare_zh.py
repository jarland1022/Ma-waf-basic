# -*- coding: utf-8 -*-
import re
from pathlib import Path

text = Path(__file__).with_name("app.js").read_text(encoding="utf-8")
lines = text.splitlines()
bare = []
for i, line in enumerate(lines, 1):
    if not re.search(r"[\u4e00-\u9fff]", line):
        continue
    if line.strip().startswith("//"):
        continue
    # strip simple t("zh","en") / t('zh','en')
    cleaned = re.sub(
        r"""t\(\s*(['"])(?:\\.|(?!\1).)*\1\s*,\s*(['"])(?:\\.|(?!\2).)*\2\s*\)""",
        "",
        line,
    )
    cleaned = re.sub(r"t\(\s*`[^`]*`\s*,\s*`[^`]*`\s*\)", "", cleaned)
    if re.search(r"[\u4e00-\u9fff]", cleaned):
        bare.append((i, line.rstrip()[:200]))

print("count", len(bare))
for a, b in bare:
    print(f"{a}: {b}")
