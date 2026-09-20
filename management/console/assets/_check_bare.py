# -*- coding: utf-8 -*-
"""Quick check: scan bare ZH and dump UTF-8."""
import re
from pathlib import Path

assets = Path(__file__).parent
text = (assets / "app.js").read_text(encoding="utf-8")
lines = text.splitlines()
bare = []
for i, line in enumerate(lines, 1):
    if not re.search(r"[\u4e00-\u9fff]", line):
        continue
    if line.strip().startswith("//"):
        continue
    cleaned = re.sub(
        r"""t\(\s*(['"])(?:\\.|(?!\1).)*\1\s*,\s*(['"])(?:\\.|(?!\2).)*\2\s*\)""",
        "",
        line,
    )
    cleaned = re.sub(r"t\(\s*`[^`]*`\s*,\s*`[^`]*`\s*\)", "", cleaned)
    if re.search(r"[\u4e00-\u9fff]", cleaned):
        bare.append((i, line.rstrip()[:220]))

out = assets / "_bare_zh.txt"
out.write_text(
    "count " + str(len(bare)) + "\n" + "\n".join(f"{a}: {b}" for a, b in bare) + "\n",
    encoding="utf-8",
)
print("count", len(bare))
print("wrote", out)
# show first 40
for a, b in bare[:40]:
    print(f"{a}: {b}")
