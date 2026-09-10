#!/usr/bin/env python3
"""Type-check the runtime files each installer actually declares for copying."""
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

root = Path(__file__).resolve().parent.parent
plans = [
    ("Linux", "install-agent.sh", r"cp '\$\{AGENT_SOURCE_DIR\}/([^']+\.(?:ts|jsonc))'"),
    ("Windows", "install-agent-windows.ps1", r'Copy-Item -Path "\$PSScriptRoot\\\.\.\\([^"\\]+\.(?:ts|jsonc))"'),
]
for platform, installer, pattern in plans:
    names = re.findall(pattern, (root / "scripts" / installer).read_text())
    assert "main.ts" in names, f"{platform}: runtime copy instructions not found"
    with tempfile.TemporaryDirectory() as temporary:
        for name in names:
            shutil.copyfile(root / name, Path(temporary) / name)
        subprocess.run(["deno", "check", str(Path(temporary) / "main.ts")], check=True)
    print(f"{platform}: installed runtime dependency closure verified")
