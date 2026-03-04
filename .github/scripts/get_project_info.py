"""Extract project metadata from pyproject.toml and write to GITHUB_OUTPUT."""

import os
import re
import sys
import tomllib

from datetime import UTC, datetime
from pathlib import Path


PYPROJECT_PATH = Path("pyproject.toml")


def main() -> None:
    data = tomllib.loads(PYPROJECT_PATH.read_text())["project"]
    version = data.get("version", "0.0.0")
    is_pre = bool(re.search(r"(a|b|rc|dev|alpha|beta|pre)", version))

    output_file_path = os.environ.get("GITHUB_OUTPUT", None)
    output = sys.stdout
    if output_file_path:
        ofp = Path(output_file_path)
        if ofp.exists():
            output = ofp.open("a")

    with output as f:
        f.write(f"version={version}\n")
        f.write(f"license={data.get('license', '')}\n")
        f.write(f"description={data.get('description', '')}\n")
        f.write(f"is_prerelease={str(is_pre).lower()}\n")
        f.write(f"created_at={datetime.now(UTC).strftime('%Y-%m-%dT%H:%M:%S.%fZ')}\n")


if __name__ == "__main__":
    main()
