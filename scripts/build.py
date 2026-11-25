"""Build wheel and source distribution without installing anything."""

import runpy
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main():
    backend = runpy.run_path(str(ROOT / "build_support/swassh_build.py"))
    output = ROOT / "dist"
    output.mkdir(exist_ok=True)
    print(backend["build_wheel"](output))
    print(backend["build_sdist"](output))


if __name__ == "__main__":
    main()
