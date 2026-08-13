"""Smoke-test the installed wheel from outside the source checkout."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import tarfile
import zipfile


def main(argv: list[str] | None = None) -> int:
    repo_root = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(repo_root))
    from kona import __version__
    distribution = Path(argv[0]).expanduser() if argv else repo_root / "dist"
    wheels = sorted(distribution.glob(f"kona_local_hop-{__version__}-*.whl"))
    if not wheels:
        raise RuntimeError("no wheel found in dist/")
    wheel = wheels[-1]
    with zipfile.ZipFile(wheel) as archive:
        names = set(archive.namelist())
    if "kona/contract.py" not in names:
        raise RuntimeError(f"wheel does not contain runtime contract module: {wheel.name}")
    runtime_modules = ("kona/workspace.py", "kona/bundle.py", "kona/github.py", "kona/authoring.py", "kona/explanation.py", "kona/scanner.py")
    if any(module not in names for module in runtime_modules):
        raise RuntimeError(f"wheel does not contain all runtime modules: {wheel.name}")
    source_archives = sorted(distribution.glob(f"kona_local_hop-{__version__}.tar.gz"))
    if source_archives:
        with tarfile.open(source_archives[-1], "r:gz") as archive:
            source_names = set(archive.getnames())
        required_assets = ("schemas/contract.schema.json", "skills/kona-capture/SKILL.md", "examples/contracts/README.md", "action.yml")
        for asset in required_assets:
            if not any(name.endswith(asset) for name in source_names):
                raise RuntimeError(f"source distribution is missing {asset}")
    with tempfile.TemporaryDirectory(prefix="kona-installed-") as temporary:
        environment_root = Path(temporary) / "venv"
        subprocess.run([sys.executable, "-m", "venv", str(environment_root)], check=True, capture_output=True, text=True)
        installed_python = environment_root / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
        environment = os.environ.copy()
        environment.pop("PYTHONPATH", None)
        subprocess.run(
            [str(installed_python), "-m", "pip", "install", "--no-deps", str(wheel)],
            cwd=temporary,
            env=environment,
            check=True,
            capture_output=True,
            text=True,
        )
        subprocess.run([str(installed_python), "-m", "kona", "--help"], cwd=temporary, env=environment, check=True)
        subprocess.run([str(installed_python), "-m", "kona", "contract", "templates", "--json"], cwd=temporary, env=environment, check=True)
        subprocess.run([str(installed_python), "-m", "kona", "scan", ".", "--format", "json"], cwd=temporary, env=environment, check=True)
        subprocess.run(
            [str(installed_python), "-c", f"import kona; assert kona.__version__ == '{__version__}'"],
            cwd=temporary,
            env=environment,
            check=True,
        )
    print(f"installed wheel smoke test passed: {wheel.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
