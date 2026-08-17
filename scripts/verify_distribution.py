"""Smoke-test the installed wheel from outside the source checkout."""

from __future__ import annotations

import json
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
    runtime_modules = ("kona/workspace.py", "kona/bundle.py", "kona/github.py", "kona/authoring.py", "kona/explanation.py", "kona/scanner.py", "kona/providers.py")
    if any(module not in names for module in runtime_modules):
        raise RuntimeError(f"wheel does not contain all runtime modules: {wheel.name}")
    source_archives = sorted(distribution.glob(f"kona_local_hop-{__version__}.tar.gz"))
    if source_archives:
        with tarfile.open(source_archives[-1], "r:gz") as archive:
            source_names = set(archive.getnames())
        required_assets = ("schemas/contract.schema.json", "skills/kona-capture/SKILL.md", "examples/contracts/README.md", "action.yml", "scan/action.yml")
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
        subprocess.run([str(installed_python), "-m", "kona", "scan", ".", "--format", "sarif"], cwd=temporary, env=environment, check=True)
        finding_token = "ghp_" + "Z" * 36
        (Path(temporary) / "finding.py").write_text(f'TOKEN = "{finding_token}"\n', encoding="utf-8")
        finding = subprocess.run(
            [str(installed_python), "-m", "kona", "scan", ".", "--format", "sarif", "--fail-on", "high"],
            cwd=temporary,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
        )
        if finding.returncode != 1:
            raise RuntimeError(f"installed wheel did not fail on a high finding: {finding.returncode}")
        finding_sarif = json.loads(finding.stdout)
        finding_results = finding_sarif["runs"][0]["results"]
        if not any(result.get("ruleId") == "SEC002" for result in finding_results):
            raise RuntimeError("installed wheel did not emit the expected SEC002 SARIF result")
        if finding_token in finding.stdout or finding_token in finding.stderr:
            raise RuntimeError("installed wheel leaked the fixture credential")
        subprocess.run([str(installed_python), "-m", "kona", "explain", ".", "--provider", "deepseek", "--model", "deepseek-v4-pro", "--preview"], cwd=temporary, env=environment, check=True)
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
