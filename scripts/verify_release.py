"""Block an agent release when its image, chart, or identity safety metadata drifts."""

from __future__ import annotations

import argparse
import ast
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def assigned_string(path: Path, name: str) -> str:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in tree.body:
        if (
            isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == name for target in node.targets)
            and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)
        ):
            return node.value.value
    raise SystemExit(f"{path.name} does not define a literal {name}")


def yaml_scalar(path: Path, name: str) -> str:
    match = re.search(rf"(?m)^{re.escape(name)}:\s*[\"']?([^\"'\s]+)", path.read_text(encoding="utf-8"))
    if not match:
        raise SystemExit(f"{path} does not define {name}")
    return match.group(1)


def image_tag(path: Path) -> str:
    in_image = False
    for line in path.read_text(encoding="utf-8").splitlines():
        if line and not line[0].isspace():
            in_image = line.rstrip() == "image:"
            continue
        if in_image:
            match = re.match(r'\s+tag:\s*["\']?([^"\'\s]+)', line)
            if match:
                return match.group(1)
    raise SystemExit(f"{path} does not define image.tag")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--agent-only", action="store_true")
    parser.add_argument("--chart-dir", type=Path)
    args = parser.parse_args()

    version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
    reported = assigned_string(ROOT / "collector.py", "AGENT_VERSION")
    if not version or version != reported:
        raise SystemExit(f"Release blocked: VERSION={version!r}, collector.AGENT_VERSION={reported!r}")

    source = (ROOT / "agent.py").read_text(encoding="utf-8")
    required = (
        "stable_cluster_identity_source",
        "stable_cluster_identifier",
        "kube-system-namespace-uid-v1",
        'signals["cluster_identity"]',
    )
    missing = [marker for marker in required if marker not in source]
    if missing:
        raise SystemExit("Release blocked: stable physical cluster identity is missing: " + ", ".join(missing))

    if args.chart_dir and not args.agent_only:
        chart_dir = args.chart_dir.resolve()
        chart_version = yaml_scalar(chart_dir / "Chart.yaml", "version")
        app_version = yaml_scalar(chart_dir / "Chart.yaml", "appVersion")
        values_version = image_tag(chart_dir / "values.yaml")
        if app_version != version or values_version != version:
            raise SystemExit(
                "Release blocked: image metadata differs: "
                f"VERSION={version}, appVersion={app_version}, values.image.tag={values_version}"
            )
        if not chart_version:
            raise SystemExit("Release blocked: Helm chart version is empty")

    print(f"Release safety check passed for KrevoPilot Agent {version}")


if __name__ == "__main__":
    main()
