"""Reconcile the small successful hosted font-intake evidence artifact."""
from pathlib import Path
import hashlib
import json
import re


RUN = 45870354806
SOURCE = "d436c6ee8a7ed159afa59db9bd82377ae8ea2389"
ARTIFACT = 15143136081
CANDIDATE = 15143375647
root = Path(__file__).resolve().parents[6]
here = Path(__file__).resolve().parent
evidence = here / "original"


def load(path):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key: {key}")
            result[key] = value
        return result
    return json.loads(path.read_text(), object_pairs_hook=unique)


def digest(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


metadata = load(here / "artifact-metadata.json")
archive = here / "artifact.zip"
assert metadata["id"] == ARTIFACT
assert metadata["name"] == "nerd-font-intake-evidence"
assert metadata["workflow_run"]["id"] == RUN
assert metadata["workflow_run"]["head_sha"] == SOURCE
assert metadata["expired"] is False
assert metadata["size_in_bytes"] == archive.stat().st_size
assert metadata["digest"] == "sha256:" + digest(archive)

files = load(here / "artifact-files.json")
actual = []
for path in sorted(p for p in evidence.rglob("*") if p.is_file()):
    assert not path.is_symlink()
    actual.append({"path": path.relative_to(evidence).as_posix(),
                   "sha256": digest(path), "size": path.stat().st_size})
assert sorted(files["files"], key=lambda row: row["path"]) == actual
assert files["expanded_file_count"] == len(actual) == 4
assert files["expanded_size"] == sum(row["size"] for row in actual) == 22703

pins_path = root / "image/fonts/inputs.json"
pins = load(pins_path)
result = load(evidence / "result.json")
assert result["schema"] == 1 and result["passed"] is True
assert result["source_commit"] == SOURCE
assert result["inputs_sha256"] == digest(pins_path)
assert result["downloads"] == pins["assets"]
assert result["selected"] is result["font_parser_executed"] is result["archive_extracted"] is False
assert result["os_qualified"] is False and result["private_downloads_removed"] is True
assert result["limits"] == {"memory.max": "536870912", "memory.swap.max": "0",
                             "cpu.max": "100000 100000", "pids.max": "32"}
for name, summary in result["inventories"].items():
    path = evidence / f"{name}.inventory.json"
    inventory = load(path)
    assert summary["inventory_sha256"] == digest(path)
    assert summary["members"] == len(inventory)
    assert summary["fonts"] == sum(name.lower().endswith((".ttf", ".otf")) for name in inventory)
    assert summary["expanded_bytes"] == sum(row["bytes"] for row in inventory.values())
assert result["inventories"]["JetBrainsMono.tar.xz"]["fonts"] == 96
assert result["inventories"]["NerdFontsSymbolsOnly.tar.xz"]["fonts"] == 2
events = dict(line.split() for line in result["cgroup_final"]["memory.events"].splitlines())
assert events["oom"] == events["oom_kill"] == events["oom_group_kill"] == "0"
assert result["cgroup_final"]["memory.swap.max"] == "0"

log = (evidence / "hosted-intake.log").read_text()
assert "Finished with result: success" in log and "status=0" in log and "Memory swap peak: 0B" in log

candidate = load(here / "candidate-artifact-metadata.json")
assert candidate["id"] == CANDIDATE and candidate["name"] == "nerd-font-candidates"
assert candidate["workflow_run"]["id"] == RUN and candidate["workflow_run"]["head_sha"] == SOURCE
assert candidate["expired"] is False and candidate["size_in_bytes"] == 9647668
assert re.fullmatch(r"sha256:[0-9a-f]{64}", candidate["digest"])

check = {
    "schema": 1,
    "independent_evidence_recheck_passed": True,
    "run_id": RUN,
    "source_commit": SOURCE,
    "evidence_artifact": {"id": ARTIFACT, "bytes": archive.stat().st_size,
                           "sha256": digest(archive)},
    "candidate_artifact": {"id": CANDIDATE, "bytes": candidate["size_in_bytes"],
                            "sha256": candidate["digest"].removeprefix("sha256:")},
    "authenticated_downloads": len(result["downloads"]),
    "passively_inventoried_members": sum(row["members"] for row in result["inventories"].values()),
    "passively_inventoried_fonts": sum(row["fonts"] for row in result["inventories"].values()),
    "font_parser_executed": False,
    "archive_extracted": False,
    "oom_or_kill": False,
    "swap_enabled": False,
    "selected": False,
    "os_qualified": False,
    "limitations": "Candidate payload remains hosted. This is intake and passive inventory evidence, not release selection, native font parsing, security clearance, or OS qualification.",
}
(here / "independent-check.json").write_text(json.dumps(check, indent=2) + "\n")
print(json.dumps(check, indent=2))
