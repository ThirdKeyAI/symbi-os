"""Run bounded offline audio/video decoder checks for MPlayer and mpv."""
import hashlib
import json
import math
import os
from pathlib import Path
import struct
import wave

try:
    from image.launcher.probes.bounded_process import run_bounded
except ModuleNotFoundError:  # Copied standalone into the qualification mount.
    from bounded_process import run_bounded


PLAYBACK_LIMITS = {"memory.max": "536870912", "memory.swap.max": "0",
                   "cpu.max": "100000 100000", "pids.max": "64"}
PLAYBACK_SCOPE = "Headless software decode to null outputs; no device, GPU, display or untrusted-media qualification"
PLAYBACK_FIXTURE_SHA256 = {
    "audio": "2c3170195b4a48840b8b9dd1ee2a269bc793413ce58a474b6f80412b068947a3",
    "video": "65a5574f4654cfbfdc53b38f7f2f8f6c3471940406cc4b991b91c29bbb10f421",
}


def write_fixtures(directory):
    directory.mkdir(parents=True, exist_ok=True)
    audio = directory / "tone.wav"
    rate = 8000
    with wave.open(str(audio), "wb") as output:
        output.setnchannels(1); output.setsampwidth(2); output.setframerate(rate)
        samples = bytearray()
        for index in range(rate // 4):
            samples.extend(struct.pack("<h", int(4096 * math.sin(2 * math.pi * 440 * index / rate))))
        output.writeframes(samples)
    video = directory / "frames.y4m"
    width = height = 16
    header = f"YUV4MPEG2 W{width} H{height} F5:1 Ip A1:1 C420jpeg\n".encode()
    frame = b"FRAME\n" + bytes([96]) * (width * height) + bytes([128]) * (width * height // 2)
    video.write_bytes(header + frame + frame)
    audio.chmod(0o644); video.chmod(0o644)
    return {"audio": audio, "video": video}


PACKAGE_FIELDS = ("name", "epoch", "version", "release", "arch", "nevra", "vendor", "license", "source_rpm")


def _package_identity(row):
    return {name: row[name] for name in PACKAGE_FIELDS}


def require_playback_report(report, variant, lock_sha256, expected_packages):
    expected = {(player, media) for player in ("mplayer", "mpv") for media in ("audio", "video")}
    fields = {"schema", "passed", "variant", "lock_sha256", "limits", "checks",
              "installed_packages", "network", "audio_device_qualified",
              "hardware_decode_qualified", "interactive_output_qualified", "scope",
              "cgroup_final"}
    if not isinstance(report, dict) or set(report) != fields:
        raise ValueError("Media playback report has an unexpected schema")
    rows = report.get("checks")
    packages = report.get("installed_packages")
    final = report.get("cgroup_final")
    if not isinstance(final, dict) or set(final) != {
            *PLAYBACK_LIMITS, "memory.peak", "memory.events", "cpu.stat"}:
        raise ValueError("Media playback report lacks exact final resource evidence")

    def table(raw):
        if not isinstance(raw, str):
            raise ValueError("Malformed media playback resource counters")
        rows = [line.split() for line in raw.splitlines()]
        if any(len(row) != 2 for row in rows) or len({row[0] for row in rows}) != len(rows):
            raise ValueError("Malformed media playback resource counters")
        return dict(rows)

    events = table(final["memory.events"])
    cpu = table(final["cpu.stat"])
    expected_events = {"low", "high", "max", "oom", "oom_kill", "oom_group_kill"}
    if (set(events) != expected_events or any(not value.isdigit() for value in events.values())
            or any(events[name] != "0" for name in ("oom", "oom_kill", "oom_group_kill"))
            or not {"usage_usec", "user_usec", "system_usec"}.issubset(cpu)
            or any(not value.isdigit() for value in cpu.values())
            or not isinstance(final["memory.peak"], str) or not final["memory.peak"].isdigit()
            or int(final["memory.peak"]) > int(PLAYBACK_LIMITS["memory.max"])):
        raise ValueError("Media playback final resource counters are incomplete or unsafe")
    if (report.get("schema") != 1 or report.get("passed") is not True or report.get("variant") != variant
            or report.get("lock_sha256") != lock_sha256 or report.get("network") != "none"
            or report.get("limits") != PLAYBACK_LIMITS
            or any(final[name] != value for name, value in PLAYBACK_LIMITS.items())
            or report.get("scope") != PLAYBACK_SCOPE
            or report.get("audio_device_qualified") is not False
            or report.get("hardware_decode_qualified") is not False
            or report.get("interactive_output_qualified") is not False
            or not isinstance(rows, list) or len(rows) != 4
            or {(row.get("player"), row.get("media")) for row in rows} != expected
            or any(set(row) != {"player", "media", "exit_code", "bounded", "fixture_sha256"}
                   or row.get("exit_code") != 0 or row.get("bounded") is not True
                   or row.get("fixture_sha256") != PLAYBACK_FIXTURE_SHA256.get(row.get("media"))
                   for row in rows)
            or packages != [_package_identity(row) for row in expected_packages]):
        raise ValueError("Media playback report is incomplete or overclaims its scope")
    return True


def main():
    inputs, output = Path("/qualification"), Path("/output")
    if os.geteuid() != 10001 or not Path("/run/.containerenv").exists():
        raise SystemExit("Use the unprivileged hosted media qualification container")
    status = dict(row.split(":", 1) for row in Path("/proc/self/status").read_text().splitlines() if ":" in row)
    group = Path("/sys/fs/cgroup") / Path(Path("/proc/self/cgroup").read_text().strip().split("::", 1)[1]).relative_to("/")
    limits = {name: (group / name).read_text().strip()
              for name in ("memory.max", "memory.swap.max", "cpu.max", "pids.max")}
    if (limits != PLAYBACK_LIMITS
            or status["CapEff"].strip() != "0000000000000000" or status["NoNewPrivs"].strip() != "1"
            or not os.statvfs("/").f_flag & os.ST_RDONLY
            or sorted(path.name for path in Path("/sys/class/net").iterdir()) != ["lo"]):
        raise ValueError("Media playback isolation or resource limits changed")
    expected = json.loads((inputs / "expected.json").read_text())
    expected_packages = expected["root_packages"]
    if [row.get("name") for row in expected_packages] != ["mplayer", "mplayer-common", "mpv"]:
        raise ValueError("Playback expected package set changed")
    fixtures = write_fixtures(output / "fixtures")
    record = {"schema": 1, "passed": False, "variant": expected["variant"],
              "lock_sha256": expected["lock_sha256"], "limits": limits, "checks": [],
              "installed_packages": [],
              "network": "none", "audio_device_qualified": False,
              "hardware_decode_qualified": False, "interactive_output_qualified": False,
              "scope": PLAYBACK_SCOPE}

    def save():
        (output / "result.json").write_text(json.dumps(record, indent=2) + "\n")

    commands = {
        "mplayer": lambda path: ["/usr/bin/mplayer", "-really-quiet", "-nolirc", "-noconsolecontrols",
                                   "-ao", "null", "-vo", "null", "-frames", "2", str(path)],
        "mpv": lambda path: ["/usr/bin/mpv", "--no-config", "--really-quiet", "--ao=null", "--vo=null",
                               "--frames=2", "--", str(path)],
    }
    versions = {"mplayer": ["/usr/bin/mplayer", "-version"],
                "mpv": ["/usr/bin/mpv", "--version"]}
    try:
        query_format = "%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\t%{NEVRA}\t%{VENDOR}\t%{LICENSE}\t%{SOURCERPM}\n"
        for index, package in enumerate(expected_packages):
            result = run_bounded(["/usr/bin/rpm", "-q", "--qf", query_format, package["name"]],
                                 output / f"rpm-{index:03}-identity.out",
                                 output / f"rpm-{index:03}-identity.err", 15, 128 * 1024)
            result.check_returncode()
            rows = result.stdout.splitlines()
            actual = dict(zip(PACKAGE_FIELDS, rows[0].split("\t"))) if len(rows) == 1 else {}
            if actual != _package_identity(package):
                raise ValueError("Installed media package identity differs from the selected lock")
            record["installed_packages"].append(actual)
            save()
        for player, build in commands.items():
            version = run_bounded(versions[player], output / (player + "-version.out"),
                                  output / (player + "-version.err"), 15, 128 * 1024)
            version.check_returncode()
            for media, path in fixtures.items():
                result = run_bounded(build(path), output / (player + "-" + media + ".out"),
                                     output / (player + "-" + media + ".err"), 30, 128 * 1024)
                row = {"player": player, "media": media, "exit_code": result.returncode,
                       "bounded": True, "fixture_sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
                record["checks"].append(row); save(); result.check_returncode()
        record["passed"] = True
    except Exception as error:
        record["failure"] = type(error).__name__ + ": " + str(error)
        raise
    finally:
        record["cgroup_final"] = {name: (group / name).read_text().strip()
                                   for name in (*limits, "memory.peak", "memory.events", "cpu.stat")}
        events = dict(row.split() for row in record["cgroup_final"]["memory.events"].splitlines())
        if any(events.get(name) != "0" for name in ("oom", "oom_kill", "oom_group_kill")):
            record["passed"] = False
        save()
    if record["passed"]:
        try:
            require_playback_report(record, expected["variant"], expected["lock_sha256"], expected_packages)
        except Exception as error:
            record["passed"] = False
            record["failure"] = type(error).__name__ + ": " + str(error)
            save()
            raise
    if not record["passed"]:
        raise RuntimeError("Media playback resource controls failed")


if __name__ == "__main__":
    main()
