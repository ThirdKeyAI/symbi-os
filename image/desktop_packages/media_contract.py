"""Fail-closed contract for exact MPlayer/mpv package and evidence inputs."""
import hashlib
import json
from pathlib import Path
import re


FEDORA = "4F50A6114CD5C6976A7F1179655A4B02F577861E"
FUSION = "E9A491A3DE247814E7E067EAE06F8ECDD651FF2E"
HASH = re.compile(r"[0-9a-f]{64}")
COMMIT = re.compile(r"[0-9a-f]{40}")
RPM_TOKEN = re.compile(r"[A-Za-z0-9+_.~^-]+")
MEDIA_ARTIFACT_NAME = "media-rpms-fedora-45-x86_64"
MEDIA_ARTIFACT_REPOSITORY = "ThirdKeyAI/symbi-os"
MEDIA_ARTIFACT_WORKFLOW = ".github/workflows/media-closure.yml"
MAX_MEDIA_ARTIFACT_BYTES = 2 * 1024**3
# upload-artifact stores the files in a ZIP. Keep a fixed margin for ZIP records,
# uncompressed-deflate framing and filenames so its retained archive remains
# below the artifact contract even at the expanded-payload ceiling.
MAX_MEDIA_ARCHIVE_OVERHEAD_BYTES = 8 * 1024**2
MAX_MEDIA_EXPANDED_BYTES = MAX_MEDIA_ARTIFACT_BYTES - MAX_MEDIA_ARCHIVE_OVERHEAD_BYTES
MAX_MEDIA_MANIFEST_BYTES = 1024**2
MAX_MEDIA_RPM_PAYLOAD_BYTES = MAX_MEDIA_EXPANDED_BYTES - MAX_MEDIA_MANIFEST_BYTES
MAX_MEDIA_RPM_BYTES = 1024**3


def _digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def media_selection_digest(lock):
    """Hash install-affecting selection data without the post-build commit link."""
    if not isinstance(lock, dict) or "image_source_commit" not in lock:
        raise ValueError("Media selection lacks its image commit coordination field")
    selected = dict(lock)
    selected.pop("image_source_commit")
    raw = json.dumps(selected, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return hashlib.sha256(raw).hexdigest()


def require_media_image_binding(lock, manifest, tested_commit):
    """Require the post-build commit relink and the in-image selection digest."""
    linked = lock.get("image_source_commit") if isinstance(lock, dict) else None
    if (not isinstance(manifest, dict) or not COMMIT.fullmatch(tested_commit or "")
            or linked != tested_commit
            or manifest.get("media_selection_sha256") != media_selection_digest(lock)):
        raise ValueError("Retained image was not assembled from the exact selected media inputs")
    return True


def _bound_file(root, binding, maximum=1024 * 1024):
    path = Path(binding.get("path", ""))
    if path.is_absolute() or ".." in path.parts:
        raise ValueError("Evidence path escapes the repository")
    target = root / path
    if (target.is_symlink() or not target.is_file() or target.resolve() != target
            or type(binding.get("bytes")) is not int
            or not 0 < binding["bytes"] <= maximum
            or target.stat().st_size != binding["bytes"]
            or not HASH.fullmatch(binding.get("sha256", ""))
            or _digest(target) != binding["sha256"]):
        raise ValueError("Retained evidence bytes changed")
    return target


def _require_binary_row(row):
    fields = {"name", "epoch", "version", "release", "arch", "nevra", "vendor", "license",
              "source_rpm", "filename", "bytes", "sha256", "signature_verified", "key_fingerprint"}
    if (not isinstance(row, dict) or set(row) != fields
            or not re.fullmatch(r"[a-z][a-z0-9+_.-]*", row.get("name", ""))
            or not RPM_TOKEN.fullmatch(row.get("version", ""))
            or not RPM_TOKEN.fullmatch(row.get("release", ""))
            or row.get("epoch") != "0" or row.get("arch") not in ("x86_64", "noarch")
            or row.get("nevra") != f'{row.get("name")}-{row.get("version")}-{row.get("release")}.{row.get("arch")}'
            or row.get("filename") != row.get("nevra") + ".rpm"
            or not re.fullmatch(r"[A-Za-z0-9+_.~^-]+\.src\.rpm", row.get("source_rpm", ""))
            or type(row.get("bytes")) is not int or not 0 < row["bytes"] <= 512 * 1024 * 1024
            or not HASH.fullmatch(row.get("sha256", "")) or row.get("signature_verified") is not True
            or row.get("key_fingerprint") not in (FEDORA, FUSION)
            or not row.get("vendor") or not row.get("license")):
        raise ValueError("Malformed or unauthenticated media package row")


def _require_source_row(row):
    fields = {"name", "epoch", "version", "release", "arch", "nevra", "filename", "bytes",
              "sha256", "signature_verified", "key_fingerprint"}
    if (not isinstance(row, dict) or set(row) != fields
            or not re.fullmatch(r"[a-z][a-z0-9+_.-]*", row.get("name", ""))
            or not RPM_TOKEN.fullmatch(row.get("version", ""))
            or not RPM_TOKEN.fullmatch(row.get("release", ""))
            or row.get("epoch") != "0"
            or row.get("arch") != "src"
            or row.get("nevra") != f'{row.get("name")}-{row.get("version")}-{row.get("release")}.src'
            or row.get("filename") != row.get("nevra") + ".rpm"
            or type(row.get("bytes")) is not int or not 0 < row["bytes"] <= MAX_MEDIA_RPM_BYTES
            or not HASH.fullmatch(row.get("sha256", "")) or row.get("signature_verified") is not True
            or row.get("key_fingerprint") not in (FEDORA, FUSION)):
        raise ValueError("Malformed or unauthenticated source RPM row")


def require_source_release_match(packages, sources):
    """Bind each selected binary header to its exact authenticated source RPM."""
    if not isinstance(packages, list) or not isinstance(sources, list):
        raise ValueError("Package/source rows must be lists")
    for row in packages:
        _require_binary_row(row)
    for row in sources:
        _require_source_row(row)
    by_filename = {row["filename"]: row for row in sources}
    if len(by_filename) != len(sources):
        raise ValueError("Duplicate source RPM identity")
    expected = {row["source_rpm"] for row in packages}
    if set(by_filename) != expected:
        raise ValueError("Every selected binary needs exactly one authenticated source RPM")
    for package in packages:
        source = by_filename[package["source_rpm"]]
        if (source["version"] != package["version"] or source["release"] != package["release"]
                or source["key_fingerprint"] != package["key_fingerprint"]):
            raise ValueError("Binary/source release or signer mismatch")
    return True


def _require_artifact(value, resolution_base):
    if (not isinstance(value, dict) or set(value) != {
                "id", "name", "producer", "resolution_base", "bytes", "sha256",
                "manifest_sha256"}
            or type(value["id"]) is not int or value["id"] <= 0
            or value["name"] != MEDIA_ARTIFACT_NAME
            or value["resolution_base"] != resolution_base
            or type(value["bytes"]) is not int
            or not 0 < value["bytes"] <= MAX_MEDIA_ARTIFACT_BYTES
            or not HASH.fullmatch(value["sha256"]) or not HASH.fullmatch(value["manifest_sha256"])):
        raise ValueError("Invalid media-only hosted artifact binding")
    producer = value["producer"]
    if (not isinstance(producer, dict)
            or set(producer) != {"repository", "workflow", "run_id", "head_sha"}
            or producer["repository"] != MEDIA_ARTIFACT_REPOSITORY
            or producer["workflow"] != MEDIA_ARTIFACT_WORKFLOW
            or type(producer["run_id"]) is not int or producer["run_id"] <= 0
            or not COMMIT.fullmatch(producer["head_sha"])):
        raise ValueError("Invalid media-only artifact producer binding")


def require_media_artifact_metadata(lock, artifact_metadata, run_metadata):
    """Match GitHub's artifact and workflow-run records to the frozen producer."""
    try:
        artifact = lock["closure"]["artifact"]
        _require_artifact(artifact, lock["resolution_base"])
        producer = artifact["producer"]
        workflow_run = artifact_metadata["workflow_run"]
        repository = run_metadata["repository"]
        if (artifact_metadata.get("id") != artifact["id"]
                or artifact_metadata.get("name") != artifact["name"]
                or artifact_metadata.get("size_in_bytes") != artifact["bytes"]
                or artifact_metadata.get("expired") is not False
                or workflow_run.get("id") != producer["run_id"]
                or workflow_run.get("head_sha") != producer["head_sha"]
                or run_metadata.get("id") != producer["run_id"]
                or run_metadata.get("head_sha") != producer["head_sha"]
                or run_metadata.get("path") != producer["workflow"]
                or repository.get("full_name") != producer["repository"]
                or run_metadata.get("status") != "completed"
                or run_metadata.get("conclusion") != "success"):
            raise ValueError("Media artifact differs from its exact successful producer run")
        return True
    except (KeyError, TypeError, AttributeError) as error:
        raise ValueError("Malformed media artifact producer metadata") from error


def require_media_lock(lock, root, pins, trust, require_ready=False):
    """Validate pending and complete states; only the complete state may install."""
    try:
        if (lock.get("schema") != 1 or lock.get("release") != "45" or lock.get("architecture") != "x86_64"
                or lock.get("resolution_base") != pins["variants"]["generic"]["image"]
                or lock.get("target_bases") != {name: pins["variants"][name]["image"]
                                                        for name in ("generic", "nvidia")}
                or lock.get("trusted_keys") != trust["keys"]
                or [row["fingerprint"] for row in lock["trusted_keys"]] != [FEDORA, FUSION]
                or lock.get("persists_repository_trust") is not False):
            raise ValueError("Media release, base or isolated trust inputs changed")
        discovery = lock["discovery"]
        if (not COMMIT.fullmatch(discovery.get("source_commit", ""))
                or type(discovery.get("run_id")) is not int or discovery["run_id"] <= 0
                or type(discovery.get("job_id")) is not int or discovery["job_id"] <= 0
                or discovery.get("scope") != "Aggregate desktop discovery only; the artifact is not a media-only install closure"):
            raise ValueError("Media discovery binding changed")
        result_binding = {"path": discovery["result_path"], "bytes": discovery["result_bytes"],
                          "sha256": discovery["result_sha256"]}
        result = json.loads(_bound_file(root, result_binding).read_text())
        artifact = discovery["candidate_artifact"]
        if (artifact != {"id": 15116164474, "bytes": 46648044,
                         "sha256": "7f8f6128f3977caeeea5a3efdb355213570d84acd7d441c3be3e22e9d63e1cbc",
                         "expires_at": "2026-12-03T12:22:01Z"}
                or result.get("passed") is not True or result.get("packages_selected") is not False
                or result.get("security_qualified") is not False or result.get("os_qualified") is not False):
            raise ValueError("Aggregate discovery scope or artifact identity changed")
        roots = lock["root_packages"]
        if [row.get("name") for row in roots] != ["mplayer", "mplayer-common", "mpv"]:
            raise ValueError("Expected only the three frozen media roots")
        for row in roots:
            _require_binary_row(row)
        retained = {row["name"]: row for row in result["packages"]}
        if roots != [retained[name] for name in ("mplayer", "mplayer-common", "mpv")]:
            raise ValueError("Media root metadata differs from retained native RPM inspection")
        if ([row["key_fingerprint"] for row in roots] != [FUSION, FUSION, FEDORA]
                or roots[0]["source_rpm"] != roots[1]["source_rpm"]):
            raise ValueError("Media root signer or source relationship changed")

        security = lock["security_evidence"]
        if (security.get("status") != "incomplete-product-name-search-only"
                or security.get("cleared") is not False
                or security.get("scope") != "Retained public product-name searches bound to the exact candidate versions; incomplete and not a CVE or backport clearance"):
            raise ValueError("Media security evidence overstates its scope")
        request_path = _bound_file(root, security["request_manifest"])
        requests = json.loads(request_path.read_text())
        request_list = requests.get("requests")
        if (requests.get("schema") != 1 or requests.get("passed") is not True
                or requests.get("scope") != "Public product-name candidate search for not-yet-packaged desktop additions; no installed-version or Fedora-backport assessment"
                or requests.get("private_source_uploaded") is not False
                or requests.get("alerts_dismissed") is not False
                or not isinstance(request_list, list)
                or len({row.get("query") for row in request_list if isinstance(row, dict)}) != len(request_list)):
            raise ValueError("Retained CVE request manifest overstates or obscures its scope")
        request_rows = {row["query"]: row for row in request_list}
        request_urls = {
            "MPlayer": "https://cve.bz/api/public/cves?q=MPlayer&limit=100",
            "mpv": "https://cve.bz/api/public/cves?q=mpv&limit=100",
        }
        packages = security.get("packages")
        if not isinstance(packages, list) or [row.get("name") for row in packages] != ["mplayer", "mpv"]:
            raise ValueError("Expected exact MPlayer and mpv evidence bindings")
        roots_by_name = {row["name"]: row for row in roots}
        expected_queries = {"mplayer": "MPlayer", "mpv": "mpv"}
        for row in packages:
            root_row = roots_by_name[row["name"]]
            if (set(row) != {"name", "version", "release", "source_rpm", "query", "path", "bytes",
                             "sha256", "package_version_assessed"}
                    or row["package_version_assessed"] is not False
                    or (row["version"], row["release"], row["source_rpm"]) !=
                       (root_row["version"], root_row["release"], root_row["source_rpm"])
                    or row["query"] != expected_queries[row["name"]]):
                raise ValueError("CVE search is not bound to the exact package release")
            response_path = _bound_file(root, row)
            request = request_rows.get(row["query"], {})
            if (request.get("file") != Path(row["path"]).name or request.get("bytes") != row["bytes"]
                    or request.get("sha256") != row["sha256"]
                    or request.get("url") != request_urls[row["query"]]
                    or request.get("method") != "GET" or request.get("status") != 200
                    or request.get("content_type") != "application/json"):
                raise ValueError("Retained CVE request manifest differs from bound response")
            response = json.loads(response_path.read_text())
            if (not isinstance(response, dict)
                    or set(response) != {"entries", "next", "importing", "attribution"}
                    or not isinstance(response["entries"], list)
                    or not isinstance(response["next"], str)
                    or not isinstance(response["importing"], list)
                    or not isinstance(response["attribution"], list)
                    or not response["attribution"]
                    or any(not isinstance(value, str) for value in response["attribution"])):
                raise ValueError("Retained CVE response is not the expected public search JSON")

        source_inputs = lock["source_inputs"]
        expected_sources = [(roots[0]["source_rpm"], FUSION), (roots[2]["source_rpm"], FEDORA)]
        if [(row.get("source_rpm"), row.get("expected_key_fingerprint")) for row in source_inputs] != expected_sources:
            raise ValueError("Source input slots differ from selected binary headers")
        pending_sources = True
        for row in source_inputs:
            if row.get("status") == "missing-authenticated-source-rpm":
                if (set(row) != {"source_rpm", "expected_key_fingerprint", "status", "filename", "bytes",
                                 "sha256", "signature_verified"}
                        or any(row[name] is not None for name in ("filename", "bytes", "sha256"))
                        or row["signature_verified"] is not False):
                    raise ValueError("Missing source slot contains fabricated authentication metadata")
            else:
                pending_sources = False
        closure = lock["closure"]
        if closure.get("complete") is False:
            if (closure != {"complete": False, "packages": [], "artifact": None,
                            "reason": "The retained aggregate candidate artifact does not prove the exact additive MPlayer and mpv dependency closure"}
                    or not pending_sources or lock.get("status") !=
                       "blocked-missing-media-closure-and-authenticated-sources"
                    or lock.get("install_ready") is not False or lock.get("image_source_commit") is not None):
                raise ValueError("Pending media state is not exactly closed")
            ready = False
        else:
            rows = closure.get("packages")
            if (closure.get("complete") is not True or not isinstance(rows, list) or not 3 <= len(rows) <= 128
                    or closure.get("reason") is not None):
                raise ValueError("Incomplete media package closure")
            for row in rows:
                _require_binary_row(row)
            if (len({row["filename"] for row in rows}) != len(rows)
                    or len({(row["name"], row["arch"]) for row in rows}) != len(rows)
                    or any(row not in rows for row in roots)):
                raise ValueError("Media closure duplicates or omits frozen roots")
            _require_artifact(closure.get("artifact"), lock["resolution_base"])
            sources = []
            for slot in source_inputs:
                if slot.get("status") != "authenticated" or set(slot) != {
                        "source_rpm", "expected_key_fingerprint", "status", "name", "epoch", "version",
                        "release", "arch", "nevra", "filename", "bytes", "sha256", "signature_verified",
                        "key_fingerprint"}:
                    raise ValueError("Authenticated source input is incomplete")
                source = {name: slot[name] for name in ("name", "epoch", "version", "release", "arch",
                                                               "nevra", "filename", "bytes", "sha256",
                                                               "signature_verified", "key_fingerprint")}
                if source["filename"] != slot["source_rpm"] or source["key_fingerprint"] != slot["expected_key_fingerprint"]:
                    raise ValueError("Authenticated source slot changed identity")
                sources.append(source)
            require_source_release_match(roots, sources)
            if sum(row["bytes"] for row in rows + sources) > MAX_MEDIA_RPM_PAYLOAD_BYTES:
                raise ValueError("Media package payload exceeds its retained artifact contract")
            image_source_commit = lock.get("image_source_commit")
            if (lock.get("status") != "ready-for-offline-image-install" or lock.get("install_ready") is not True
                    or (image_source_commit is not None
                        and not COMMIT.fullmatch(image_source_commit))):
                raise ValueError("Complete package inputs were not explicitly selected")
            ready = True
        if lock.get("playback_qualified") != {"generic": False, "nvidia": False}:
            raise ValueError("Playback cannot be pre-qualified by the package lock")
        if require_ready and not ready:
            raise ValueError("Media install is closed until its dedicated closure and source RPMs are authenticated")
        return ready
    except (KeyError, TypeError, AttributeError, json.JSONDecodeError) as error:
        raise ValueError("Malformed media package lock") from error


def offline_install_command(paths, output):
    """Build the only allowed local transaction after independent RPM verification."""
    paths = [Path(path) for path in paths]
    if (not paths or len({str(path) for path in paths}) != len(paths)
            or any(not path.is_absolute() or path.suffix != ".rpm" or ".." in path.parts for path in paths)):
        raise ValueError("Offline media transaction needs unique absolute RPM paths")
    # An exact empty repository directory is the fail-closed repository set.
    # dnf5 rejects a wildcard disable selector when that directory has no
    # repositories, so do not add a selector that can only make the offline
    # transaction fail before checking the local closure.
    return ["dnf5", "--assumeyes", "--disable-plugin=*",
            "--setopt=reposdir=" + str(output / "empty-repos"),
            "--setopt=cachedir=" + str(output / "dnf-cache"),
            "--setopt=localpkg_gpgcheck=False", "--setopt=install_weak_deps=False",
            "--setopt=tsflags=nodocs", "install", "--", *[str(path) for path in paths]]
