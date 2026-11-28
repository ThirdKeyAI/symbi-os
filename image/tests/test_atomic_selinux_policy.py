"""Static and adversarial contracts for the dedicated Atomic update domain."""
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
import unittest
from unittest.mock import patch

from image.desktop import verify as desktop_verify
from image.atomic.selinux import install as selinux_install
from image.atomic.selinux.policy import (
    BRIDGE_CONTEXT,
    CONTROLLER_CONTEXT,
    CONTROLLER_PATH,
    ENTRYPOINT_CONTEXT,
    ENTRYPOINT_PATH,
    INSTALL_TRANSITION_INVENTORY,
    INSTALL_CONTEXT,
    MANIFEST_PATH,
    POLICY_NAME,
    validate_policy_sources,
    validate_sesearch_evidence,
)
from image.atomic.update_boot import firmware_arguments
from image.atomic.update_guest import controller_observation
from image.recipe import render


ROOT = Path(__file__).resolve().parents[2]


class AtomicSelinuxPolicyTests(unittest.TestCase):
    def test_policy_source_is_minimal_and_has_no_generic_transition(self):
        te = (ROOT / "image/atomic/selinux/symbi_atomic_update.te").read_bytes()
        fc = (ROOT / "image/atomic/selinux/symbi_atomic_update.fc").read_bytes()
        validate_policy_sources(te, fc)
        text = te.decode("ascii")
        self.assertIn("init_daemon_domain(symbi_atomic_update_t, symbi_atomic_update_exec_t)", text)
        self.assertIn("type symbi_bootc_transition_exec_t;", text)
        self.assertIn(
            "domain_entry_file(install_t, symbi_bootc_transition_exec_t)", text)
        self.assertIn("gen_require(`\n    type install_t;\n')", text)
        self.assertIn(
            "domtrans_pattern(symbi_atomic_update_t, "
            "symbi_bootc_transition_exec_t, install_t)", text)
        self.assertNotIn("install_domtrans(symbi_atomic_update_t)", text)
        self.assertNotIn("unconfined_domain", text)
        self.assertNotIn("allow unconfined_service_t install_t:process transition", text)
        fc_text = fc.decode("ascii")
        self.assertIn(
            "/usr/libexec/symbi-bootc-transition -- "
            "gen_context(system_u:object_r:symbi_bootc_transition_exec_t,s0)",
            fc_text)
        self.assertNotIn("/usr/bin/bootc", fc_text)
        self.assertNotIn("/usr/bin/ostree", fc_text)
        for forbidden in (
            "noatsecure", "setexec", "setcurrent", "dyntransition",
            "siginh", "rlimitinh", "load_policy", "setenforce",
        ):
            self.assertNotIn(forbidden, text)
        for mutation in (
            te.replace(b"symbi_bootc_transition_exec_t, install_t)",
                       b"install_exec_t, install_t)"),
            te + b"allow unconfined_service_t install_t:process transition;\n",
            te + b"unconfined_domain(symbi_atomic_update_t)\n",
        ):
            with self.subTest(mutation=hashlib.sha256(mutation).hexdigest()), \
                    self.assertRaises(ValueError):
                validate_policy_sources(mutation, fc)
        with self.assertRaises(ValueError):
            validate_policy_sources(te, fc.replace(
                b"/usr/libexec/symbi-atomic-update", b"/usr/libexec/copied-update"))

    def test_expanded_policy_evidence_rejects_broad_or_forbidden_authority(self):
        evidence = {
            "schema": 2,
            "policy": POLICY_NAME,
            "install_transition_inventory": copy.deepcopy(
                INSTALL_TRANSITION_INVENTORY),
            "required": {
                "init_entrypoint": True,
                "init_transition": True,
                "bridge_entrypoint": True,
                "bridge_transition": True,
                "bridge_type_transition": True,
                "install_sigchld": True,
            },
            "forbidden": {
                "shared_install_type_transition": False,
                "generic_install_transition": False,
                "controller_forbidden_process_permissions": False,
                "controller_policy_load": False,
                "controller_enforcing_change": False,
            },
        }
        self.assertEqual(validate_sesearch_evidence(evidence), evidence)
        for section, field in (
            ("required", "bridge_type_transition"),
            ("forbidden", "shared_install_type_transition"),
            ("forbidden", "generic_install_transition"),
            ("forbidden", "controller_forbidden_process_permissions"),
            ("forbidden", "controller_policy_load"),
            ("forbidden", "controller_enforcing_change"),
        ):
            changed = copy.deepcopy(evidence)
            changed[section][field] = not changed[section][field]
            with self.subTest(section=section, field=field), self.assertRaises(ValueError):
                validate_sesearch_evidence(changed)
        changed = copy.deepcopy(evidence)
        changed["required"]["extra"] = True
        with self.assertRaises(ValueError):
            validate_sesearch_evidence(changed)
        for mutation in (
                None,
                [],
                {**INSTALL_TRANSITION_INVENTORY, "extra": False},
                {**INSTALL_TRANSITION_INVENTORY, "schema": True},
                {**INSTALL_TRANSITION_INVENTORY, "rules": []},
                {**INSTALL_TRANSITION_INVENTORY, "rules": [
                    *INSTALL_TRANSITION_INVENTORY["rules"],
                    "type_transition symbi_atomic_update_t "
                    "other_exec_t:process install_t;",
                ]},
        ):
            changed = copy.deepcopy(evidence)
            if mutation is None:
                del changed["install_transition_inventory"]
            else:
                changed["install_transition_inventory"] = mutation
            with self.subTest(inventory=mutation), self.assertRaises(ValueError):
                validate_sesearch_evidence(changed)

    def test_expanded_policy_queries_only_the_unique_bridge_transition(self):
        calls = []

        def evidence_query(_policy, mode, source, target, klass,
                           permission=None):
            calls.append((mode, source, target, klass, permission))
            rules = {
                ("-A", "symbi_atomic_update_t",
                 "symbi_atomic_update_exec_t", "file", "entrypoint"): [
                    "allow symbi_atomic_update_t "
                    "symbi_atomic_update_exec_t:file entrypoint;"],
                ("-A", "init_t", "symbi_atomic_update_t", "process",
                 "transition"): [
                    "allow init_t symbi_atomic_update_t:process transition;"],
                ("-A", "install_t", "symbi_bootc_transition_exec_t",
                 "file", "entrypoint"): [
                    "allow install_t symbi_bootc_transition_exec_t:file "
                    "{ entrypoint execute getattr map open read };"],
                ("-A", "symbi_atomic_update_t", "install_t", "process",
                 "transition"): [
                    "allow symbi_atomic_update_t install_t:process transition;"],
                ("-T", "symbi_atomic_update_t", None, "process", None): [
                    "type_transition symbi_atomic_update_t "
                    "symbi_bootc_transition_exec_t:process install_t;"],
                ("-A", "install_t", "symbi_atomic_update_t", "process",
                 "sigchld"): [
                    "allow install_t symbi_atomic_update_t:process sigchld;"],
            }
            return rules.get(calls[-1], [])

        with patch.object(selinux_install, "query", side_effect=evidence_query):
            evidence = selinux_install.expanded_evidence(Path("/fixed/policy"))
        self.assertTrue(all(evidence["required"].values()))
        self.assertFalse(any(evidence["forbidden"].values()))
        self.assertEqual(evidence["install_transition_inventory"],
                         INSTALL_TRANSITION_INVENTORY)
        self.assertIn(
            ("-T", "symbi_atomic_update_t", None, "process", None), calls)
        self.assertEqual(
            [call for call in calls if call[0] == "-T"],
            [("-T", "symbi_atomic_update_t", None, "process", None)],
        )
        self.assertNotIn(
            ("-T", "symbi_atomic_update_t",
             "symbi_bootc_transition_exec_t", "process", None), calls)
        self.assertNotIn(
            ("-T", "symbi_atomic_update_t", "install_exec_t", "process", None),
            calls)

        def extra_transition(executable):
            def query_with_extra(_policy, mode, source, target, klass,
                                 permission=None):
                if (mode, source, target, klass, permission) == (
                        "-T", "symbi_atomic_update_t", None, "process", None):
                    return [
                        "type_transition symbi_atomic_update_t "
                        "symbi_bootc_transition_exec_t:process install_t;",
                        "type_transition symbi_atomic_update_t "
                        f"{executable}:process install_t;",
                    ]
                return evidence_query(_policy, mode, source, target, klass,
                                      permission)
            return query_with_extra

        for executable in ("install_exec_t", "other_exec_t"):
            with self.subTest(executable=executable), \
                    patch.object(selinux_install, "query",
                                 side_effect=extra_transition(executable)), \
                    self.assertRaises(ValueError):
                selinux_install.expanded_evidence(Path("/fixed/policy"))

        def malformed_transition(_policy, mode, source, target, klass,
                                 permission=None):
            if (mode, source, target, klass, permission) == (
                    "-T", "symbi_atomic_update_t", None, "process", None):
                return ["type_transition symbi_atomic_update_t "
                        "other_exec_t:process install_t [unexpected];"]
            return evidence_query(_policy, mode, source, target, klass,
                                  permission)

        with patch.object(selinux_install, "query", side_effect=malformed_transition), \
                self.assertRaises(ValueError):
            selinux_install.expanded_evidence(Path("/fixed/policy"))

    def test_compiled_launcher_has_only_fixed_paths_and_arguments(self):
        source = (ROOT / "image/atomic/selinux/symbi-atomic-update.c").read_text()
        for value in (str(ENTRYPOINT_PATH), str(CONTROLLER_PATH), "/usr/bin/python3",
                      "--probe", "--advance",
                      "/run/credentials/o.service/symbi-update-expected.json",
                      "/run/credentials/o.service/symbi-update-policy.json"):
            self.assertIn(value, source)
        for forbidden in ("system(", "popen(", "execvp(", "execlp(", "/bin/sh", "PATH"):
            self.assertNotIn(forbidden, source)
        self.assertIn(
            'argc == 4 && strcmp(argv[1], "--advance") == 0', source)
        self.assertIn(
            'strcmp(argv[2], expected) == 0 && strcmp(argv[3], policy) == 0',
            source)
        self.assertIn(
            '(char *)controller, "--advance",\n        (char *)expected, '
            '(char *)policy, NULL', source)

    def test_compiled_bridge_dispatches_only_fixed_operations_and_closes_receipt(self):
        source = (ROOT / "image/atomic/selinux/symbi-bootc-transition.c").read_text()
        for value in (str(INSTALL_CONTEXT), "/usr/bin/bootc", "--receipt-fd",
                      'strcmp(operation, "probe")',
                      'strcmp(operation, "negative")',
                      'strcmp(operation, "positive")',
                      'strcmp(operation, "rollback")',
                      "F_SETFD, FD_CLOEXEC"):
            self.assertIn(value, source)
        self.assertLess(source.index("write_all(receipt_fd"),
                        source.index("F_SETFD, FD_CLOEXEC"))
        self.assertLess(source.index("F_SETFD, FD_CLOEXEC"),
                        source.index("execve(bootc"))
        for forbidden in ("system(", "popen(", "execvp(", "execlp(", "/bin/sh"):
            self.assertNotIn(forbidden, source)

    def test_controller_observation_binds_both_image_owned_files_and_context(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            entrypoint = root / "symbi-atomic-update"
            bridge = root / "symbi-bootc-transition"
            controller = root / "controller.py"
            entrypoint.write_bytes(b"ELF fixture")
            bridge.write_bytes(b"bridge ELF fixture")
            controller.write_bytes(b"print('fixture')\n")
            entrypoint.chmod(0o755)
            bridge.chmod(0o755)
            controller.chmod(0o444)
            manifest_path = root / "manifest.json"
            manifest = {
                "schema": 1,
                "policy": POLICY_NAME,
                "entrypoint": {
                    "path": str(entrypoint),
                    "sha256": hashlib.sha256(entrypoint.read_bytes()).hexdigest(),
                    "uid": os.getuid(), "gid": os.getgid(), "mode": "0755",
                    "selinux_label": ENTRYPOINT_CONTEXT,
                },
                "bridge": {
                    "path": str(bridge),
                    "sha256": hashlib.sha256(bridge.read_bytes()).hexdigest(),
                    "uid": os.getuid(), "gid": os.getgid(), "mode": "0755",
                    "selinux_label": BRIDGE_CONTEXT,
                },
                "controller": {
                    "path": str(controller),
                    "sha256": hashlib.sha256(controller.read_bytes()).hexdigest(),
                    "uid": os.getuid(), "gid": os.getgid(), "mode": "0444",
                },
                "controller_context": CONTROLLER_CONTEXT,
                "install_context": INSTALL_CONTEXT,
                "policy_sources": {
                    "te_sha256": "1" * 64,
                    "fc_sha256": "2" * 64,
                    "launcher_sha256": "3" * 64,
                    "bridge_sha256": "4" * 64,
                },
                "expanded_policy": {
                    "schema": 2, "policy": POLICY_NAME,
                    "install_transition_inventory": copy.deepcopy(
                        INSTALL_TRANSITION_INVENTORY),
                    "required": {
                        "init_entrypoint": True,
                        "init_transition": True,
                        "bridge_entrypoint": True,
                        "bridge_transition": True,
                        "bridge_type_transition": True,
                        "install_sigchld": True,
                    },
                    "forbidden": {
                        "shared_install_type_transition": False,
                        "generic_install_transition": False,
                        "controller_forbidden_process_permissions": False,
                        "controller_policy_load": False,
                        "controller_enforcing_change": False,
                    },
                },
            }
            manifest_path.write_text(json.dumps(manifest, sort_keys=True) + "\n")
            manifest_path.chmod(0o444)
            label = (ENTRYPOINT_CONTEXT + "\0").encode()
            bridge_label = (BRIDGE_CONTEXT + "\0").encode()
            current = (CONTROLLER_CONTEXT + "\n").encode()
            def labels(descriptor, _name):
                path = Path(os.readlink(f"/proc/self/fd/{descriptor}"))
                return bridge_label if path == bridge else label
            observed = controller_observation(
                entrypoint_path=entrypoint, bridge_path=bridge,
                controller_path=controller,
                manifest_path=manifest_path, argv0=str(controller),
                expected_uid=os.getuid(), expected_gid=os.getgid(),
                label_reader=labels,
                context_reader=lambda: current,
            )
            self.assertEqual(observed["entrypoint_sha256"],
                             manifest["entrypoint"]["sha256"])
            self.assertEqual(observed["controller_sha256"],
                             manifest["controller"]["sha256"])
            self.assertEqual(observed["bridge_sha256"],
                             manifest["bridge"]["sha256"])
            self.assertEqual(observed["controller_context"], CONTROLLER_CONTEXT)
            manifest_mutations = (
                ("missing-inventory", lambda item: item["expanded_policy"].pop(
                    "install_transition_inventory")),
                ("boolean-schema", lambda item: item["expanded_policy"]
                    ["install_transition_inventory"].__setitem__("schema", True)),
                ("extra-inventory-field", lambda item: item["expanded_policy"]
                    ["install_transition_inventory"].__setitem__("extra", False)),
                ("other-executable", lambda item: item["expanded_policy"]
                    ["install_transition_inventory"]["rules"].append(
                        "type_transition symbi_atomic_update_t "
                        "other_exec_t:process install_t;")),
                ("shared-executable", lambda item: item["expanded_policy"]
                    ["install_transition_inventory"]["rules"].append(
                        "type_transition symbi_atomic_update_t "
                        "install_exec_t:process install_t;")),
            )
            for name, mutate in manifest_mutations:
                changed = copy.deepcopy(manifest)
                mutate(changed)
                manifest_path.chmod(0o644)
                manifest_path.write_text(json.dumps(changed, sort_keys=True) + "\n")
                manifest_path.chmod(0o444)
                with self.subTest(manifest=name), self.assertRaises(ValueError):
                    controller_observation(
                        entrypoint_path=entrypoint, bridge_path=bridge,
                        controller_path=controller,
                        manifest_path=manifest_path, argv0=str(controller),
                        expected_uid=os.getuid(), expected_gid=os.getgid(),
                        label_reader=labels,
                        context_reader=lambda: current,
                    )
            manifest_path.chmod(0o644)
            manifest_path.write_text(json.dumps(manifest, sort_keys=True) + "\n")
            manifest_path.chmod(0o444)
            for name, kwargs in (
                ("argv", {"argv0": str(root / "copy.py")}),
                ("wrong-context", {"context_reader": lambda: b"system_u:system_r:unconfined_service_t:s0\n"}),
                ("wrong-label", {"label_reader": lambda _fd, _name: b"system_u:object_r:bin_t:s0\0"}),
            ):
                arguments = {
                    "entrypoint_path": entrypoint, "bridge_path": bridge,
                    "controller_path": controller,
                    "manifest_path": manifest_path, "argv0": str(controller),
                    "expected_uid": os.getuid(), "expected_gid": os.getgid(),
                    "label_reader": labels,
                    "context_reader": lambda: current,
                }
                arguments.update(kwargs)
                with self.subTest(name=name), self.assertRaises((OSError, ValueError)):
                    controller_observation(**arguments)
            copied = root / "copied-controller.py"
            copied.write_bytes(controller.read_bytes())
            copied.chmod(0o444)
            with self.assertRaises((OSError, ValueError)):
                controller_observation(
                    entrypoint_path=entrypoint, bridge_path=bridge,
                    controller_path=copied,
                    manifest_path=manifest_path, argv0=str(copied),
                    expected_uid=os.getuid(), expected_gid=os.getgid(),
                    label_reader=labels,
                    context_reader=lambda: current)
            linked = root / "linked-entrypoint"
            linked.symlink_to(entrypoint)
            with self.assertRaises((OSError, ValueError)):
                controller_observation(
                    entrypoint_path=linked, bridge_path=bridge,
                    controller_path=controller,
                    manifest_path=manifest_path, argv0=str(controller),
                    expected_uid=os.getuid(), expected_gid=os.getgid(),
                    label_reader=labels,
                    context_reader=lambda: current)

    def test_installed_image_validator_binds_exact_transition_inventory(self):
        digests = {
            "entrypoint": "a" * 64,
            "bridge": "b" * 64,
            "controller": "c" * 64,
            "te_sha256": "d" * 64,
            "fc_sha256": "e" * 64,
            "launcher_sha256": "f" * 64,
            "bridge_sha256": "9" * 64,
        }
        source_paths = {
            "image/atomic/update_guest.py": digests["controller"],
            "image/atomic/selinux/symbi_atomic_update.te": digests["te_sha256"],
            "image/atomic/selinux/symbi_atomic_update.fc": digests["fc_sha256"],
            "image/atomic/selinux/symbi-atomic-update.c": digests["launcher_sha256"],
            "image/atomic/selinux/symbi-bootc-transition.c": digests["bridge_sha256"],
        }
        expansion = {
            "schema": 2, "policy": POLICY_NAME,
            "install_transition_inventory": copy.deepcopy(
                INSTALL_TRANSITION_INVENTORY),
            "required": {
                "init_entrypoint": True, "init_transition": True,
                "bridge_entrypoint": True, "bridge_transition": True,
                "bridge_type_transition": True, "install_sigchld": True,
            },
            "forbidden": {
                "shared_install_type_transition": False,
                "generic_install_transition": False,
                "controller_forbidden_process_permissions": False,
                "controller_policy_load": False,
                "controller_enforcing_change": False,
            },
        }
        manifest = {
            "schema": 1, "policy": POLICY_NAME,
            "entrypoint": {
                "path": str(desktop_verify.CONTROLLER_ENTRYPOINT),
                "sha256": digests["entrypoint"], "uid": 0, "gid": 0,
                "mode": "0755", "selinux_label": ENTRYPOINT_CONTEXT,
            },
            "bridge": {
                "path": str(desktop_verify.CONTROLLER_BRIDGE),
                "sha256": digests["bridge"], "uid": 0, "gid": 0,
                "mode": "0755", "selinux_label": BRIDGE_CONTEXT,
            },
            "controller": {
                "path": str(desktop_verify.CONTROLLER),
                "sha256": digests["controller"], "uid": 0, "gid": 0,
                "mode": "0444",
            },
            "controller_context": CONTROLLER_CONTEXT,
            "install_context": INSTALL_CONTEXT,
            "policy_sources": {
                key: digests[key] for key in (
                    "te_sha256", "fc_sha256", "launcher_sha256",
                    "bridge_sha256")
            },
            "expanded_policy": expansion,
        }
        source = {"context": {
            path: {"sha256": value} for path, value in source_paths.items()
        }}

        def validate(candidate):
            values = {
                desktop_verify.CONTROLLER_ENTRYPOINT: {
                    "sha256": digests["entrypoint"]},
                desktop_verify.CONTROLLER_BRIDGE: {"sha256": digests["bridge"]},
                desktop_verify.CONTROLLER: {"sha256": digests["controller"]},
                desktop_verify.CONTROLLER_MANIFEST: {
                    "sha256": "8" * 64,
                    "raw": (json.dumps(candidate) + "\n").encode(),
                },
            }
            with patch.object(desktop_verify, "fixed_file",
                              side_effect=lambda path, _mode, _maximum: values[path]):
                return desktop_verify.verify_atomic_update_controller(source)

        self.assertEqual(validate(manifest)["expanded_policy"], expansion)
        for name, mutate in (
                ("boolean-schema", lambda item: item["expanded_policy"]
                    ["install_transition_inventory"].__setitem__("schema", True)),
                ("extra-field", lambda item: item["expanded_policy"]
                    ["install_transition_inventory"].__setitem__("extra", False)),
                ("other-executable", lambda item: item["expanded_policy"]
                    ["install_transition_inventory"]["rules"].append(
                        "type_transition symbi_atomic_update_t "
                        "other_exec_t:process install_t;")),
                ("shared-executable", lambda item: item["expanded_policy"]
                    ["install_transition_inventory"]["rules"].append(
                        "type_transition symbi_atomic_update_t "
                        "install_exec_t:process install_t;"))):
            changed = copy.deepcopy(manifest)
            mutate(changed)
            with self.subTest(name=name), self.assertRaises(ValueError):
                validate(changed)

    def test_units_execute_only_the_immutable_launcher(self):
        probe = (ROOT / "image/atomic/update-b.service").read_text()
        update = (ROOT / "image/atomic/update-o.service").read_text()
        self.assertIn("ExecStart=/usr/libexec/symbi-atomic-update --probe", probe)
        self.assertIn("ExecStart=/usr/libexec/symbi-atomic-update --advance %d/symbi-update-expected.json %d/symbi-update-policy.json", update)
        combined = probe + update
        self.assertNotIn("runcon", combined)
        self.assertNotIn("SELinuxContext=", combined)
        self.assertNotIn("symbi-update.py", combined)
        arguments = firmware_arguments()
        self.assertNotIn("opt/io.systemd.credentials/symbi-update.py", arguments)

    def test_recipe_builds_launcher_and_installs_policy_before_hardening(self):
        pins = json.loads((ROOT / "image/base-images.json").read_text())
        recipe = render(pins, "generic", ROOT)
        snippets = recipe["modules"][0]["snippets"]
        self.assertIn(
            "COPY image/atomic/update_guest.py /usr/libexec/symbi-atomic-update-controller.py",
            snippets)
        self.assertIn(
            "COPY image/atomic/selinux/ /tmp/symbi-atomic-update-policy/",
            snippets)
        self.assertLess(
            snippets.index("COPY image/atomic/selinux/ /tmp/symbi-atomic-update-policy/"),
            snippets.index("RUN bash /tmp/symbi-harden-image.sh && rm /tmp/symbi-harden-image.sh"))

    def test_desktop_workflow_watches_atomic_controller_and_policy_on_both_events(self):
        workflow = (ROOT / ".github/workflows/desktop-image.yml").read_text()
        for event in ("push", "pull_request"):
            match = re.search(
                rf"(?ms)^  {event}:\n(?P<body>.*?)(?=^  [a-z_]+:)", workflow)
            self.assertIsNotNone(match, event)
            paths = re.search(
                r"(?ms)^    paths:\n(?P<items>(?:^      - .*\n)+)",
                match.group("body"))
            self.assertIsNotNone(paths, event)
            watched = {
                line.strip()[2:].strip().strip('"')
                for line in paths.group("items").splitlines()
            }
            self.assertIn("image/atomic/update_guest.py", watched, event)
            self.assertIn("image/atomic/selinux/**", watched, event)


if __name__ == "__main__":
    unittest.main()
