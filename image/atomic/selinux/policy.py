"""Exact source and expanded-policy contracts for the Atomic update domain."""
import copy
from pathlib import Path


POLICY_NAME = "symbi_atomic_update"
ENTRYPOINT_PATH = Path("/usr/libexec/symbi-atomic-update")
BRIDGE_PATH = Path("/usr/libexec/symbi-bootc-transition")
CONTROLLER_PATH = Path("/usr/libexec/symbi-atomic-update-controller.py")
MANIFEST_PATH = Path("/usr/share/symbi-os/selinux/symbi-atomic-update.json")
CONTROLLER_CONTEXT = "system_u:system_r:symbi_atomic_update_t:s0"
ENTRYPOINT_CONTEXT = "system_u:object_r:symbi_atomic_update_exec_t:s0"
BRIDGE_CONTEXT = "system_u:object_r:symbi_bootc_transition_exec_t:s0"
INSTALL_CONTEXT = "system_u:system_r:install_t:s0"

TE_SOURCE = b"""policy_module(symbi_atomic_update, 1.0)\n\ntype symbi_atomic_update_t;\ntype symbi_atomic_update_exec_t;\ntype symbi_bootc_transition_exec_t;\nfiles_type(symbi_bootc_transition_exec_t)\n\ninit_daemon_domain(symbi_atomic_update_t, symbi_atomic_update_exec_t)\n\ngen_require(`\n    type install_t;\n')\n\ndomain_entry_file(install_t, symbi_bootc_transition_exec_t)\ndomtrans_pattern(symbi_atomic_update_t, symbi_bootc_transition_exec_t, install_t)\n"""
FC_SOURCE = (b"/usr/libexec/symbi-atomic-update -- "
             b"gen_context(system_u:object_r:symbi_atomic_update_exec_t,s0)\n"
             b"/usr/libexec/symbi-bootc-transition -- "
             b"gen_context(system_u:object_r:symbi_bootc_transition_exec_t,s0)\n")

REQUIRED_EXPANSION = {
    "init_entrypoint": True,
    "init_transition": True,
    "bridge_entrypoint": True,
    "bridge_transition": True,
    "bridge_type_transition": True,
    "install_sigchld": True,
}
FORBIDDEN_EXPANSION = {
    "shared_install_type_transition": False,
    "generic_install_transition": False,
    "controller_forbidden_process_permissions": False,
    "controller_policy_load": False,
    "controller_enforcing_change": False,
}
INSTALL_TRANSITION_INVENTORY = {
    "schema": 1,
    "source": "symbi_atomic_update_t",
    "class": "process",
    "destination": "install_t",
    "rules": [
        "type_transition symbi_atomic_update_t "
        "symbi_bootc_transition_exec_t:process install_t;",
    ],
}


def validate_policy_sources(te, fc):
    """Accept only the reviewed minimal interface use and one file context."""
    if type(te) is not bytes or type(fc) is not bytes:
        raise ValueError("SELinux policy sources must be bytes")
    if te != TE_SOURCE or fc != FC_SOURCE:
        raise ValueError("Atomic update SELinux policy source differs")
    return True


def validate_sesearch_evidence(evidence):
    """Require exact semantic results from queries against the built policy."""
    if (not isinstance(evidence, dict) or set(evidence) != {
            "schema", "policy", "install_transition_inventory",
            "required", "forbidden"}
            or type(evidence.get("schema")) is not int or evidence["schema"] != 2
            or evidence.get("policy") != POLICY_NAME
            or not isinstance(evidence.get("install_transition_inventory"), dict)
            or set(evidence["install_transition_inventory"]) != {
                "schema", "source", "class", "destination", "rules"}
            or type(evidence["install_transition_inventory"].get("schema")) is not int
            or evidence["install_transition_inventory"]["schema"] != 1
            or evidence["install_transition_inventory"] != INSTALL_TRANSITION_INVENTORY
            or evidence.get("required") != REQUIRED_EXPANSION
            or evidence.get("forbidden") != FORBIDDEN_EXPANSION):
        raise ValueError("expanded Atomic update policy evidence differs")
    return copy.deepcopy(evidence)
