"""Map artifact evidence to relevant skills and available tools without executing targets."""
from __future__ import annotations
from .registry import list_tools

ROUTES: dict[str, tuple[list[str], list[str]]] = {
    "pe": (["native", "windows"], ["rei-native-binaries", "rei-evidence-ledger", "rei-reconstruction-parity"]),
    "elf": (["native", "linux"], ["rei-native-binaries", "rei-evidence-ledger", "rei-reconstruction-parity"]),
    "mach-o-fat": (["native", "apple"], ["rei-native-binaries", "rei-evidence-ledger"]),
    "java-class": (["java"], ["rei-wasm-and-managed", "rei-evidence-ledger"]),
    "mach-o": (["native", "apple"], ["rei-native-binaries", "rei-evidence-ledger"]),
    "apk": (["android"], ["rei-android-apks", "rei-evidence-ledger", "rei-reconstruction-parity"]),
    "android-app-bundle": (["android"], ["rei-android-apks", "rei-evidence-ledger"]),
    "ipa": (["apple"], ["rei-mobile-runtime", "rei-evidence-ledger"]),
    "dex": (["android"], ["rei-android-apks", "rei-evidence-ledger"]),
    "wasm": (["wasm"], ["rei-wasm-and-managed", "rei-evidence-ledger"]),
    "sqlite": (["data"], ["rei-evidence-ledger"]),
    "pcap": (["network"], ["rei-web-and-protocols", "rei-evidence-ledger"]),
    "pcapng": (["network"], ["rei-web-and-protocols", "rei-evidence-ledger"]),
    "har-json-unconfirmed": (["web"], ["rei-web-and-protocols", "rei-evidence-ledger"]),
    "asar-unconfirmed": (["electron"], ["rei-electron-and-js", "rei-evidence-ledger"]),
    "jar": (["java"], ["rei-wasm-and-managed", "rei-evidence-ledger"]),
    "directory": (["source", "javascript"], ["rei-electron-and-js", "rei-evidence-ledger"]),
    "zip": (["formats"], ["rei-firmware-and-iot", "rei-evidence-ledger"]),
    "gzip": (["firmware"], ["rei-firmware-and-iot", "rei-evidence-ledger"]),
    "xz": (["firmware"], ["rei-firmware-and-iot", "rei-evidence-ledger"]),
}

BASE_STEPS = [
    "Establish permission, investigation question, immutable input hash and resource limits",
    "Inventory metadata and entry points; distinguish observed facts from hypotheses",
    "Choose the smallest available read-only technique to trace one feature",
    "Record evidence offsets/paths, contradictions and tool versions in the case ledger",
    "Construct a behavioral specification, then implement outside the original",
    "Compare outputs on an authorized reproducible test corpus; report gaps and rollback",
]


def build_plan(inspection: dict) -> dict:
    kind = inspection["kind"]
    tags, skills = ROUTES.get(kind, (["all"], ["rei-rea-orchestrator", "rei-evidence-ledger"]))
    found = list_tools()
    matching = [x for x in found if set(tags).intersection(x["tags"]) or "all" in x["tags"]]
    matching.sort(key=lambda x: (not x["installed"], x["integration"] != "static-adapter", x["id"]))
    return {
        "artifact_kind": kind,
        "artifact_sha256": inspection["sha256"],
        "skill_routes": ["rei-rea-orchestrator", *[s for s in skills if s != "rei-rea-orchestrator"]],
        "tool_tags": tags,
        "tool_candidates": [{"id": x["id"], "available_on_path": x["installed"], "integration": x["integration"]} for x in matching[:24]],
        "steps": BASE_STEPS,
        "execution_policy": "No untrusted target execution or external tools run during plan/inspect. Opt in separately for vetted static adapters.",
        "limitations": ["Tool catalog is not an installation bundle", "Tool availability is PATH detection, not a capability benchmark",
                        "No behavior recovered from headers or names alone"],
    }
