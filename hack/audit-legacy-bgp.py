#!/usr/bin/env python3
"""Compare old network-group BGP objects with Galactic objects in one cell.

Read-only. An old-only object needs an operator to check its workload and
routing state before the old CRD can be retired.
"""

import argparse
import json
import subprocess
import sys

KINDS = ("bgpadvertisements", "bgpvrfinstances")
OLD_GROUP = "network.datumapis.com"
NEW_GROUP = "galactic.datumapis.com"


def resources(context, kind, group):
    command = ["kubectl", "--context", context, "get", f"{kind}.{group}", "-A", "-o", "json"]
    result = subprocess.run(command, check=True, capture_output=True, text=True)
    return {
        (item["metadata"]["namespace"], item["metadata"]["name"]): item
        for item in json.loads(result.stdout)["items"]
    }


def ready(item):
    return any(
        condition.get("type") == "Ready" and condition.get("status") == "True"
        for condition in item.get("status", {}).get("conditions", [])
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--context", required=True, help="Kubernetes cell context")
    args = parser.parse_args()

    blockers = 0
    for kind in KINDS:
        old = resources(args.context, kind, OLD_GROUP)
        new = resources(args.context, kind, NEW_GROUP)
        old_only = sorted(old.keys() - new.keys())
        matched = sorted(old.keys() & new.keys())
        spec_mismatch = [key for key in matched if old[key]["spec"] != new[key]["spec"]]
        not_ready = [key for key in matched if not ready(new[key])]
        blockers += len(old_only) + len(set(spec_mismatch) | set(not_ready))
        print(
            f"{kind}: old={len(old)} matching_new={len(matched)} old_only={len(old_only)} "
            f"spec_mismatch={len(spec_mismatch)} new_not_ready={len(not_ready)}"
        )
        for namespace, name in old_only:
            item = old[(namespace, name)]
            print(f"  {namespace}/{name} created={item['metadata']['creationTimestamp']}")
        for namespace, name in sorted(set(spec_mismatch) | set(not_ready)):
            reasons = []
            if (namespace, name) in spec_mismatch:
                reasons.append("spec mismatch")
            if (namespace, name) in not_ready:
                reasons.append("new object not Ready")
            print(f"  {namespace}/{name}: {', '.join(reasons)}")

    if blockers:
        print("Resolve old-only, divergent, and unready objects before retiring the old API.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (subprocess.CalledProcessError, KeyError, json.JSONDecodeError) as error:
        print(f"audit failed: {error}", file=sys.stderr)
        sys.exit(2)
