#!/usr/bin/env python3
"""Generate `fixtures/large_manifest.json` — a 100-tool MCP manifest
with intentionally bloated, redundant descriptions so the optimizer
benchmark has meat to chew on. Deterministic (no randomness)."""

import json
import pathlib

VERBS = [
    "list", "get", "create", "update", "delete", "search", "find", "fetch",
    "read", "summarize", "compute", "validate", "annotate", "render",
    "compose", "publish", "archive", "restore", "deduplicate", "schedule",
]
RESOURCES = [
    "invoice", "user", "team", "project", "task", "comment", "label", "release",
    "tag", "metric",
]


def bloated(verb: str, resource: str) -> str:
    return (
        f"Please note that this tool is a tool that allows you to {verb} a {resource}. "
        f"Be sure to use this tool when you need to {verb} a {resource} in the system. "
        f"This {verb} operation on a {resource} returns the resulting {resource}. "
        f"Use this tool when you want to {verb} a {resource}, simply just by passing the id. "
        f"Note that this tool will {verb} the {resource} appropriately, properly, and correctly. "
        f"It handles various {resource} things and returns relevant stuff."
    )


def main() -> None:
    tools = []
    i = 0
    for verb in VERBS:
        for resource in RESOURCES:
            tools.append({
                "name": f"{verb}_{resource}",
                "description": bloated(verb, resource),
                "inputSchema": {
                    "type": "object",
                    "properties": {"id": {"type": "string"}},
                    "required": ["id"],
                },
            })
            i += 1
            if i >= 100:
                break
        if i >= 100:
            break

    manifest = {
        "serverInfo": {"name": "bloated-server", "version": "1.0.0"},
        "tools": tools,
    }
    out = pathlib.Path(__file__).resolve().parent.parent / "fixtures" / "large_manifest.json"
    out.write_text(json.dumps(manifest, indent=2) + "\n")
    print(f"wrote {out} ({len(tools)} tools)")


if __name__ == "__main__":
    main()
