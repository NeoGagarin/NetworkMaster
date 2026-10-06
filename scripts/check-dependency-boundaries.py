"""Reject every transitive nm-ai -> nm-creds dependency path, including wrappers."""

import json
import subprocess
import sys

metadata = json.loads(
    subprocess.check_output(["cargo", "metadata", "--locked", "--format-version=1"])
)
packages = {package["id"]: package["name"] for package in metadata["packages"]}
nodes = {node["id"]: node["dependencies"] for node in metadata["resolve"]["nodes"]}
start = next(key for key, name in packages.items() if name == "nm-ai")
stack = [(start, ["nm-ai"])]
seen = set()
while stack:
    node, path = stack.pop()
    if node in seen:
        continue
    seen.add(node)
    if packages[node] == "nm-creds":
        sys.exit("Forbidden credential dependency: " + " -> ".join(path))
    stack.extend((dep, [*path, packages[dep]]) for dep in nodes[node])
print("AI credential dependency boundary passed.")
