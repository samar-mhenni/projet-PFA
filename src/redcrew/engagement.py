import json
from pathlib import Path


def load_engagement(path):
    if Path(path).stat().st_size > 100_000:
        raise ValueError("Engagement exceeds 100 KB; summarize evidence first")
    data = json.loads(Path(path).read_text())
    if not isinstance(data, dict):
        raise ValueError("Engagement must be a JSON object")
    if data.get("authorized") is not True:
        raise ValueError("Engagement must explicitly declare authorized: true")
    for key in ("name", "objective"):
        if not isinstance(data.get(key), str) or not data[key].strip():
            raise ValueError(f"{key} must be a nonempty string")
    targets = data.get("targets")
    if not isinstance(targets, list) or not targets or any(not isinstance(t, str) or not t.strip() for t in targets):
        raise ValueError("Provide an explicit nonempty list of authorized targets")
    evidence = data.get("evidence")
    if not isinstance(evidence, list) or not evidence:
        raise ValueError("Provide at least one evidence item")
    ids = set()
    for item in evidence:
        if not isinstance(item, dict):
            raise ValueError("Evidence items must be objects")
        if item.get("target") not in targets:
            raise ValueError("Evidence target is outside the engagement scope")
        for key in ("id", "kind", "content"):
            if not isinstance(item.get(key), str) or not item[key].strip():
                raise ValueError(f"Evidence {key} must be a nonempty string")
        if item["id"] in ids:
            raise ValueError("Evidence IDs must be unique")
        ids.add(item["id"])
    if len(json.dumps(data)) > 100_000:
        raise ValueError("Engagement exceeds 100 KB; summarize evidence first")
    return data
