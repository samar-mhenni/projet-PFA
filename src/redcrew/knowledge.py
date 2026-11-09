"""Local semantic retrieval of official MITRE ATT&CK STIX data."""
import hashlib
import json
import sys
import re
from pathlib import Path
from urllib.request import urlopen

SOURCE = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
TYPES = {"attack-pattern", "course-of-action", "intrusion-set", "malware", "tool", "x-mitre-tactic", "x-mitre-detection-strategy", "x-mitre-analytic"}


def records(bundle):
    if bundle.get("type") != "bundle" or not isinstance(bundle.get("objects"), list):
        raise ValueError("Expected a STIX bundle containing objects")
    for obj in bundle["objects"]:
        if obj.get("type") not in TYPES or obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        ref = next((r for r in obj.get("external_references", []) if r.get("source_name") == "mitre-attack" and r.get("external_id")), {})
        if not ref:
            continue
        meta = {"attack_id": ref["external_id"], "name": obj["name"], "type": obj["type"], "url": ref.get("url", ""), "modified": obj.get("modified", ""), "platforms": ", ".join(obj.get("x_mitre_platforms", []))}
        body = f'{meta["attack_id"]}: {meta["name"]}\nType: {meta["type"]}\nPlatforms: {meta["platforms"]}\nTactics: ' + ", ".join(k["phase_name"] for k in obj.get("kill_chain_phases", [])) + "\n" + obj.get("description", "")
        # Small overlapping chunks fit the local embedding model's context window.
        for i, start in enumerate(range(0, len(body), 900)):
            yield {"id": f'{obj["id"]}:{i}', "document": body[start:start + 1100], "metadata": meta}


class Knowledge:
    def __init__(self, path="data/chroma"):
        import chromadb
        from chromadb.utils.embedding_functions import DefaultEmbeddingFunction
        self.client = chromadb.PersistentClient(path=str(path))
        self.embedding = DefaultEmbeddingFunction()
        self.retrievals = []
        self.collection = self.client.get_or_create_collection("mitre_attack", embedding_function=self.embedding)

    def ingest(self, file=None):
        raw = Path(file).read_bytes() if file else urlopen(SOURCE, timeout=120).read()
        rows = list(records(json.loads(raw)))
        if not rows:
            raise ValueError("Bundle contains no supported active ATT&CK records")
        digest = hashlib.sha256(raw).hexdigest()
        # Build a new collection; publish its name only after the complete import.
        name = "attack_" + digest[:24]
        collection = self.client.get_or_create_collection(name, embedding_function=self.embedding)
        print(f"Embedding {len(rows)} ATT&CK chunks locally...", file=sys.stderr)
        for start in range(0, len(rows), 128):
            batch = rows[start:start + 128]
            collection.upsert(ids=[r["id"] for r in batch], documents=[r["document"] for r in batch], metadatas=[r["metadata"] for r in batch])
            print(f"Indexed {min(start + 128, len(rows))}/{len(rows)}", file=sys.stderr)
        self.collection.modify(metadata={"active_collection": name, "sha256": digest, "source": str(file) if file else SOURCE})
        return {"chunks": collection.count(), "sha256": digest, "source": str(file) if file else SOURCE}

    def active(self):
        name = (self.collection.metadata or {}).get("active_collection")
        return self.client.get_collection(name, embedding_function=self.embedding) if name else self.collection

    def search(self, query, limit=5):
        collection = self.active()
        if not collection.count():
            raise ValueError("Knowledge base is empty. Run redcrew ingest first.")
        limit = min(max(limit, 1), 10)
        result = collection.query(query_texts=[query], n_results=min(40, collection.count()))
        candidates = {}
        for rank, (meta, doc, distance) in enumerate(zip(result["metadatas"][0], result["documents"][0], result["distances"][0])):
            candidates.setdefault(meta['attack_id'], {**meta, 'excerpt': doc, 'distance': distance, 'retrieval_score': 1 / (60 + rank)})
        # Title/ID matches complement embeddings, especially for short technical queries.
        tokens = set(re.findall(r"[a-z0-9]+", query.lower())) - {'on', 'the', 'a', 'of', 'and', 'for', 'in'}
        catalog = collection.get(include=['metadatas'])
        lexical = []
        for row_id, meta in zip(catalog['ids'], catalog['metadatas']):
            title = set(re.findall(r"[a-z0-9]+", meta['name'].lower()))
            exact = meta['attack_id'].lower() in query.lower().split()
            overlap = len(tokens & title) / max(len(title), 1)
            if exact or overlap:
                lexical.append((100 if exact else overlap, row_id, meta))
        seen = set()
        for score, row_id, meta in sorted(lexical, key=lambda x: (-x[0], x[1])):
            attack_id = meta['attack_id']
            if attack_id in seen:
                continue
            seen.add(attack_id)
            if attack_id not in candidates:
                doc = collection.get(ids=[row_id], include=['documents'])['documents'][0]
                candidates[attack_id] = {**meta, 'excerpt': doc, 'distance': None, 'retrieval_score': 0.0}
            candidates[attack_id]['retrieval_score'] += (1 if score == 100 else score * 0.04)
            if len(seen) >= 20:
                break
        rows = sorted(candidates.values(), key=lambda r: -r['retrieval_score'])[:limit]
        self.retrievals.append({'query': query, 'results': rows})
        return rows

    def related(self, rows, limit=30):
        """Follow STIX links only from a bundle matching the active index fingerprint."""
        metadata = self.collection.metadata or {}
        source = metadata.get('source', '')
        path = Path(source) if source and not source.startswith(('https://', 'http://')) else Path('data/enterprise-attack.json')
        if not path.is_file():
            return []
        raw = path.read_bytes()
        if hashlib.sha256(raw).hexdigest() != metadata.get('sha256'):
            return []
        objects = json.loads(raw)['objects']
        active = {o['id']: o for o in objects if not o.get('revoked') and not o.get('x_mitre_deprecated')}
        selected = {r['attack_id'] for r in rows}
        stix = {o['id'] for o in active.values() if any(r.get('external_id') in selected for r in o.get('external_references', []))}
        links = []
        for relation in active.values():
            kind = relation.get('relationship_type')
            if kind not in {'mitigates', 'detects', 'subtechnique-of', 'uses'}:
                continue
            source_id, target_id = relation.get('source_ref'), relation.get('target_ref')
            other = source_id if target_id in stix else target_id if source_id in stix else None
            if other in active and other not in stix:
                links.append((kind, other, source_id, target_id))
        result = []
        seen = set()
        collection = self.active()
        priority = {'mitigates': 0, 'detects': 1, 'subtechnique-of': 2, 'uses': 3}
        for kind, other, source_id, target_id in sorted(links, key=lambda r: priority[r[0]]):
            if other in seen:
                continue
            found = collection.get(ids=[other + ':0'], include=['documents', 'metadatas'])
            if not found['ids']:
                continue
            seen.add(other)
            result.append({**found['metadatas'][0], 'excerpt': found['documents'][0],
                           'relationship': {'type': kind, 'source_ref': source_id, 'target_ref': target_id}})
            if len(result) >= limit:
                break
        self.retrievals.append({'query': 'STIX relationship expansion (matching snapshot)', 'results': result})
        return result
