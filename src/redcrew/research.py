"""Deterministic ATT&CK research performed before any LLM request."""
import json

TOPICS = {
    'Planning': 'attack surface techniques mitigations detection',
    'Recon': 'network service discovery remote services',
    'Web': 'web application public facing application exploitation authentication',
    'Linux': 'Linux SSH permissions account access authentication logs',
    'ATT&CK analyst': 'adversary techniques mitigations detection strategies',
    'Reviewer': 'detection evidence mitigations validation',
    'Reporting': 'security mitigations detection recommendations',
}


def packet(rows, max_chars=3000):
    """Fit complete source identities and short excerpts, never engagement evidence."""
    selected = []
    seen = set()
    for row in rows:
        if row['attack_id'] in seen:
            continue
        item = {k: row.get(k, '') for k in ('attack_id', 'name', 'url')}
        item['excerpt'] = row.get('excerpt', '')[:300]
        if 'relationship' in row:
            item['relationship'] = row['relationship']
        candidate = selected + [item]
        if len(json.dumps(candidate, ensure_ascii=True)) > max_chars:
            continue
        selected = candidate
        seen.add(row['attack_id'])
    return selected


def prepare_research(knowledge, engagement):
    queries = []
    merged = {}
    general = []

    def search(query, evidence_id=None, role=None):
        rows = knowledge.search(query)
        queries.append({'query': query, 'evidence_id': evidence_id, 'role': role,
                        'attack_ids': [r['attack_id'] for r in rows]})
        for row in rows:
            entry = merged.setdefault(row['attack_id'], {**row, 'evidence_ids': [], 'roles': []})
            if evidence_id and evidence_id not in entry['evidence_ids']:
                entry['evidence_ids'].append(evidence_id)
            if role and role not in entry['roles']:
                entry['roles'].append(role)
        return rows

    general.extend(search(engagement['objective']))
    for evidence in engagement['evidence']:
        # Cover the entire supplied content, rather than just its first sentence.
        content = evidence['content']
        for start in range(0, len(content), 900):
            general.extend(search(content[start:start + 1100], evidence_id=evidence['id']))
    evidence_summary = ' '.join(e['content'][:250] for e in engagement['evidence'])[:1200]
    by_role = {}
    for role, topic in TOPICS.items():
        by_role[role] = search(topic + '\n' + evidence_summary, role=role)
    related = knowledge.related(list(merged.values())) if hasattr(knowledge, 'related') else []
    for row in related:
        merged.setdefault(row['attack_id'], {**row, 'evidence_ids': [], 'roles': []})
    packets = {}
    for role, rows in by_role.items():
        # Reserve room for evidence-oriented results and linked mitigations.
        packets[role] = packet(rows[:2] + general[:2] + related[:2] + rows[2:] + general + related)
    return {'queries': queries, 'sources': list(merged.values()), 'relationships': related,
            'agent_packets': packets,
            'limitations': ['Ranked ATT&CK matches are candidates, not confirmed findings.',
                            'Packets contain bounded excerpts; full retrieved excerpts are saved here.']}
