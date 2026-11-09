from types import SimpleNamespace
import pytest
from redcrew.budget import RequestBudget, RequestBudgetError, request_budget
from redcrew.crew import compact_sources, concise_handoff


def test_large_request_fails_before_waiting():
    llm = object()
    guard = RequestBudget(llm, sleep=lambda _: pytest.fail('must not wait'))
    with pytest.raises(RequestBudgetError, match='Reduce engagement'):
        guard(SimpleNamespace(llm=llm, messages=[{'content': 'a' * 20000}]))


def test_spacing_and_unrelated_calls():
    llm = object()
    waits = []
    guard = RequestBudget(llm, clock=lambda: 100, sleep=waits.append)
    guard(SimpleNamespace(llm=object(), messages=[]))
    assert guard.last_call is None
    guard(SimpleNamespace(llm=llm, messages=[]))
    guard(SimpleNamespace(llm=llm, messages=[]))
    assert waits == [61]


def test_compaction_retains_source_identity():
    rows = [{'attack_id': 'T1', 'name': 'name', 'url': 'source', 'excerpt': 'x' * 2000, 'distance': 1}] * 5
    compact = compact_sources(rows)
    assert len(compact) == 3
    assert compact[0]['attack_id'] == 'T1'
    assert len(compact[0]['excerpt']) == 650
    assert 'distance' not in compact[0]
    assert concise_handoff(SimpleNamespace(raw='x' * 2201))[0] is False


def test_guard_aborts_actual_crewai_execution(monkeypatch):
    from test_reliability import ScriptedLLM
    from redcrew.crew import build_crew
    llm = ScriptedLLM(model='offline-test')
    crew = build_crew(object(), llm=llm)
    monkeypatch.setenv('LLM_MIN_CALL_INTERVAL', '0')
    with request_budget(llm):
        with pytest.raises(RequestBudgetError):
            crew.kickoff(inputs={'engagement': 'x' * 24000, 'knowledge': '[]'})
    assert llm._prompts == []


def test_small_overflow_compacts_only_registered_sources():
    import json
    llm = object()
    rows = [{'attack_id': 'T1021.004', 'name': 'SSH', 'url': 'https://attack.mitre.org/techniques/T1021/004/', 'excerpt': 'A' * 300}] * 5
    packet = json.dumps(rows)
    evidence = 'Original evidence: ' + 'E' * 2500
    messages = [{'role': 'user', 'content': evidence + '\nSources: ' + packet}]
    probe = RequestBudget(llm)
    budget = probe.estimate(messages) - 21
    guard = RequestBudget(llm, tokens=budget, interval=0, source_packets=[packet])
    guard(SimpleNamespace(llm=llm, messages=messages))
    assert guard.estimate(messages) <= budget
    assert messages[0]['content'].startswith(evidence)
    compact = json.loads(messages[0]['content'].split('\nSources: ')[1])
    assert all(row['attack_id'] == 'T1021.004' and row['url'] == rows[0]['url'] for row in compact)
    assert all(len(row['excerpt']) < 300 for row in compact)
    next_messages = [{'role': 'user', 'content': evidence + '\nSources: ' + packet}]
    guard(SimpleNamespace(llm=llm, messages=next_messages))
    assert guard.estimate(next_messages) <= budget


def test_uncompressible_evidence_still_rejected():
    import json
    llm = object()
    packet = json.dumps([{'attack_id': 'T1', 'excerpt': 'tiny'}])
    messages = [{'content': 'E' * 25000 + packet}]
    guard = RequestBudget(llm, source_packets=[packet])
    with pytest.raises(RequestBudgetError):
        guard(SimpleNamespace(llm=llm, messages=messages))
    assert messages[0]['content'].startswith('E' * 25000)


def test_error_does_not_redact_budget_settings(monkeypatch):
    from redcrew.diagnostics import safe_error
    monkeypatch.setenv('LLM_REQUEST_TOKEN_BUDGET', '7000')
    monkeypatch.setenv('LLM_MAX_TOKENS', '1200')
    monkeypatch.setenv('LLM_API_KEY', 'secret-api-value')
    message = safe_error(ValueError('budget 7000 output 1200 key secret-api-value'))
    assert '7000' in message and '1200' in message
    assert 'secret-api-value' not in message


def test_json_compaction_preserves_evidence_and_embedded_quotes():
    import json
    from redcrew.budget import compact_json_fragments
    evidence = {'content': 'Whitespace  inside\n evidence must stay. {"key":  3}', 'unicode': 'é'}
    original = json.dumps({'evidence': [evidence]}, indent=4)
    result = compact_json_fragments('Prefix\n' + original + '\nSuffix')
    assert json.loads(result[len('Prefix\n'):-len('\nSuffix')]) == {'evidence': [evidence]}
    assert len(result) < len(original) + len('Prefix\n\nSuffix')


def test_json_compaction_handles_residual_overflow():
    import json
    llm = object()
    payload = json.dumps({'evidence': [{'id': 'E1', 'content': 'Original evidence unchanged.'}] * 20}, indent=8)
    messages = [{'role': 'user', 'content': payload}]
    probe = RequestBudget(llm)
    limit = probe.estimate(messages) - 142
    guard = RequestBudget(llm, tokens=limit, interval=0)
    guard(SimpleNamespace(llm=llm, messages=messages))
    assert guard.estimate(messages) <= limit
    assert json.loads(messages[0]['content']) == json.loads(payload)
    assert guard.adjustments[-1]['method'] == 'lossless_json_compaction'
