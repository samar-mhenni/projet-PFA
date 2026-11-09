"""Construct the actual CrewAI graph without making provider requests."""
import pytest


def test_crew_graph(monkeypatch):
    monkeypatch.setenv('OTEL_SDK_DISABLED', 'true')
    monkeypatch.setenv('CREWAI_TELEMETRY_DISABLED', 'true')
    monkeypatch.setenv('LLM_API_KEY', 'test-placeholder-not-a-real-key')
    from redcrew.crew import build_crew
    crew = build_crew(object())
    assert len(crew.agents) == len(crew.tasks) == 7
    assert len(crew.tasks[-1].context) == 1
    assert all(not a.allow_delegation for a in crew.agents)
    assert all(a.tools[0].name == 'search_mitre_attack' for a in crew.agents[:-1])
    assert crew.agents[-1].tools == []


def test_missing_api_key(monkeypatch):
    monkeypatch.delenv('LLM_API_KEY', raising=False)
    from redcrew.crew import build_crew
    with pytest.raises(ValueError, match='LLM_API_KEY'):
        build_crew(object())
