import json
import os
os.environ['OTEL_SDK_DISABLED'] = 'true'
os.environ['CREWAI_TELEMETRY_DISABLED'] = 'true'
import pytest
from crewai import BaseLLM
from pydantic import PrivateAttr
from redcrew.reporting import AssessmentReport, validate_report, render_report

ENGAGEMENT = {'targets': ['lab.test'], 'evidence': [{'id': 'E1', 'target': 'lab.test', 'content': 'SSH patch status is unknown.'}]}
SOURCES = [{'query': 'SSH', 'results': [{'attack_id': 'T1021.004', 'url': 'https://attack.mitre.org/techniques/T1021/004/'}]}]


def report_data():
    return {'summary': 'Review of supplied SSH configuration evidence.', 'findings': [
        {'title': 'Patch status unknown', 'target': 'lab.test', 'status': 'unknown', 'severity': 'informational',
         'explanation': 'The evidence does not establish the SSH patch status.',
         'evidence': [{'evidence_id': 'E1', 'quote': 'SSH patch status is unknown.'}],
         'attack': [{'attack_id': 'T1021.004', 'url': 'https://attack.mitre.org/techniques/T1021/004/', 'rationale': 'SSH provides context only, not proof of compromise.'}],
         'validation': 'Review the installed package version and vendor advisories.',
         'remediation': 'Apply supported vendor updates if required.'}],
        'limitations': ['No live tests were executed.']}


def test_valid_provenance():
    report = validate_report(AssessmentReport.model_validate(report_data()), ENGAGEMENT, SOURCES)
    assert 'not independently verified' in render_report(report)


@pytest.mark.parametrize('change', ['target', 'id', 'quote', 'url', 'attack_id', 'unretrieved'])
def test_rejects_bad_provenance(change):
    data = report_data()
    finding = data['findings'][0]
    if change == 'target': finding['target'] = 'outside.test'
    if change == 'id': finding['evidence'][0]['evidence_id'] = 'E999'
    if change == 'quote': finding['evidence'][0]['quote'] = 'Invented evidence proving compromise.'
    if change == 'url': finding['attack'][0]['url'] = 'https://invalid.test/'
    if change == 'attack_id': finding['attack'][0]['attack_id'] = 'T9999'
    with pytest.raises(ValueError):
        validate_report(AssessmentReport.model_validate(data), ENGAGEMENT, [] if change == 'unretrieved' else SOURCES)


class ScriptedLLM(BaseLLM):
    _roles: list = PrivateAttr(default_factory=list)
    _prompts: list = PrivateAttr(default_factory=list)
    _asked_tool: bool = PrivateAttr(default=False)

    def call(self, messages, **kwargs):
        agent = kwargs.get('from_agent')
        self._roles.append(agent.role if agent else 'conversion')
        self._prompts.append(str(messages))
        if not self._asked_tool:
            self._asked_tool = True
            return 'Thought: Retrieve SSH source context.\nAction: search_mitre_attack\nAction Input: {"query": "SSH"}'
        return 'Final Answer: ' + json.dumps(report_data())


def test_real_seven_agent_kickoff(monkeypatch):
    from redcrew.crew import build_crew, ROLES
    llm = ScriptedLLM(model='offline-test')
    class KnowledgeStub:
        calls = []
        def search(self, query):
            self.calls.append(query)
            return SOURCES[0]['results']
    knowledge = KnowledgeStub()
    crew = build_crew(knowledge, llm=llm)
    from redcrew.budget import request_budget
    monkeypatch.setenv('LLM_MIN_CALL_INTERVAL', '0')
    with request_budget(llm):
        result = crew.kickoff(inputs={'engagement': json.dumps(ENGAGEMENT), 'knowledge': json.dumps(SOURCES)})
    assert [t.agent for t in result.tasks_output] == [r[0] for r in ROLES]
    assert len(result.tasks_output) == 7
    assert knowledge.calls == ['SSH']
    assert result.pydantic is not None
    validate_report(result.pydantic, ENGAGEMENT, SOURCES)
    # Later agents actually receive preceding task output.
    assert 'Patch status unknown' in llm._prompts[-1]


@pytest.mark.parametrize('invalid', [False, True])
def test_cli_publishes_only_valid_reports(tmp_path, monkeypatch, invalid):
    from types import SimpleNamespace
    from redcrew import cli, crew, knowledge
    data = report_data()
    if invalid:
        data['findings'][0]['evidence'][0]['evidence_id'] = 'invented'
    report = AssessmentReport.model_validate(data)
    result = SimpleNamespace(pydantic=report, tasks_output=[], raw=report.model_dump_json())
    monkeypatch.setenv('LLM_API_KEY', 'test-key')
    monkeypatch.setattr(crew, 'build_crew', lambda k, **kwargs: SimpleNamespace(kickoff=lambda **kw: result, agents=[SimpleNamespace(llm=object())]))
    fake = SimpleNamespace(search=lambda q: SOURCES[0]['results'], retrievals=SOURCES, collection=SimpleNamespace(metadata={}))
    monkeypatch.setattr(knowledge, 'Knowledge', lambda path: fake)
    path = tmp_path / 'engagement.json'
    path.write_text(json.dumps({**ENGAGEMENT, 'name': 'Test lab', 'authorized': True, 'objective': 'Review supplied SSH evidence', 'evidence': [{**ENGAGEMENT['evidence'][0], 'kind': 'configuration'}]}))
    output = tmp_path / 'reports'
    monkeypatch.setattr('sys.argv', ['redcrew', 'run', str(path), '--output', str(output)])
    if invalid:
        with pytest.raises(SystemExit) as error:
            cli.main()
        assert error.value.code == 1
    else:
        cli.main()
    folder = next(output.iterdir())
    assert (folder / 'report.md').exists() is not invalid
    assert (folder / 'report.json').exists() is not invalid
    audit = json.loads((folder / 'audit.json').read_text())
    assert audit['status'] == ('failed' if invalid else 'provenance_validated')
    assert audit['retrievals'] == SOURCES
