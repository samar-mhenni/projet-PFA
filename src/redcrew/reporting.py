"""Deterministic provenance checks; these do not prove a finding is true."""
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field


class StrictModel(BaseModel):
    model_config = ConfigDict(extra='forbid')


class EvidenceCitation(StrictModel):
    evidence_id: str
    quote: str = Field(min_length=10)


class AttackCitation(StrictModel):
    attack_id: str
    url: str
    rationale: str = Field(min_length=10)


class Finding(StrictModel):
    title: str = Field(min_length=1)
    target: str
    status: Literal['observation', 'hypothesis', 'unknown']
    severity: Literal['informational', 'low', 'medium', 'high', 'critical']
    explanation: str = Field(min_length=10)
    evidence: list[EvidenceCitation] = Field(min_length=1)
    attack: list[AttackCitation]
    validation: str = Field(min_length=10)
    remediation: str = Field(min_length=10)


class AssessmentReport(StrictModel):
    summary: str = Field(min_length=10)
    findings: list[Finding]
    limitations: list[str] = Field(min_length=1)


def validate_report(report, engagement, retrievals):
    evidence = {e['id']: e for e in engagement['evidence']}
    sources = {(r['attack_id'], r['url']) for call in retrievals for r in call['results']}
    errors = []
    for index, finding in enumerate(report.findings):
        prefix = f'Finding {index + 1}'
        if finding.target not in engagement['targets']:
            errors.append(f'{prefix}: target outside authorized scope')
        for citation in finding.evidence:
            item = evidence.get(citation.evidence_id)
            if item is None:
                errors.append(f'{prefix}: unknown evidence ID {citation.evidence_id}')
            elif item['target'] != finding.target or citation.quote not in item['content']:
                errors.append(f'{prefix}: evidence quote or target does not match {citation.evidence_id}')
        for citation in finding.attack:
            if (citation.attack_id, citation.url) not in sources:
                errors.append(f'{prefix}: ATT&CK ID/URL was not retrieved: {citation.attack_id}')
    if errors:
        raise ValueError('; '.join(errors))
    return report


def render_report(report):
    lines = ['# Security assessment', '', report.summary, '',
             '> Evidence analysis only. Provenance checks passed; findings are not independently verified.', '']
    for finding in report.findings:
        lines += [f'## {finding.title}', '', f'Target: {finding.target} | Status: {finding.status} | Severity: {finding.severity}', '', finding.explanation, '']
        for citation in finding.evidence:
            lines += [f'- Evidence {citation.evidence_id}: {citation.quote}']
        for citation in finding.attack:
            lines += [f'- ATT&CK [{citation.attack_id}]({citation.url}): {citation.rationale}']
        lines += ['', f'Validation: {finding.validation}', '', f'Remediation: {finding.remediation}', '']
    lines += ['## Limitations', ''] + [f'- {item}' for item in report.limitations]
    return '\n'.join(lines) + '\n'
