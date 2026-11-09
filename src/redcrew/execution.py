"""Execute fixed HTTP-check scripts, never model-supplied source code."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from typing import Literal
from crewai.tools import BaseTool
from pydantic import BaseModel, PrivateAttr
from .target import normalize_target


class CheckInput(BaseModel):
    target: str
    check: Literal['headers', 'methods'] = 'headers'


class ScriptRunner:
    def __init__(self, folder, engagement):
        self.folder = Path(folder) / 'scripts' / 'executed'
        self.folder.mkdir(parents=True, exist_ok=True)
        self.engagement = engagement
        self.records = []

    def run(self, target, check, agent):
        if self.engagement.get('authorized') is not True:
            raise ValueError('Explicit target authorization is required')
        if check not in {'headers', 'methods'}:
            raise ValueError('Unsupported check')
        url = normalize_target(target)
        allowed = {normalize_target(t): t for t in self.engagement['targets'] if t.startswith(('http://', 'https://'))}
        if url not in allowed:
            raise ValueError('URL is outside the exact authorized target scope')
        if len(self.records) >= 2:
            return json.dumps({'status': 'limit_reached', 'message': 'Two checks already attempted; use their existing evidence.'})
        method = 'HEAD' if check == 'headers' else 'OPTIONS'
        index = len(self.records) + 1
        script = self.folder / f'check_{index:02d}.py'
        code = '''import json
from urllib.request import Request, build_opener, HTTPRedirectHandler, ProxyHandler
from urllib.error import HTTPError
class NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None
opener = build_opener(ProxyHandler({}), NoRedirects())
try:
    response = opener.open(Request(URL, method=METHOD, headers={'User-Agent': 'RedCrew-check/0.1'}), timeout=5)
except HTTPError as exc:
    response = exc
with response:
    print(json.dumps({'status': response.code, 'headers': str(response.headers)[:350]}))
'''
        code = f'URL = {url!r}\nMETHOD = {method!r}\n' + code
        script.write_text(code)
        record = {'script': str(script), 'agent': agent, 'target': url, 'method': method,
                  'sha256': hashlib.sha256(code.encode()).hexdigest(), 'status': 'started'}
        self.records.append(record)
        try:
            result = subprocess.run([sys.executable, '-I', str(script.resolve())], capture_output=True, text=True,
                                    timeout=10, env={}, cwd=str(self.folder.resolve()))
            record.update(exit_code=result.returncode, stdout=result.stdout, stderr=result.stderr,
                          status='completed' if result.returncode == 0 else 'failed')
        except subprocess.TimeoutExpired:
            record.update(status='timeout', exit_code=None, stdout='', stderr='Execution exceeded 10 seconds')
        except OSError as exc:
            record.update(status='failed', exit_code=None, stdout='', stderr=type(exc).__name__)
        if record['status'] == 'completed':
            evidence_id = f'EXEC{index:03d}'
            if any(e['id'] == evidence_id for e in self.engagement['evidence']):
                evidence_id = f'EXEC{index:03d}_{record["sha256"][:12]}'
            content = f'{method} {url}: {record["stdout"].strip()}'
            self.engagement['evidence'].append({'id': evidence_id, 'target': allowed[url],
                                              'kind': 'executed_http_check', 'content': content})
            record['evidence_id'] = evidence_id
            record['evidence_content'] = content
        (self.folder / f'check_{index:02d}.json').write_text(json.dumps(record, indent=2))
        return json.dumps(record)


class ExecuteHTTPCheck(BaseTool):
    name: str = 'execute_http_check'
    description: str = 'Actually execute a fixed HEAD (headers) or OPTIONS (methods) script against an exact authorized URL. Returns execution status and evidence. No arbitrary code, redirects or shell commands. Maximum two checks per run.'
    args_schema: type[BaseModel] = CheckInput
    _runner: object = PrivateAttr()
    _agent: str = PrivateAttr()

    def __init__(self, runner, agent):
        super().__init__()
        self._runner, self._agent = runner, agent

    def _run(self, target: str, check: str = 'headers') -> str:
        return self._runner.run(target, check, self._agent)
