import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
import pytest
from redcrew.execution import ScriptRunner, ExecuteHTTPCheck


def test_executes_real_scripts_and_records_evidence(tmp_path):
    calls = []
    class Handler(BaseHTTPRequestHandler):
        def do_HEAD(self):
            calls.append('HEAD')
            self.send_response(200)
            self.end_headers()
        def do_OPTIONS(self):
            calls.append('OPTIONS')
            self.send_response(200)
            self.send_header('Allow', 'GET, HEAD, OPTIONS')
            self.end_headers()
        def log_message(self, *args): pass
    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f'http://127.0.0.1:{server.server_port}/'
    engagement = {'authorized': True, 'targets': [url], 'evidence': []}
    runner = ScriptRunner(tmp_path, engagement)
    try:
        tool = ExecuteHTTPCheck(runner, 'Recon')
        first = json.loads(tool.run(target=url, check='headers'))
        second = json.loads(runner.run(url, 'methods', 'Web'))
        assert first['status'] == second['status'] == 'completed'
        assert first['exit_code'] == 0
        assert calls == ['HEAD', 'OPTIONS']
        assert len(engagement['evidence']) == 2
        assert 'EXEC001' == engagement['evidence'][0]['id']
        assert (tmp_path / 'scripts/executed/check_01.py').exists()
        assert json.loads((tmp_path / 'scripts/executed/check_02.json').read_text())['method'] == 'OPTIONS'
        assert json.loads(runner.run(url, 'headers', 'Recon'))['status'] == 'limit_reached'
        assert len(calls) == 2
    finally:
        server.shutdown(); server.server_close(); thread.join()


@pytest.mark.parametrize('url,check', [('http://outside.test/', 'headers'), ('http://localhost/other','headers'), ('http://localhost/', 'shell')])
def test_refuses_out_of_scope_and_arbitrary_scripts(tmp_path, url, check):
    runner = ScriptRunner(tmp_path, {'authorized': True, 'targets': ['http://localhost/'], 'evidence': []})
    with pytest.raises(ValueError): runner.run(url, check, 'Web')
    assert not runner.records


def test_execution_tools_only_on_recon_web(tmp_path, monkeypatch):
    monkeypatch.setenv('LLM_API_KEY', 'test-key')
    from redcrew.crew import build_crew
    runner = ScriptRunner(tmp_path, {'authorized': True, 'targets': ['http://localhost/'], 'evidence': []})
    crew = build_crew(object(), execution=runner)
    roles = [a.role for a in crew.agents if any(t.name == 'execute_http_check' for t in a.tools)]
    assert roles == ['Recon', 'Web']
