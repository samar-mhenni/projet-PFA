from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
import pytest
from redcrew.target import normalize_target, collect_target


@pytest.mark.parametrize('value', ['file:///etc/passwd', 'ftp://localhost', 'http://user:password@localhost', 'http://localhost:bad', 'http://bad host'])
def test_reject_invalid_target(value):
    with pytest.raises(ValueError):
        normalize_target(value)


def test_default_scheme_and_fragment():
    assert normalize_target('127.0.0.1:8080#fragment') == 'http://127.0.0.1:8080/'


@pytest.fixture
def server():
    class Handler(BaseHTTPRequestHandler):
        calls = []
        def do_GET(self):
            self.calls.append(self.path)
            self.send_response(302 if self.path == '/redirect' else 200)
            self.send_header('Content-Type', 'text/html')
            self.send_header('Location', '/other')
            self.end_headers()
            self.wfile.write(b'Example lab page' * 500)
        def log_message(self, *args):
            pass
    httpd = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield f'http://127.0.0.1:{httpd.server_port}', Handler.calls
    httpd.shutdown()
    httpd.server_close()
    thread.join()


def test_collects_bounded_real_response(server, tmp_path):
    import json
    from redcrew.engagement import load_engagement
    url, calls = server
    result = collect_target(url, name='Lab', objective='Review HTTP evidence')
    assert 'HTTP 200' in result['evidence'][0]['content']
    assert 'Example lab page' in result['evidence'][1]['content']
    assert len(result['evidence'][1]['content']) < 2000
    assert calls == ['/']
    path = tmp_path / 'engagement.json'
    path.write_text(json.dumps(result))
    assert load_engagement(path)['name'] == 'Lab'


def test_does_not_follow_redirect(server):
    url, calls = server
    result = collect_target(url + '/redirect')
    assert 'HTTP 302' in result['evidence'][0]['content']
    assert calls == ['/redirect']


def test_assess_cli_runs_pipeline(server, tmp_path, monkeypatch):
    import json
    from types import SimpleNamespace
    from redcrew import cli, crew, knowledge
    from redcrew.reporting import AssessmentReport
    url, calls = server
    captured = {}
    report = AssessmentReport(summary='No confirmed findings from this HTTP snapshot.', findings=[], limitations=['HTTP evidence only.'])
    def kickoff(inputs):
        captured.update(inputs)
        return SimpleNamespace(pydantic=report, tasks_output=[], raw=report.model_dump_json())
    monkeypatch.setenv('LLM_API_KEY', 'test-key')
    monkeypatch.setattr(crew, 'build_crew', lambda k, **kwargs: SimpleNamespace(kickoff=kickoff, agents=[SimpleNamespace(llm=object())]))
    monkeypatch.setattr(knowledge, 'Knowledge', lambda path: SimpleNamespace(search=lambda query: [], retrievals=[], collection=SimpleNamespace(metadata={})))
    monkeypatch.setattr('sys.argv', ['redcrew', 'assess', url, '--output', str(tmp_path), '--name', 'Local test'])
    cli.main()
    folder = next(tmp_path.iterdir())
    assert (folder / 'report.md').exists()
    assert json.loads((folder / 'audit.json').read_text())['status'] == 'provenance_validated'
    engagement = json.loads(captured['engagement'])
    assert engagement['name'] == 'Local test'
    assert 'HTTP 200' in engagement['evidence'][0]['content']
    assert calls == ['/']
