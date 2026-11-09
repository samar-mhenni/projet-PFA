# RedCrew

A Python project using seven CrewAI agents and a persistent Chroma vector database for evidence-led, authorized security assessments. Add your LLM API key when ready. ATT&CK ingestion and semantic search use local embeddings and need no paid API.

## One-command target assessment

With your LLM API configured in `.env` and the local ATT&CK index populated:

```bash
source .venv/bin/activate
redcrew assess http://127.0.0.1:8080
```

Only the target is required. Three optional arguments are available: `--name`, `--objective`, and `--output`.

```bash
redcrew assess http://127.0.0.1:8080 --name "Vulhub Tomcat" --objective "Review HTTP exposure and mitigations" --output reports
```

Use this command for targets you own or are authorized to assess. It initially sends one GET request, then enables agent-driven HEAD and OPTIONS scripts. It saves a bounded HTTP header/body snapshot as `engagement.json`, researches local ATT&CK, and invokes the configured LLM API. Redirects are recorded without following them. HTTPS certificate validation stays enabled. No shell, exploit, port scan or host inspection runs. Requesting a target assessment declares authorization for that target. Collected evidence is sent to the configured LLM provider; API usage applies.

The original `redcrew run engagement.json` command remains available for richer manually supplied evidence and research-only runs. API credentials and token limits remain in `.env`, so they do not need command arguments.

## Setup

Use Python 3.11–3.13 (Python 3.14 is not supported by this project's dependency range).

```bash
python3.13 -m venv .venv
source .venv/bin/activate
pip install -r requirements.lock.txt
pip install -e '.[dev]'
cp .env.example .env
redcrew run examples/engagement.json --dry-run
redcrew ingest
redcrew search 'Linux SSH remote services'
```

The first ingestion downloads official Enterprise ATT&CK and Chroma's local ONNX embedding model. Internet access and disk space are required. Subsequent search uses the stored database and cached model. Set `VECTORDB_PATH` in `.env` to change storage. To import a pinned release or work from a downloaded bundle, use `redcrew ingest --file /path/to/enterprise-attack.json`.

In `.env`, set `LLM_MODEL`, `LLM_API_KEY` and optionally `LLM_BASE_URL` for an OpenAI-compatible endpoint. Other providers may require CrewAI provider extras. Then:

```bash
redcrew run examples/engagement.json
```

Copy the example engagement and supply your authorized targets and actual evidence. The example contains fictional training observations, not live findings. Evidence `target` values must exactly match a declared target, and evidence IDs must be unique. Evidence and retrieved context are sent to the configured LLM provider during a run.

## Agent workflow

Planning → Recon → Web → Linux → ATT&CK analyst → Reviewer → Reporting.

Each task receives the immediately preceding agent’s concise handoff and the original engagement. Handoffs must preserve relevant earlier findings; this reduces repeated context but can lose detail, so the original evidence remains available to each agent. Analysis agents can search the local ATT&CK database; Reporting uses the prepared context. Retrieval combines semantic matches with technique-name and exact-ID matches and deduplicates records. Recon, web and Linux agents analyze supplied inventory, HTTP observations, configuration and logs. The reviewer challenges unsupported claims before reporting. A sequential CrewAI process makes task dependencies explicit; these are distinct agents, not concurrent shell processes.

This version provides analysis and validation plans. It does not execute exploits, shell commands or network scans. The assess command additionally enables the bounded agent-executed HTTP checks described below. An authorization declaration is required before assessment. Agent instructions require evidence citations, distinguish unknowns from findings, and treat evidence as untrusted content; these instructions cannot guarantee the correctness of LLM output.

## Knowledge and reliability

Official MITRE STIX objects are filtered to exclude revoked/deprecated content, chunked and embedded into Chroma. Supported records include techniques/sub-techniques, mitigations, tactics, groups, software, detection strategies and analytics. STIX relationships are expanded locally from the matching source bundle during pre-LLM research; Chroma stores record embeddings, not a graph database. Source URLs, ATT&CK IDs, modification dates and platforms accompany retrieved excerpts. Retrieval returns semantic matches, which are context rather than proof that a vulnerability exists.

Imports use content-addressed collections and switch the active collection only after completion, so a failed new import leaves the previous collection usable. Reimporting the same bundle upserts the same IDs. Old snapshots remain on disk. Each successful import records the source and SHA-256; the default upstream `master` URL changes over time, so use a versioned local file for reproducibility.

Successful runs write a timestamped `reports/` directory containing `report.md`, structured `report.json`, and `audit.json`. The audit includes evidence, model, dataset fingerprint, completed task outputs, and every ATT&CK search performed through the knowledge object. Failed runs keep an audit with failure status and publish no final report. A mid-run failure may leave task outputs unavailable; the audit is not a complete provider transcript. Reports may contain sensitive supplied evidence; `.env`, data, and reports are gitignored. Review conclusions before using them operationally.

## Development

```bash
pytest -q
pip freeze > requirements.lock.txt
```

The vector integration test downloads the embedding model on first use; the remaining tests need no network. No API key is required for tests. Full LLM execution requires a configured provider and can incur API charges. `max_iter`, output limits and CrewAI rate limits are configured in `src/redcrew/crew.py`.

Sources: [CrewAI agents](https://docs.crewai.com/en/concepts/agents), [CrewAI LLM configuration](https://docs.crewai.com/en/concepts/llms), [Chroma](https://docs.trychroma.com/), [official MITRE ATT&CK STIX data and license](https://github.com/mitre-attack/attack-stix-data). ATT&CK data remains subject to MITRE's license; no dataset is committed to this project.

## Reliability checks

The final agent must return a structured report. Before publication, Python validates every finding's target against the authorized scope, evidence IDs against the supplied evidence, verbatim quotes against the cited content, and ATT&CK ID/URL pairs against sources actually retrieved during that run. Unknown IDs, mismatched quotes, fabricated source URLs and malformed output prevent publication. Findings use `observation`, `hypothesis`, or `unknown`; they are never labeled independently confirmed by this application.

These are provenance checks, not factual proof: a real quotation can still be misinterpreted, supplied evidence can be wrong, and relevant ATT&CK context does not establish a vulnerability. Summary, explanations and proposed mitigations still require human review. Retrieval always returns ranked candidates, even for unrelated queries; scores are not confidence probabilities. Agent prompts instruct abstention where evidence is insufficient.

`pytest -q` exercises the real seven-agent CrewAI execution engine with a deterministic offline model, a search-tool invocation, sequential task handoffs, schema parsing, invalid citations, and CLI publication/failure handling. This verifies integration without provider charges. It does not evaluate a real model's reasoning or verify API credentials. After setting your API key, run the example engagement and inspect the audit and report before using real assessment data.

## Groq accounts with an 8,000 TPM limit

The default request settings are now conservative:

```dotenv
LLM_MAX_TOKENS=1200
LLM_REQUEST_TOKEN_BUDGET=7000
LLM_MIN_CALL_INTERVAL=61
```

The CLI spaces model calls by at least 61 seconds, including tool follow-ups. Seven agents can therefore take several minutes. Avoid concurrent runs or other clients using the same Groq quota. The preflight budget estimates message tokens and reserves space for schemas and completion tokens. It is deliberately conservative, but is not Groq's exact tokenizer and cannot guarantee acceptance. Oversized requests stop with an audit entry; evidence is not silently truncated. Reduce the engagement size if this check fails.

Agents receive one preceding handoff capped at 2,200 characters; overly long handoffs get one correction attempt. Retrieval sent to the model is limited to three excerpts of 650 characters each; full retrievals stay in the audit. Provider SDK retries and agent retries are disabled to avoid repeating oversized requests. The approximate-token-count warning from CrewAI is informational and remains visible. Increase limits only when your account supports them; larger output budgets also need a larger total request budget. Full model/provider behavior still requires a live run.

## Database-first research

Before creating the LLM crew, the runner searches the objective, every evidence item (in overlapping segments), and seven specialist topics against local Chroma. It deduplicates results and, when a matching STIX bundle is available, follows mitigation, detection, sub-technique and usage relationships. Relationship expansion checks the bundle SHA-256 against the active index and returns up to 30 linked indexed records; it does not treat unrelated snapshots as authoritative.

`research.json` saves all retrieved source excerpts, query/evidence associations, linked records and the exact bounded source packet selected for each agent. Each packet is capped at 3,000 serialized characters to fit low-throughput Groq accounts. These are ranked candidate mappings, not proof that the behavior occurred. Additional agent searches remain available. More database coverage happens locally without putting the entire ATT&CK database into an LLM prompt.

To research without making any LLM call or needing an API key:

```bash
redcrew run examples/engagement.json --research-only
```

A normal run performs the same research automatically. Completed agent outputs are saved incrementally in `audit.json`, even when a later agent fails. Errors now retain credential-redacted exception details and causes in both the CLI and audit. Old audits that recorded only `Exception` cannot reconstruct the original underlying error. GPT-OSS defaults to low reasoning effort to leave more completion budget for the actual answer; override with `LLM_REASONING_EFFORT` if needed. Short handoffs request at most 140 words to stay within the existing character guardrail.

Near-budget requests automatically shorten registered ATT&CK excerpts before failing, leaving source identifiers, source URLs, and original engagement evidence intact. Full retrieved text stays in `research.json`; `audit.json` records the estimated size before and after each adjustment in `budget_adjustments`. If the request still cannot fit after excerpt reduction, it stops without sending an oversized request. This remains an approximate local budget, not a guarantee of provider acceptance.

The reporting agent uses its prepared sources and reviewer handoff without a search tool. If excerpt reduction alone is insufficient, the request preflight also removes formatting whitespace from embedded JSON while preserving decoded evidence values. Both reductions are recorded in `budget_adjustments`. Reporting prompts require short contiguous quotes with original whitespace and HTML markup; citation validation still rejects altered quotations.

## Script artifacts

Every new run exports a `scripts/` folder alongside its report and audit, including failed runs. `manifest.json` records each artifact's origin, execution status and SHA-256. HTTP assessments include a snapshot of the collector used by the application, plus a `replay_http.py` wrapper. `replay_searches.py` replays recorded vector searches. Replay scripts are generated for reproduction and are not automatically executed. They require the project virtual environment.

Supported fenced code blocks actually emitted by agents are saved as `agent_XX_proposal_YY.*` and explicitly marked `proposed_not_executed`. No agent shell execution is implemented, and no scripts are fabricated if the agents produced none. Review proposals before manually running them.

To export artifacts for an existing report without API calls:

```bash
redcrew export-scripts reports/YOUR_RUN_DIRECTORY
```

For older runs without collection metadata, the collector snapshot is labeled as current reference code, not proven historical execution. Replaying a script gathers new observations and may use a different database snapshot. Original evidence remains in the audit.

## Agent-executed checks

`redcrew assess URL` now enables `execute_http_check` for Recon and Web. Recon is instructed to execute a HEAD headers check and Web an OPTIONS methods check. The tool generates a fixed Python script and executes it as a subprocess, with no shell and without inherited API-key environment variables. Only exact authorized HTTP(S) URLs and these two check types are accepted. Redirects are not followed; requests time out after 5 seconds and processes after 10 seconds. At most two checks may be attempted in a run. This is a restricted template executor, not a sandbox for arbitrary model-generated code.

Each attempt produces `scripts/executed/check_XX.py` and `check_XX.json`, containing agent attribution, source hash, stdout, stderr, exit code and status. Successful observations receive evidence IDs and are passed to later tasks and provenance validation. The manifest and audit reference execution records. Failed requests do not become confirmed observations. OPTIONS/Allow headers do not establish exploitability.

The model can still fail to invoke a tool; only actual execution records establish that a check ran. Fenced code proposals remain unexecuted. `redcrew run engagement.json` retains evidence-analysis behavior. These checks do not execute exploits, inspect Linux configuration, or automatically run arbitrary shell/Python proposals.
