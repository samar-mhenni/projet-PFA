import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
from uuid import uuid4
from dotenv import load_dotenv
from .engagement import load_engagement


def main():
    load_dotenv()
    os.environ.setdefault("OTEL_SDK_DISABLED", "true")
    os.environ.setdefault("CREWAI_TELEMETRY_DISABLED", "true")
    parser = argparse.ArgumentParser(description="CrewAI security assessment and MITRE ATT&CK vector search")
    sub = parser.add_subparsers(dest="command", required=True)
    ingest = sub.add_parser("ingest", help="Embed official Enterprise ATT&CK; no LLM key required")
    ingest.add_argument("--file", type=Path, help="Use a local STIX bundle instead of downloading")
    search = sub.add_parser("search")
    search.add_argument("query")
    run = sub.add_parser("run")
    run.add_argument("engagement", type=Path)
    run.add_argument("--dry-run", action="store_true", help="Validate input and show workflow without API calls")
    run.add_argument("--research-only", action="store_true", help="Research ATT&CK locally and save packets without any LLM calls")
    run.add_argument("--output", type=Path, default=Path("reports"))
    assess = sub.add_parser("assess", help="Collect HTTP evidence and assess a target with the configured LLM API",
                            description="Assess a target you own or are authorized to test. Sends one HTTP GET, then uses the configured LLM API.")
    assess.add_argument("target", help="HTTP(S) URL or host:port")
    assess.add_argument("--name", help="Assessment name")
    assess.add_argument("--objective", help="Override the assessment objective")
    assess.add_argument("--output", type=Path, default=Path("reports"))
    assess.set_defaults(research_only=False)
    export = sub.add_parser("export-scripts", help="Export scripts from an existing run without API calls")
    export.add_argument("folder", type=Path, help="Run directory containing audit.json")
    args = parser.parse_args()
    try:
        if args.command == "export-scripts":
            from .artifacts import export_scripts
            audit = json.loads((args.folder / 'audit.json').read_text())
            print(f"Scripts: {export_scripts(args.folder, audit)}")
            return
        if args.command == "run":
            engagement = load_engagement(args.engagement)
            if args.dry_run:
                print(json.dumps({"status": "validated", "engagement": engagement["name"], "targets": engagement["targets"], "agents": ["Planning", "Recon", "Web", "Linux", "ATT&CK analyst", "Reviewer", "Reporting"], "execution": "Evidence analysis only; no live target connections"}, indent=2))
                return
            if not args.research_only and not os.getenv("LLM_API_KEY"):
                raise ValueError("Set LLM_API_KEY in .env before running the agents")
        if args.command == "assess":
            if not os.getenv("LLM_API_KEY"):
                raise ValueError("Set LLM_API_KEY in .env before running the agents")
            from .target import collect_target
            print('Collecting HTTP evidence from the target...')
            engagement = collect_target(args.target, name=args.name, objective=args.objective)
        from .knowledge import Knowledge
        knowledge = Knowledge(os.getenv("VECTORDB_PATH", "data/chroma"))
        if args.command == "ingest":
            print(json.dumps(knowledge.ingest(args.file), indent=2))
        elif args.command == "search":
            print(json.dumps(knowledge.search(args.query), indent=2))
        else:
            folder = args.output / (datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid4().hex[:8])
            folder.mkdir(parents=True)
            (folder / 'engagement.json').write_text(json.dumps(engagement, indent=2))
            # Apply the same validation to generated and user-supplied engagements.
            engagement = load_engagement(folder / 'engagement.json')
            audit = {"engagement": engagement, "model": os.getenv("LLM_MODEL", "openai/gpt-4.1-mini"), "knowledge": knowledge.collection.metadata, "status": "researching", "tasks": []}

            audit['collection_method'] = 'http_get' if args.command == 'assess' else 'supplied_evidence'

            execution = None
            if args.command == 'assess':
                from .execution import ScriptRunner
                execution = ScriptRunner(folder, engagement)

            def save_task(output):
                audit['tasks'].append({'agent': output.agent, 'output': output.raw})
                if execution is not None:
                    inputs['engagement'] = json.dumps(engagement)
                    for pending in getattr(crew, 'tasks', []):
                        if pending.output is None:
                            pending.interpolate_inputs_and_add_conversation_history(inputs)
                audit['retrievals'] = knowledge.retrievals
                (folder / 'audit.json').write_text(json.dumps(audit, indent=2))

            budget_guard = None
            try:
                from .research import prepare_research, TOPICS
                print('Researching the local ATT&CK database before LLM execution...')
                research = prepare_research(knowledge, engagement)
                (folder / 'research.json').write_text(json.dumps(research, indent=2))
                print(f"Local research: {len(research['queries'])} queries, {len(research['sources'])} unique sources, {len(research['relationships'])} linked records.")
                if args.research_only:
                    audit['status'] = 'research_complete'
                    print(f"Research: {folder / 'research.json'}")
                    return
                from .crew import build_crew
                crew = build_crew(knowledge, research=research, task_callback=save_task, execution=execution)
                inputs = {'engagement': json.dumps(engagement)}
                for index, role in enumerate(TOPICS):
                    inputs['knowledge_' + str(index)] = json.dumps(research['agent_packets'][role])
                audit['status'] = 'running'
                from .budget import request_budget
                with request_budget(crew.agents[0].llm, source_packets=[value for key, value in inputs.items() if key.startswith('knowledge_')]) as budget_guard:
                    result = crew.kickoff(inputs=inputs)
                audit['tasks'] = [{"agent": t.agent, "output": t.raw} for t in result.tasks_output]
                from .reporting import AssessmentReport, validate_report, render_report
                report = result.pydantic or AssessmentReport.model_validate_json(result.raw)
                try:
                    validate_report(report, engagement, knowledge.retrievals)
                except ValueError as exc:
                    audit['validation_error'] = str(exc)
                    raise
                (folder / "report.json").write_text(report.model_dump_json(indent=2))
                (folder / "report.md").write_text(render_report(report))
                audit['status'] = 'provenance_validated'
            except Exception as exc:
                audit['status'] = 'failed'
                from .diagnostics import safe_error
                audit['error'] = safe_error(exc)
                audit['error_type'] = type(exc).__name__
                from .budget import RequestBudgetError
                if isinstance(exc, RequestBudgetError):
                    audit['validation_error'] = str(exc)
                raise ValueError(f"Assessment failed: {audit['error']}\nAudit: {folder / 'audit.json'}") from None
            finally:
                if execution is not None:
                    audit['executions'] = execution.records
                    (folder / 'engagement.json').write_text(json.dumps(engagement, indent=2))
                if budget_guard is not None:
                    audit['budget_adjustments'] = budget_guard.adjustments
                audit['retrievals'] = knowledge.retrievals
                (folder / "audit.json").write_text(json.dumps(audit, indent=2))
                from .artifacts import export_scripts
                print(f"Scripts: {export_scripts(folder, audit)}")
            print(f"Report: {folder / 'report.md'}")
    except (ValueError, OSError) as exc:
        parser.exit(1, f"Error: {exc}\n")

if __name__ == "__main__":
    main()
