"""Command-line entry point: run the guarded triage loop and print the report."""

from __future__ import annotations

import argparse
from pathlib import Path

from . import (
    ActionGuard,
    AuditLog,
    TriagePipeline,
    default_allowed_services,
    render_report,
    sample_alert_stream,
)
from .backends import (
    AnthropicBackend,
    GeminiBackend,
    OllamaBackend,
    StubBackend,
)

_BACKENDS = {
    "stub": StubBackend,
    "gemini": GeminiBackend,
    "anthropic": AnthropicBackend,
    "ollama": OllamaBackend,
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="alertward", description=__doc__)
    parser.add_argument(
        "--backend",
        choices=sorted(_BACKENDS),
        default="stub",
        help="planner backend (default: stub, fully offline)",
    )
    parser.add_argument(
        "--max-auto",
        type=int,
        default=3,
        help="max read-only actions auto-executed per run",
    )
    parser.add_argument(
        "--audit",
        type=Path,
        default=None,
        help="write the JSONL audit trail to this path",
    )
    args = parser.parse_args(argv)

    pipeline = TriagePipeline(
        guard=ActionGuard(
            allowed_services=default_allowed_services(),
            max_auto_actions=args.max_auto,
        ),
        backend=_BACKENDS[args.backend](),
        audit=AuditLog(path=args.audit),
    )
    result = pipeline.run(sample_alert_stream())
    pipeline.audit.close()
    print(render_report(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
