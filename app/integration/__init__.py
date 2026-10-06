"""T4 integration layer — the seams between T1/T2/T3.

Only this package knows about more than one team's internals. The rest of
the merged app keeps team boundaries: T1's runtime calls handlers through
its own ``CommandHandler`` protocol; this package supplies the handlers
that adapt T3's pipeline (and through it, T2's agent) to that protocol.

Guarantees carried through the adapter:
- No host execution: the adapted handlers call T3's ``sandbox.execute``
  / ``llm_engine.generate_response`` / ``process_command`` — the same
  single-choke-point code paths the standalone pipeline uses.
- session_id passthrough: T2's engine accepts ``session_id`` so agent
  events land in the same session record (T2's own optional-arg change).
- Errors are converted to :class:`CommandResult` failures per T1's
  dispatcher contract — handlers must return, not raise.
"""
from app.integration.pipeline_handler import (  # noqa: F401
    T3PipelineHandler,
    attach_default_handlers,
)

__all__ = ["T3PipelineHandler", "attach_default_handlers"]
