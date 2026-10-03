"""HTTP API layer: thin routes over MirageRuntime.

Routes never touch storage, the bus, or repositories directly — they
validate input at the boundary, call the runtime, and serialize its
typed dataclasses. Nothing here executes attacker input on the host.
"""
