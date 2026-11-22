"""Live remote mode (M6, docs/remote-live-design.md): the only code in this package that can reach a network is `collector.py`, and
it runs inside an isolated container (D-E38). Everything else is controller-side policy, bookkeeping and validation, and opens
no socket except `resolver.py`, which resolves each declared host once (D-E39)."""
