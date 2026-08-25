# AsterCode deterministic resume demo

This deliberately small project contains one arithmetic regression in
`calculator.py`.  The acceptance flow copies this fixture into a new temporary
Git repository and asks AsterCode to:

1. inspect the implementation and regression checks;
2. diagnose the subtraction/addition mismatch;
3. apply one minimal patch through the approval policy;
4. persist the exact process approval, close the first orchestrator, rebuild all
   runtime objects, and resume from SQLite;
5. run `python test_calculator.py` inside the attested, network-disabled Docker
   sandbox;
6. capture the exact Git diff and audit-chain evidence.

The fixture has no third-party dependencies and the deterministic provider does
not read an API key or contact a model endpoint.  Run it from the AsterCode
repository root:

```powershell
uv run python scripts/resume_demo.py
```

For CI or hosts without Docker, the explicit `--backend fake` mode uses a
clearly labelled test-only executor.  It verifies the exact fixture bytes but
does not claim that a real process or sandbox ran:

```powershell
uv run python scripts/resume_demo.py --backend fake --cleanup
```

To prepare a fresh buggy project for an optional live-model demonstration
without reading or printing any key:

```powershell
uv run python scripts/resume_demo.py --prepare-only
cd <the workspace path printed by the command>
aster
```
