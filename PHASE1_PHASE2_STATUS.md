# CLOUDGAURD — Phase 1 / Phase 2 handoff

## Changes in this repair pass

- Fixed Dockerfile readiness regular expressions so `FROM` and `CMD`/`ENTRYPOINT` lines are actually recognized.
- Made Maven detection explicitly handle a `pom.xml` at the repository root or in a nested module (such as `myproject/pom.xml`).
- Tightened GitHub URL validation for the scan endpoint.
- Added `backend/requirements.txt`.
- Made the frontend API URL configurable through `VITE_API_BASE_URL`, retaining `http://127.0.0.1:8000` as the local default.
- Added regression tests for nested Maven, Dockerfile readiness, missing manifests, and security gating.

## Verification completed in the repair environment

- Python syntax compilation: passed for `backend/main.py` and `backend/deployment.py`.
- Nested Maven readiness test: passed.
- Dockerfile readiness test: passed.
- Archived AQUAGUARD repository: detected `maven`, readiness `READY` when security status is `PASSED`.

The actual Docker image build and a live remote GitHub clone were not run in this environment. They must be verified on your Windows machine with Git and Docker Desktop available.

## Local commands (PowerShell)

Run from the project root:

```powershell
cd C:\Users\Administrator\Desktop\CLOUDGAURD
python -m pip install -r backend\requirements.txt
python -m unittest backend.tests.test_readiness -v
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

In a second terminal:

```powershell
cd C:\Users\Administrator\Desktop\CLOUDGAURD\frontend
npm ci
$env:VITE_API_BASE_URL = "http://127.0.0.1:8000"
npm run dev -- --host 127.0.0.1 --port 5174
```

Check the API:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/health
Invoke-RestMethod http://127.0.0.1:8000/docs
```

Use the dashboard to scan AQUAGUARD. Expected readiness detection is `build_method: "maven"` and status `READY` if the current security gate passes. `READY` means the build path was detected; it does not mean a Maven build was executed.

## Docker verification

Check Docker is running:

```powershell
docker version
```

If the target repository has a root Dockerfile, use the dashboard/API build step and confirm the result is successful before attempting deployment. A project with no Dockerfile needs a generated/configured Dockerfile or a supported build-specific workflow; detection alone does not create one.

## Notes before Render

The deployment module currently invokes the local Docker CLI and returns `localhost` URLs. That is suitable only for local experiments. It is not yet a cloud deployment integration. Before Render, the target deployment workflow must be connected to a supported cloud provider/API, long-running jobs must be moved out of blocking API requests, and the API must not accept arbitrary filesystem paths from untrusted clients.
