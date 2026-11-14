# CI/CD Pipeline

CNDS uses a Jenkins declarative pipeline defined in `Jenkinsfile`. It runs on the agent labelled `agent-45` and keeps the last 5 builds (60-minute timeout).

## Pipeline Stages

### 1. Checkout
Checks out the commit with `checkout scm`.

### 2. Build Image
Builds the Docker image `192.168.1.147:5000/cnds:<tag>`. On `master` (or the legacy single-branch job, where `BRANCH_NAME` is unset) the tag is the build number; on other branches and PRs it is `<branch>-<build>`.

### 3. Code Quality (parallel)

- **Lint** — `ruff check src/ tests/` with the rules in `ruff.toml` (blocking: any finding fails the build)
- **Security** — `safety check -r requirements.txt` (advisory: `|| true`)

### 4. Run Tests
Runs `python -m pytest tests/ -v` inside the image (with `DATABASE_URL` pointing at a temporary SQLite file), producing JUnit XML and `coverage.xml`; both are collected and the coverage report is archived. The stage fails if total coverage of `src` is below 75 % (`--cov-fail-under=75`; CI measured 76 % when the gate was added).

### 5. SonarQube Analysis
Pushes static analysis and coverage to SonarQube (project key `cnds`, sources `src`, tests `tests`, Python 3.11). Settings are in `sonar-project.properties` and the stage arguments.

### 6. Claude PR review (advisory)
Runs only for pull requests (`changeRequest()`). The `Claude PR review (advisory)` stage runs `python3 /opt/hf/ci/pr_review.py` inside the `claude-runner` image from the registry, with the Jenkins credentials `anthropic-api-key` and `gitea-factory-bot`, and posts a `claude -p` review on the Gitea PR using a spend cap (`HF_REVIEW_BUDGET`, 0.50); `costs.jsonl` and `pr-review.result.json` are archived. It is wrapped in `catchError`, so it never fails the build (at worst the stage is marked unstable, for example when credentials are missing).

### 7. Push to Registry
Tags `:latest` and pushes `cnds:<tag>` and `cnds:latest` to the private registry at `192.168.1.147:5000`, each push wrapped in `retry(4)` (up to 4 attempts) that sleeps 90 s after a failed attempt before the next one. The wait is deliberate: the registry on Magua can need longer than the Docker client's 30 s response-header timeout to commit a big new layer. The client gives up but the registry still finishes, so an immediate retry re-uploads the same layer and times out again; after the pause the next attempt finds the layer already present. This stage runs **only on `master`** (or the legacy single-branch job): PR and feature-branch builds never reach the registry.

The `Build Image arm64` stage is present but commented out; it needs an aarch64 agent labelled `raspi-62`.

After every run the `post` block removes the test artefacts, the local image and the Sonar volume, and cleans the workspace.

## Configuration Files

| File | Purpose |
|---|---|
| `Jenkinsfile` | Pipeline definition |
| `Dockerfile` | Container build (Python 3.11; installs hash-pinned dependencies in three layers, `requirements-lock-{torch,sci,rest}-<arch>.txt` (torch 2.6.0 CPU wheels, numeric stack, everything else, on amd64/arm64), so no single layer is large enough to hit the registry commit timeout; the parts are generated from `requirements-lock-<arch>.txt` by `scripts/split_lock.py`, run by `scripts/lock_requirements.sh`, and must not be edited by hand; default CMD starts the API; `dashboard` stage adds Streamlit) |
| `sonar-project.properties` | SonarQube project settings |
| `.dockerignore` | Files excluded from Docker build context |
