# CI/CD Pipeline

CNDS uses a CI/CD pipeline defined in `CI/CDfile`.

## Pipeline Stages

### 1. Checkout
Pulls the latest code from Git Server.

### 2. Build Image
Builds a Docker image tagged with the build number and `latest`:
```
docker build -t cnds:<build_number> -t cnds:latest .
```

### 3. Code Quality (parallel)

Two jobs run in parallel:

- **Lint** — `flake8` with max line length 120
- **Security** — Safety dependency audit against known vulnerability databases

### 4. Run Tests
Executes `pytest` inside the container with:
- JUnit XML output for CI/CD test reporting
- Coverage report

### 5. Quality Analysis Analysis
Pushes static analysis results to Quality Analysis (project key: `cnds`). Configuration is in `sonar-project.properties`.

### 6. Push to Registry
Pushes the built image to the private Docker registry at `[REGISTRY_IP]:5000`.

## Configuration Files

| File | Purpose |
|---|---|
| `CI/CDfile` | Pipeline definition |
| `Dockerfile` | Container build (pins `torch==2.5.1+cpu`, default CMD starts API) |
| `sonar-project.properties` | Quality Analysis project settings |
| `.dockerignore` | Files excluded from Docker build context |
