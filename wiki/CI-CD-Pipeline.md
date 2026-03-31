# CI/CD Pipeline

CNDS uses a Jenkins pipeline defined in `Jenkinsfile`.

## Pipeline Stages

### 1. Checkout
Pulls the latest code from Gitea.

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
- JUnit XML output for Jenkins test reporting
- Coverage report

### 5. SonarQube Analysis
Pushes static analysis results to SonarQube (project key: `cnds`). Configuration is in `sonar-project.properties`.

### 6. Push to Registry
Pushes the built image to the private Docker registry at `192.168.1.86:5000`.

## Configuration Files

| File | Purpose |
|---|---|
| `Jenkinsfile` | Pipeline definition |
| `Dockerfile` | Container build (pins `torch==2.5.1+cpu`, default CMD starts API) |
| `sonar-project.properties` | SonarQube project settings |
| `.dockerignore` | Files excluded from Docker build context |
