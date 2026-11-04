# Security Policy

## Supported versions

| Version | Supported |
|---|---|
| 2.0.x (including release candidates) | Yes |
| `master` | Yes |
| 1.x | No: upgrade to 2.0 (see the "Upgrading to 2.0" section of `doc/deployment.md`) |

## Reporting a vulnerability

Please **do not open a public issue** for a vulnerability.

Report it privately through GitHub: on the [repository's Security tab](https://github.com/RobertoDeLaCamara/Cognitive-Intrusion-Detection-System/security/advisories/new), choose "Report a vulnerability". Include:

- what is affected (endpoint, module, configuration) and the version or commit;
- the steps or a request that reproduces it;
- the impact you see (for example "an unauthenticated caller can create an admin user").

This is a one-maintainer project, so replies are best effort: you can expect an acknowledgement within about a week, and a fix or a written assessment as soon as it can be made. Fixes are published with a CHANGELOG "Security" entry; reporters are credited unless they ask not to be.

## Scope and trust boundaries

CNDS is meant for a network you control. These points decide what counts as a vulnerability:

- **Authentication is mandatory.** The API refuses to start unless `API_KEY` or `JWT_SECRET` is set, or `AUTH_DISABLED=true` (lab use only; it logs a warning). An `API_KEY` caller is admin-equivalent. A route that is reachable without a credential in a mode that should require one is a vulnerability (for example the `/api/auth/users` exposure fixed in the `[Unreleased]` changelog).
- **The MLflow registry is trusted.** The baseline and supervised engines load model artifacts with `joblib` / `torch` from MLflow. Joblib files are pickles, so anyone who can write to your MLflow tracking server or its artifact store can run code in the detector and API. Keep MLflow on a trusted network with write access limited to the trainer. CNDS does not yet verify the integrity of these artifacts.
- **Capture needs raw-socket privileges.** The detector runs with `NET_RAW`/`NET_ADMIN` and host networking. It parses attacker-controlled packets; a crash or memory problem triggered by crafted traffic is in scope.
- **The Guardian can block traffic.** With `GUARDIAN_ENABLED=true` it blocks source IPs at the DNS level. Keep its whitelist current: a spoofed source address could otherwise get a legitimate host blocked. Reports about bypassing the whitelist or the rollback are in scope.
- **Secrets** (`API_KEY`, `JWT_SECRET`, database and Telegram credentials) belong in `.env`, which is git-ignored. A secret committed to the repository or written to logs is a vulnerability.

Out of scope: attacks that need a valid admin credential or write access to MLflow/the database (see above), denial of service by saturating the monitored link, and findings about the synthetic demo models.
