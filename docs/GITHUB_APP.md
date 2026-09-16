# GitHub App deployment

The PatchProof App receives signed pull-request webhooks, obtains a short-lived installation token, downloads changed files and dependency manifests, applies repository or organization policy, scans without executing repository code, and posts inline review comments.

## Required configuration

| Variable | Purpose |
|---|---|
| `GITHUB_APP_ID` | Numeric GitHub App ID |
| `GITHUB_APP_PRIVATE_KEY` | PEM key; escaped newlines are accepted |
| `GITHUB_WEBHOOK_SECRET` | Webhook HMAC secret |
| `GITHUB_API_URL` | Optional GitHub API base URL |
| `PATCHPROOF_POLICY_REPOSITORY` | Optional `owner/repo` containing organization `.patchproof.yml` |
| `PORT` | HTTP port, default `3000` |

Create the App with read-only Contents and Metadata plus read/write Pull Requests. Subscribe only to pull-request events. Set the webhook to `/webhook`; `/health` is the liveness endpoint.

```bash
docker build -f app/Dockerfile -t patchproof-app .
docker run --read-only --cap-drop ALL --security-opt no-new-privileges \
  -p 3000:3000 --env-file .env patchproof-app
```

## Organization policies

Set `PATCHPROOF_POLICY_REPOSITORY=your-org/security-policy`. If the scanned repository does not contain `.patchproof.yml`, the App loads it from that policy repository. Repository policy takes precedence. Protect both repositories with CODEOWNERS and branch protection.

The service intentionally does not execute proof manifests. Executable proofs belong in a separate, explicitly trusted workflow described in [THREAT_MODEL.md](../THREAT_MODEL.md).
