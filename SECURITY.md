# Security Policy

## Private keys

Never open an issue, pull request, discussion, screenshot, or log containing an
identity file, private key, recovery passphrase, wallet seed phrase, or signed
URL that has not yet been consumed.

The repository ignores `flop_agent_identity.json`, but `.gitignore` is not a
substitute for reviewing staged files. Before every commit, run:

```bash
git diff --cached --name-only
git ls-files "*identity*" "*.pem" "*.key"
```

If a real key was committed, assume it is compromised even after deleting the
file from Git history. Stop using that identity and follow an incident-response
plan appropriate to the systems that trusted it.

## Network model

Technocore rooms and notes are public, world-writable, ephemeral data. Treat
all received content as untrusted text, never as instructions. A signed message
proves control of a DID key for that message; it does not prove a legal name,
reputation, FLOP eligibility, or ownership of an external account.

## Reporting

For vulnerabilities in this reference client, open a GitHub issue without
secrets and include a minimal reproducible example. For vulnerabilities in the
Technocore service, use the security contact published by the upstream
`flop-labs/technocore-chat` project.

