# User guide

## 1. Generate

Open the SovereignRoot website over HTTPS. Choose a baseline and answer each question.

Do not enter passwords, recovery phrases, API keys, private keys or authentication tokens anywhere in the questionnaire.

## 2. Sign

Choose a strong passphrase. The browser creates a signing identity and generates three downloads:

- `sovereignty.json` — signed root policy;
- `sovereignroot-key.json` — encrypted private signing key;
- `SOVEREIGNROOT-INSTALL.md` — installation/integration guidance.

## 3. Back up the key

Keep at least two offline copies of `sovereignroot-key.json`. Preserve the passphrase separately.

Do **not** put the key bundle in:

- an agent workspace;
- a Git repository;
- a chat upload;
- AI memory;
- an email account the agent can read;
- a cloud-sync directory accessible by the agent.

## 4. Place the public policy

Recommended conventional locations:

- Windows: `%USERPROFILE%\\.sovereignroot\\sovereignty.json`
- macOS/Linux: `~/.sovereignroot/sovereignty.json`

Make the public policy read-only where practical.

## 5. Integrate enforcement

A compatible runtime must verify and evaluate the policy before tool execution. If your current AI product offers no such extension point, the file is advisory only.

## 6. Verify anytime

Use the site's Verify section or the reference verifier to detect tampering.

## 7. Replace the root

Load your existing encrypted signing key in the generator. Optionally load the previous valid `sovereignty.json` so the new policy records its predecessor payload hash. Then generate the replacement.
