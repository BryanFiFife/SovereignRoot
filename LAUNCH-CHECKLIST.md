# SovereignRoot — Launch Checklist

## Hosting

- [ ] Create a Cloudflare Pages project.
- [ ] Confirm the final project name / hostname.
- [ ] Run `python tools/set-domain.py https://YOUR-HOSTNAME` if the default hostname changes.
- [ ] Deploy the package root with no build command and no environment variables.
- [ ] Confirm `_headers` is active in the deployed response headers.
- [ ] Confirm `robots.txt` and `sitemap.xml` use the live hostname.

## Product smoke test in a real browser

- [ ] Complete all seven generator steps using the Balanced preset.
- [ ] Create a new signing identity.
- [ ] Download `sovereignty.json`.
- [ ] Download `sovereignroot-key.json` and confirm it is encrypted.
- [ ] Download the generated install guide.
- [ ] Drop the generated `sovereignty.json` into the verifier and confirm VALID.
- [ ] Edit one byte in a copy of the signed policy and confirm verification fails.
- [ ] Import the encrypted key with the correct passphrase.
- [ ] Confirm the wrong passphrase is rejected.
- [ ] Generate a replacement policy using a previous policy and confirm continuity is shown.
- [ ] Test on desktop and mobile widths.

## Trust / standards

- [ ] Publish the source repository if public protocol adoption is the goal.
- [ ] Publish a tagged v0.1.1 release and ZIP checksum.
- [ ] Do not claim IETF, W3C, NIST or vendor endorsement.
- [ ] Do not claim trademark clearance until independently checked.
- [ ] Keep the wording that a policy file alone cannot force an incompatible AI to obey it.
- [ ] Never tell users to place secrets, passwords or recovery phrases in `sovereignty.json`.

## Next protocol work before v1.0

- [ ] Stable action vocabulary / registry.
- [ ] Cross-language canonical test vectors.
- [ ] Formal policy-strength comparison for tightening vs weakening replacements.
- [ ] Recovery / revocation design.
- [ ] Optional hardware-backed signing profile.
- [ ] Conformance suite and badge criteria.
- [ ] First hard-enforcement runtime adapter.
