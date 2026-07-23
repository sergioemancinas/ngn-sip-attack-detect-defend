<!-- Do not use this for security fixes to undisclosed vulnerabilities. See SECURITY.md. -->

## What and why

<!-- What does this change and what problem does it solve? -->

## Verification

<!-- How did you verify it? Tick what applies. -->

- [ ] `make e2e` passes (or the affected ring verified with row evidence)
- [ ] `docker compose -f <file> config` validates any changed compose file
- [ ] `shellcheck` clean on any changed scripts
- [ ] `cd ml && python -m pytest` passes if ML code changed
- [ ] No real secrets added; placeholders only

## Reproducibility / metrics

- [ ] No reported metric changed, **or** the change is backed by a committed source
- [ ] Dependencies / image tags remain pinned

## Notes

<!-- Anything a reviewer should know: trade-offs, follow-ups, internet-exposure implications. -->
