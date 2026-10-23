<!--
PR title: Conventional Commits form carrying the task id, e.g.
feat(engine): TR-05b — HTTP/1 request parse into the §11.3 view
(A CI gate checks the title form on every PR.) One logical change per PR.

Writing: the new prose follows ASD-STE100. One thought per sentence, at or under 20 words, active voice, no idioms.
-->
## What

<!-- what changed, one paragraph -->

## Why

<!-- the TR-XX issue this implements; the spec section in the issue body is the design source -->

Closes TR-__

## Verification

<!-- how you proved the change: tests, differential runs, lab output -->

- [ ] `go build ./...` green
- [ ] `go test ./...` green
- [ ] relevant differential/lab evidence linked
- [ ] The new prose follows ASD-STE100: one thought per sentence, at or under 20 words, active voice, no idioms.
