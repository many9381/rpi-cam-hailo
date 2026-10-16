# Repository address redaction — 2026-10-16

Actual local device addresses were copied into diagnostic reports and test
fixtures. The prior publication check looked for credentials, keys and binary
inputs but did not detect embedded site addresses. That check was insufficient.

The audit covered all 230 commits reachable from the firmware repository's
advertised branches/tags and all 69 corresponding Yocto commits. Ten current
firmware files (seven reports and three test fixtures), and four companion
Yocto files, contained the affected network. Address literals in all reachable
blob history and commit/tag messages were replaced with documentation-only
examples. Other private-address literals examined were synthetic rate-limiter
and setup-policy fixtures, not identified deployment addresses.

Production application sources are unchanged; the same example substitution
is applied to the layer patch and provisioning tests. Rewritten commit IDs
require the companion recipe to use the sanitized counterpart of its original
base revision. The existing patch sequence remains necessary. Historical image
IDs, measured binary hashes and private artifact evidence are preserved; old
source digest records describe their original validation inputs, not a fresh
validation of rewritten Git history. The installed Pi requires no change.

Both repositories' `validated-20261016T111625Z` tags identify the sanitized
checkpoint, including this documentation and the companion source-pin update.
Do not merge or push an old clone into the cleaned history. Re-clone other
working copies or carefully transplant only reviewed changes. This also
applies to older development checkouts embedded in images.

## GitHub retention boundary

Rewriting branches/tags does not guarantee removal of cached commit views,
server-side unreachable objects, forks or other clones. The SSH-advertised
refs contained no PR refs. Unauthenticated REST requests returned 404; this
is not proof that issues, Actions artifacts, forks or cached objects are absent.
Authenticated inspection and GitHub Support's retention cleanup remain a
separate step. No claim of complete server-side erasure is made here.

The official [GitHub removal procedure](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository)
explains cache/PR cleanup and Support's eligibility limits. Private scan,
commit-map, remote-ref verification and Support request material are kept in
`.state/privacy-cleanup-2026-10-16/` in the companion workspace.
