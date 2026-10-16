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
Authenticated inspection is a separate scope. The user explicitly removed
the GitHub Support purge request from required work on 2026-10-16. No request
was submitted, and the unused private request draft was deleted. Do not list
Support cleanup as pending unless the user changes that decision. Previously
verified retention of old objects remains a known boundary; this exclusion
does not establish complete server-side erasure.

The subsequent PR/fork/Actions follow-up found no local API credentials and
requested a GitHub plugin connection. The user declined that workflow on
2026-10-16 before a connection was confirmed. Plugin setup and its dependent
audit are excluded from active work unless explicitly requested again. No
authenticated surface inspection or deletion was performed, and no alternative
login flow was started. Preserve this as unverified scope, not a passing audit
or a pending demand to connect the plugin.

The official [GitHub removal procedure](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository)
explains cache/PR cleanup and Support's eligibility limits. Private scan,
commit-map and remote-ref verification material are kept in
`.state/privacy-cleanup-2026-10-16/` in the companion workspace.

## Existing clone follow-up

The user confirmed that the build PC and the Pi are the only machines with
working clones. The Pi development checkout now uses sanitized base
`a6364ff4c8161334fdf89b54b8d2eeb4ec55a32c`, retaining the seven image patches
as working-tree changes. Its 462 files matched the expected patched source
after address normalization; no additional user changes were found. Only
three test-fixture files needed address replacement. All available Git
objects were scanned with zero affected-address matches, Git integrity
passed, and the former base object is absent. The installed camera service
remained active with the same process ID throughout; binaries, settings and
credentials were not changed. This is source-maintenance verification, not
a new camera/Hailo acceptance run.

On the build PC, the earlier web-validation clone, three BitBake source
checkouts and two Git download caches were refreshed to sanitized history.
Source files were preserved except for the same address normalization, and
the source checkouts no longer depend on the former object caches. Download
completion markers were invalidated for the next fetch. The separate Yocto
linked worktree shares the already-cleaned Git store; its existing tracked
and untracked changes were preserved. Temporary old Git stores were deleted
only after file and object verification passed.

Historical private images, packages and provenance remain unchanged; restoring
an older image also restores its older embedded development checkout. Refresh
that checkout before publishing from it, or build with the sanitized source
pin and a fresh build ID. No image rebuild, SSD installation, QEMU build or
device reboot was performed for this follow-up. Private verification is in
the companion workspace's `.state/privacy-cleanup-2026-10-16/clone-refresh/`.
