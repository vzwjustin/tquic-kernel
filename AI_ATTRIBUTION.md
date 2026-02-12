# AI Attribution Guide for TQUIC Kernel Development

This guide explains how to properly attribute AI assistance in commits while maintaining your authorship, per Linux kernel official policy.

## Quick Reference

### Your Commit Signature Block

```
Assisted-by: Claude:claude-sonnet-4-5-20250929
Signed-off-by: Your Name <your.email@example.com>
```

Replace "Your Name" and "your.email@example.com" with your actual git identity.

## What This Means

### You Remain the Author ✅

- **Author field**: Your name (as configured in git)
- **Copyright**: You hold the copyright
- **Responsibility**: You accept full accountability
- **Signed-off-by**: You certify Developer Certificate of Origin (DCO)

### AI Assistance is Transparent ✅

- **Assisted-by**: Declares Claude helped with code generation/review
- **Model version**: Tracks which AI version was used (for kernel development history)
- **Optional tools**: Can add checkpatch, sparse, smatch if used

## Commit Examples

### Basic Bug Fix

```bash
git commit -m "$(cat <<'EOF'
net/quic: Fix null pointer dereference in stream cleanup

Check stream pointer before dereferencing in cleanup path.
Prevents crash when connection is closed during stream setup.

Assisted-by: Claude:claude-sonnet-4-5-20250929
Signed-off-by: Justin Smith <justin@example.com>

https://claude.ai/code/session_XXXXX
EOF
)"
```

### Feature Implementation

```bash
git commit -m "$(cat <<'EOF'
net/quic: Implement weighted round-robin scheduler

Add new multipath scheduler that distributes packets across
paths based on configurable weights. Allows bandwidth-proportional
load distribution for asymmetric links.

Assisted-by: Claude:claude-sonnet-4-5-20250929 checkpatch
Signed-off-by: Justin Smith <justin@example.com>

https://claude.ai/code/session_XXXXX
EOF
)"
```

### Refactoring

```bash
git commit -m "$(cat <<'EOF'
net/quic: Refactor congestion control state machine

Split monolithic congestion control function into separate
handlers for each state. Improves readability and makes it
easier to add new congestion control algorithms.

No functional changes.

Assisted-by: Claude:claude-sonnet-4-5-20250929
Signed-off-by: Justin Smith <justin@example.com>

https://claude.ai/code/session_XXXXX
EOF
)"
```

## When to Add "Assisted-by"

### Include "Assisted-by" when:
- ✅ AI helped write any part of the code
- ✅ AI helped debug or identify the issue
- ✅ AI suggested the implementation approach
- ✅ AI helped refactor or restructure code
- ✅ AI helped with error handling or edge cases

### Do NOT add "Assisted-by" when:
- ❌ AI only answered general questions (not code-specific)
- ❌ AI only explained existing code (no changes made)
- ❌ You wrote 100% of the code yourself

## Adding Analysis Tools to Attribution

If you use static analysis tools during development, add them:

```
Assisted-by: Claude:claude-sonnet-4-5-20250929 checkpatch sparse
```

Common kernel tools:
- `checkpatch` - scripts/checkpatch.pl
- `sparse` - Semantic parser for C
- `smatch` - Static analysis tool
- `coccinelle` - Semantic patch tool
- `clang-tidy` - Clang static analyzer

**Do NOT list**: git, gcc, make, vim, emacs (basic development tools)

## Legal Requirements

Per Linux kernel DCO (Developer Certificate of Origin):

1. **You certify** that you have the right to submit the code
2. **You certify** that the code is under GPL-2.0-only
3. **You accept** full responsibility for the contribution
4. **AI cannot certify** - Only humans can add Signed-off-by

## Pull Request / Patch Series

When submitting multiple commits, each commit should have its own attribution:

```
commit 3: net/quic: Add scheduler tests
    Assisted-by: Claude:claude-sonnet-4-5-20250929
    Signed-off-by: Justin Smith <justin@example.com>

commit 2: net/quic: Implement weighted scheduler
    Assisted-by: Claude:claude-sonnet-4-5-20250929 checkpatch
    Signed-off-by: Justin Smith <justin@example.com>

commit 1: net/quic: Add scheduler infrastructure
    Assisted-by: Claude:claude-sonnet-4-5-20250929
    Signed-off-by: Justin Smith <justin@example.com>
```

Cover letter should mention AI assistance:

```
This series adds a new weighted round-robin scheduler for TQUIC multipath.
Development was assisted by Claude AI (claude-sonnet-4-5-20250929), with
all code reviewed and verified by the author.
```

## Upstream Submission

When submitting to upstream Linux kernel:

1. Ensure all commits have proper Assisted-by tags
2. Include your Signed-off-by on every commit
3. Mention AI assistance in cover letter
4. Be prepared to explain and defend all code changes
5. Accept maintainer feedback and make revisions

## References

- [Documentation/process/coding-assistants.rst](https://github.com/torvalds/linux/blob/master/Documentation/process/coding-assistants.rst) - Official guidelines
- [Documentation/process/submitting-patches.rst](https://www.kernel.org/doc/html/latest/process/submitting-patches.html) - Patch submission
- [Developer Certificate of Origin](https://developercertificate.org/) - DCO details

## Your Git Configuration

Make sure your git identity is correctly set:

```bash
git config user.name "Your Real Name"
git config user.email "your.email@example.com"
```

This will be used for both Author and Signed-off-by fields.
