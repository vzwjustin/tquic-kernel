# CLAUDE.md - TQUIC Kernel Project

## Project Overview

TQUIC (True QUIC) is a kernel-level QUIC implementation for Linux, providing multipath WAN bonding capabilities. The core implementation is in `net/quic/`.

## Key Directories

```
net/quic/           # TQUIC implementation (main codebase)
├── ack.c           # ACK frame processing
├── cong.c          # Congestion control
├── connection.c    # Connection management
├── crypto.c/h      # Cryptographic operations
├── flow.c          # Flow control
├── loss.c          # Loss detection (RFC 9002)
├── output.c        # Packet transmission
├── packet.c        # Packet parsing
├── path.c          # Path management
├── protocol.c      # Protocol state machine
├── socket.c        # Socket interface
├── stream.c        # Stream management
├── timer.c         # Timer handling
├── tquic_bonding.c/h   # Multipath bonding
├── tquic_failover.c/h  # Failover logic
├── tquic_netlink.c     # Netlink interface
└── sched_*.c       # Multipath schedulers (aggregate, blest, ecf, minrtt, weighted)

kernel/             # Core kernel (upstream Linux - avoid modifying)
lib/                # Kernel libraries (upstream Linux - avoid modifying)
include/            # Headers (modify only for QUIC additions in include/net/quic/)
```

## Coding Standards

This is Linux kernel code. Follow kernel coding style:

- Tab indentation (not spaces)
- 80 character line limit (flexible for readability)
- K&R brace style
- Run `scripts/checkpatch.pl --strict -f <file>` before committing
- Use kernel APIs (kmalloc, kfree, list_head, etc.)

## AI Coding Assistant Guidelines

Per [Documentation/process/coding-assistants.rst](https://github.com/torvalds/linux/blob/master/Documentation/process/coding-assistants.rst), this project follows official Linux kernel requirements for AI-assisted development:

### Attribution Format

All commits where AI assists development MUST include an `Assisted-by` trailer:

```
Assisted-by: Claude:claude-sonnet-4-5-20250929
```

**Format**: `Assisted-by: AGENT_NAME:MODEL_VERSION [TOOL1] [TOOL2]`

- Include agent name and specific model version
- Optionally list specialized analysis tools (checkpatch, sparse, smatch, coccinelle, clang-tidy)
- Do NOT list basic tools (git, gcc, make, editors)

### Developer Responsibility

**CRITICAL**: The human developer (you) remains fully responsible for ALL contributions:

- ✅ **You are the author** - Your name goes in `Author:` field
- ✅ **You sign off** - You add `Signed-off-by:` certifying Developer Certificate of Origin
- ✅ **You review thoroughly** - AI-generated code must be carefully reviewed before submission
- ✅ **You accept accountability** - Full legal and technical responsibility for all code
- ❌ **AI cannot sign off** - AI agents cannot add `Signed-off-by` tags

### Licensing Compliance

- All code must be GPL-2.0-only compatible
- Apply appropriate SPDX license identifiers
- Consult Documentation/process/license-rules.rst for details

### Commit Message Template

```
<subject line>

<detailed description>

Assisted-by: Claude:claude-sonnet-4-5-20250929
Signed-off-by: Your Name <your.email@example.com>
```

### Example Commit

```bash
git commit -m "$(cat <<'EOF'
net/quic: Fix race condition in connection cleanup

The connection cleanup path had a race between timer callbacks
and connection teardown. Add proper locking around connection
state transitions to prevent use-after-free.

Assisted-by: Claude:claude-sonnet-4-5-20250929 checkpatch
Signed-off-by: Justin Smith <justin@example.com>

https://claude.ai/code/session_XXXXX
EOF
)"
```

## RFC References

The implementation follows these specifications:
- **RFC 9000**: QUIC Transport Protocol
- **RFC 9001**: Using TLS to Secure QUIC
- **RFC 9002**: QUIC Loss Detection and Congestion Control
- **RFC 9114**: HTTP/3
- **RFC 9221**: QUIC Datagram Extension
- **draft-ietf-quic-multipath**: Multipath QUIC

## Common Tasks

### Code Review
Use `/kernel-code-review` skill for comprehensive kernel-style review.

### Debugging
Use `/kernel-debug` skill for debugging techniques and tools.

### Patch Preparation
Use `/patch-prep` skill to prepare patches for submission.

## Build Commands

```bash
# Configure (enable QUIC)
make menuconfig  # Enable CONFIG_IP_QUIC under Networking

# Build module only
make M=net/quic

# Check for warnings
make M=net/quic W=1

# Static analysis
make M=net/quic C=1
```

## Testing

```bash
# Run KUnit tests (when available)
./tools/testing/kunit/kunit.py run --kunitconfig=net/quic/tests/.kunitconfig

# Load module for testing
insmod net/quic/quic.ko

# Check kernel logs
dmesg | grep -i quic
```

## Important Notes

1. **STUBS ARE NEVER ALLOWED**: No stub functions, placeholder code, or TODO comments. All code must be fully implemented and functional. If unsure how to implement something, MUST research online (RFCs, kernel docs, existing implementations) before writing code. Never assume - always verify.

2. **Don't modify upstream code**: Files outside `net/quic/` and `include/net/quic/` are from upstream Linux kernel. Avoid changes unless absolutely necessary.

3. **Memory safety is critical**: All allocations must be checked, all error paths must free resources, all locks must be released.

4. **Network data is untrusted**: Every field from packets must be validated before use.

5. **Reference counting**: Use proper refcounting for shared objects (connections, streams).

## Agents Available

- `security-reviewer` - Security audit for kernel code
- `performance-analyzer` - Performance bottleneck analysis
- `test-generator` - Generate KUnit/kselftest tests

## Skills Available

- `/kernel-code-review` - Review patches for style/safety
- `/kernel-debug` - Debugging techniques and tools
- `/rfc-lookup` - Quick RFC section references
- `/patch-prep` - Prepare patches for submission
- `/quic-protocol-check` - Protocol compliance (auto-invoked)

## Multi-AI Workflows (Claude Octopus)

When using `/octo:debate`, `/octo:multi`, or `/octo:review` commands, Claude should invoke external AI providers for true multi-perspective analysis.

### Provider Setup Status
- **Codex** (OpenAI): ✅ Installed at `/opt/homebrew/bin/codex` (v0.98.0) - WORKING
- **Gemini** (Google): ✅ Installed at `/opt/homebrew/bin/gemini` (v0.25.2) - Auth needs fix

### Correct CLI Invocation Patterns

**Codex** (for code analysis, technical depth):
```bash
echo "context..." | codex exec "Your question here" --full-auto
```

**Gemini** (for ecosystem breadth, alternatives):
```bash
gemini -p "Your question here"  # -p flag for non-interactive mode
```

### MANDATORY: Visual Indicator Banner

BEFORE starting any multi-AI analysis, ALWAYS display:
```
🐙 **CLAUDE OCTOPUS ACTIVATED** - [Workflow Name]
🐙 Task: [Description of what's being analyzed]

Provider Availability:
🔴 Codex CLI: Available ✓
🟡 Gemini CLI: Auth needs fix ✗
🔵 Claude: Available ✓ (Moderator and participant)
```

### Example Multi-AI Bug Verification

```bash
# 1. Check provider availability
codex_available=$(command -v codex && echo "✓" || echo "✗")
gemini_available=$(command -v gemini && echo "✓" || echo "✗")

# 2. Display banner (MANDATORY)
echo "🐙 **CLAUDE OCTOPUS ACTIVATED** - Bug Verification"
echo "Provider Status: Codex ✓, Gemini ✗, Claude ✓"

# 3. Get Codex perspective
echo "Analyzing commits for bugs..." | codex exec "Review commits 033c3048 and 7f9dabe7 for security vulnerabilities, use-after-free bugs, and race conditions in the TQUIC kernel module" --full-auto

# 4. Get Gemini perspective (when auth fixed)
gemini -p "Review commits 033c3048 and 7f9dabe7 for security vulnerabilities..."

# 5. Provide Claude's (my) independent analysis

# 6. Synthesize all perspectives
```

### Important Notes

1. **Actually invoke CLIs** - Don't just simulate multi-AI by taking different analytical perspectives. Use the actual external tools.

2. **Display banner first** - Users need to see which providers are active and understand they're being charged for external API calls.

3. **Verify provider status** - Check availability before attempting to use them.

4. **Cost awareness** - Codex uses OpenAI API credits (~$0.01-0.05 per query).

5. **Participate as Claude** - You're not just orchestrating - contribute your own independent analysis alongside Codex and Gemini perspectives.
