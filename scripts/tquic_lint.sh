#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
#
# tquic_lint.sh - Static analysis for common TQUIC kernel module mistakes
#
# Catches patterns that are easy to fix once spotted but hard to find
# during code review. Based on real bugs found during audit (bugs 1-10).
#
# Usage:
#   ./scripts/tquic_lint.sh [path]   # Default: net/tquic
#
# Exit code: 0 if clean, 1 if warnings found

set -uo pipefail

TQUIC_DIR="${1:-net/tquic}"
RED=$'\033[0;31m'
YEL=$'\033[0;33m'
CYN=$'\033[0;36m'
GRN=$'\033[0;32m'
RST=$'\033[0m'

# Use a temp file for counting since pipe | while runs in subshells
WARN_FILE=$(mktemp)
trap 'rm -f "$WARN_FILE"' EXIT

warn() {
    printf "%s[%s]%s %s%s%s %s\n" "$RED" "$1" "$RST" "$CYN" "$2" "$RST" "$3"
    echo x >> "$WARN_FILE"
}

section() {
    printf "\n%s── %s%s\n" "$YEL" "$1" "$RST"
}

# rg wrapper — returns matches from .c files, skips comments and .mod.c
rg_src() {
    rg -n --no-heading --glob '*.c' --glob '!*.mod.c' "$@" "$TQUIC_DIR" 2>/dev/null || true
}

# Filter out comment-only lines from stdin
no_comments() {
    grep -v '^\([^:]*:[0-9]*:\)\?\s*/[/*]' | grep -v '^\([^:]*:[0-9]*:\)\?\s*\*' || true
}

echo "========================================"
echo " TQUIC Static Analysis Lint"
echo " Scanning: $TQUIC_DIR"
echo "========================================"

# ── 1. Raw conn->state_machine casts (Bug 4: type confusion) ────────────
section "1. Raw conn->state_machine casts (type confusion)"

rg_src '\(struct tquic_conn_state_machine \*\).*conn->state_machine' | no_comments | \
    grep -v 'tquic_conn_get_cs' | \
    while IFS= read -r hit; do
        warn "TYPE-CAST" "$hit" "use tquic_conn_get_cs() accessor"
    done

# ── 2. READ_ONCE(conn->client) without RCU (Bug 5) ─────────────────────
section "2. conn->client reads without RCU"

rg_src 'READ_ONCE\(conn->client\)' -B5 | no_comments | \
    rg --multiline -U '(?s)(?!.*rcu_read_lock).*READ_ONCE\(conn->client\)' 2>/dev/null | \
    grep -v 'cmpxchg\|xchg' | \
    while IFS= read -r hit; do
        warn "RCU-MISS" "$hit" "needs rcu_read_lock() protection"
    done

# ── 3. Generic inet ops in proto_ops (Bug 10) ──────────────────────────
section "3. Generic inet ops in proto_ops tables"

rg_src '\.\s*(accept|listen|shutdown)\s*=\s*inet_(accept|listen|shutdown)' | no_comments | \
    while IFS= read -r hit; do
        warn "INET-OPS" "$hit" "should use tquic_ variant"
    done

# ── 4. Leftover debug prints ────────────────────────────────────────────
section "4. Leftover debug prints"

rg_src 'pr_(warn|info|err)\s*\(".*DEBUG' | no_comments | \
    while IFS= read -r hit; do
        warn "DEBUG-PRT" "$hit" "remove before release"
    done

# ── 5. Direct conn->state writes (Bug 9: bypass state machine) ─────────
section "5. Direct conn->state writes"

rg_src 'WRITE_ONCE\(conn->state\s*,' | no_comments | \
    grep -v 'tquic_conn_set_state' | \
    grep -Ev 'WRITE_ONCE\(conn->state,[[:space:]]*new_state\)' | \
    while IFS= read -r hit; do
        warn "ST-BYPASS" "$hit" "use tquic_conn_set_state()"
    done

# ── 6. list_del without _init (double-remove risk) ─────────────────────
section "6. list_del without _init"

rg_src '\blist_del\s*\(' | no_comments | \
    grep -v 'list_del_init\|list_del_rcu\|hlist_del' | \
    while IFS= read -r hit; do
        warn "LIST-DEL" "$hit" "use list_del_init() to prevent double-remove"
    done

# ── 7. kfree on sensitive material ─────────────────────────────────────
section "7. kfree on crypto/key material (should be kfree_sensitive)"

rg_src '\bkfree\s*\(' | no_comments | \
    grep -iv 'kfree_sensitive' | \
    grep -iE 'psk|_key|secret|crypto|tls_' | \
    while IFS= read -r hit; do
        warn "SENS-FREE" "$hit" "use kfree_sensitive()"
    done

# ── 8. rhashtable insert/remove balance ────────────────────────────────
section "8. rhashtable insert/remove balance"

for file in $(find "$TQUIC_DIR" -name '*.c' ! -name '*.mod.c' 2>/dev/null); do
    ins=$(grep -c 'rhashtable_insert_fast' "$file" 2>/dev/null || true)
    rem=$(grep -cE 'rhashtable_remove_fast|rhashtable_destroy|rhashtable_free_and_destroy' "$file" 2>/dev/null || true)
    [ "$ins" -gt 0 ] && [ "$rem" -lt "$ins" ] && \
        warn "RHT-BAL" "$file" "insert($ins) > remove($rem)"
done

# ── 9. sock_hold / sock_put balance ────────────────────────────────────
section "9. sock_hold / sock_put balance"

for file in $(find "$TQUIC_DIR" -name '*.c' ! -name '*.mod.c' 2>/dev/null); do
    h=$(grep -c '\bsock_hold\b' "$file" 2>/dev/null || true)
    p=$(grep -c '\bsock_put\b' "$file" 2>/dev/null || true)
    [ "$h" -gt 0 ] && [ "$p" -lt "$h" ] && \
        warn "SOCK-REF" "$file" "sock_hold($h) > sock_put($p) — possible leak"
done

# ── 10. tquic_conn_get / tquic_conn_put balance ────────────────────────
section "10. tquic_conn_get / tquic_conn_put balance"

for file in $(find "$TQUIC_DIR" -name '*.c' ! -name '*.mod.c' 2>/dev/null); do
    g=$(grep -c '\btquic_conn_get\b' "$file" 2>/dev/null || true)
    p=$(grep -c '\btquic_conn_put\b' "$file" 2>/dev/null || true)
    [ "$g" -gt 0 ] && [ "$p" -lt "$g" ] && \
        warn "CONN-REF" "$file" "tquic_conn_get($g) > tquic_conn_put($p) — possible leak"
done

# ── 11. Allocation without NULL check ──────────────────────────────────
section "11. Allocation without NULL check"

rg_src '\b(kzalloc|kmalloc|kcalloc|kvmalloc)\s*\(' -A2 | no_comments | \
    rg --multiline -U '(kzalloc|kmalloc|kcalloc|kvmalloc)\s*\([^;]+;\n[^\n]*(![^\n]*NULL|if\s*\(!)[^\n]*' 2>/dev/null > /dev/null
# Find alloc lines where the next 4 lines lack NULL/!/IS_ERR/ERR_PTR check
# (4 lines covers multi-line kcalloc + the check line)
rg_src '\b(kzalloc|kmalloc|kcalloc|kvmalloc)\s*\(' | no_comments | \
    grep -v 'if\s*(' | grep -v 'return\b' | \
    while IFS=: read -r file lineno rest; do
        [ -z "$file" ] && continue
        next=$(sed -n "$((lineno+1)),$((lineno+4))p" "$file" 2>/dev/null || true)
        if ! echo "$next" | grep -qE '![a-zA-Z_>]|NULL|IS_ERR|ERR_PTR|ENOMEM|goto.*err|goto.*fail|goto.*free|goto.*out|if \('; then
            warn "ALLOC-NULL" "$file:$lineno" "allocation without NULL check"
        fi
    done

# ── 12. Sleeping calls inside spinlock ─────────────────────────────────
section "12. Sleeping calls inside spinlock"

# Fast approach: find files with both spin_lock and sleeping calls, then spot-check
for file in $(find "$TQUIC_DIR" -name '*.c' ! -name '*.mod.c' 2>/dev/null); do
    grep -q 'spin_lock' "$file" 2>/dev/null || continue
    grep -q 'cancel_work_sync\|cancel_delayed_work_sync\|del_timer_sync\|flush_work\|msleep\|mutex_lock\|GFP_KERNEL' "$file" 2>/dev/null || continue

    # Quick awk pass: track spin_lock/spin_unlock depth, flag sleeping calls
    awk '
    /^}/ { depth=0; lock_line=0 }
    /spin_lock(_bh|_irq|_irqsave)?[[:space:]]*\(/ { depth++; lock_line=NR }
    /spin_unlock(_bh|_irq|_irqrestore)?[[:space:]]*\(/ { if(depth>0) depth-- }
    depth > 0 && /cancel_work_sync|cancel_delayed_work_sync|del_timer_sync|flush_work|msleep|schedule_timeout|mutex_lock/ {
        printf "%s:%d: %s (spinlock at line %d)\n", FILENAME, NR, $0, lock_line
    }
    depth > 0 && /kmalloc|kzalloc|kcalloc/ && /GFP_KERNEL/ {
        printf "%s:%d: %s (spinlock at line %d)\n", FILENAME, NR, $0, lock_line
    }
    ' "$file" | while IFS= read -r hit; do
        warn "SLEEP-ATM" "$hit" ""
    done
done

# ── 13. lock_sock without release_sock on return paths ─────────────────
section "13. Bare return after lock_sock (lock leak)"

# Fast awk approach instead of bash line loop
for file in $(find "$TQUIC_DIR" -name '*.c' ! -name '*.mod.c' 2>/dev/null); do
    grep -q 'lock_sock' "$file" 2>/dev/null || continue

    awk '
    /lock_sock[[:space:]]*\(/ { locked=1; lock_ln=NR }
    /release_sock[[:space:]]*\(/ { locked=0 }
    # Reset at function boundaries (line starting with { or } at col 0)
    /^}/ { locked=0 }
    locked && /^[[:space:]]+return[[:space:]]/ && !/release_sock/ {
        printf "%s:%d: return inside lock_sock section (locked at %d)\n", FILENAME, NR, lock_ln
    }
    ' "$file" | while IFS= read -r hit; do
        warn "LOCK-LEAK" "$hit" ""
    done
done

# ── 14. Whitespace issues (git diff --check) ──────────────────────────
section "14. Whitespace issues"

toplevel=$(git -C "$TQUIC_DIR" rev-parse --show-toplevel 2>/dev/null || echo ".")
ws=$(cd "$toplevel" && git diff --check -- "$TQUIC_DIR" 2>/dev/null | head -10)
if [ -n "$ws" ]; then
    while IFS= read -r hit; do
        warn "WSPACE" "$hit" ""
    done <<< "$ws"
else
    printf "  %sNo whitespace issues%s\n" "$GRN" "$RST"
fi

# ── 15. Missing NULL guard on conn->sk dereference ────────────────────
section "15. conn->sk dereference without NULL check"

rg_src 'conn->sk->' | no_comments | \
    grep -v 'if.*conn->sk' | \
    while IFS=: read -r file lineno rest; do
        [ -z "$file" ] && continue
        prev=$(sed -n "$((lineno > 3 ? lineno-3 : 1)),${lineno}p" "$file" 2>/dev/null || true)
        if ! echo "$prev" | grep -qE 'conn->sk\b.*NULL|!conn->sk|if.*conn->sk\b'; then
            warn "SK-NULL" "$file:$lineno" "conn->sk-> without prior NULL check"
        fi
    done

# ── 16. tquic_conn_destroy missing cleanup calls (OOT vs in-tree) ─────
section "16. Destroy function completeness"

for file in $(find "$TQUIC_DIR" -name '*.c' ! -name '*.mod.c' 2>/dev/null); do
    grep -q 'tquic_conn_destroy' "$file" 2>/dev/null || continue
    # Check if this file defines the destroy function
    if grep -qE '^(void|int)\s+tquic_conn_destroy' "$file" 2>/dev/null; then
        for call in tquic_conn_state_cleanup tquic_server_unbind_client tquic_pm_conn_release; do
            if ! grep -q "$call" "$file" 2>/dev/null; then
                warn "DESTROY" "$file" "tquic_conn_destroy missing $call()"
            fi
        done
    fi
done

# ═══════════════════════════════════════════════════════════════════════
#  SUMMARY
# ═══════════════════════════════════════════════════════════════════════
echo ""
echo "========================================"
WARN_COUNT=$(wc -l < "$WARN_FILE" | tr -d ' ')
if [ "$WARN_COUNT" -eq 0 ]; then
    printf "%sPASS: 0 warnings%s\n" "$GRN" "$RST"
else
    printf "%sFOUND: %d warning(s)%s\n" "$RED" "$WARN_COUNT" "$RST"
fi
echo "========================================"

[ "$WARN_COUNT" -gt 0 ] && exit 1
exit 0
