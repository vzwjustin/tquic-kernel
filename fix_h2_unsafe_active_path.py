#!/usr/bin/env python3
"""
Fix H-2: Convert unsafe READ_ONCE(conn->active_path) to RCU-safe refcounted access.

This script fixes the pattern where functions return paths without taking references,
violating the API contract that returned paths must be referenced.
"""

import re
import sys

def fix_return_best_pattern(content):
    """Fix: return best ?: READ_ONCE(conn->active_path);"""
    pattern = r'(\t+)(return best \?: READ_ONCE\(conn->active_path\);)'

    replacement = r'''\1/* Return referenced path per API contract */
\1if (best && tquic_path_get(best))
\1	return best;

\1rcu_read_lock();
\1best = rcu_dereference(conn->active_path);
\1if (best && !tquic_path_get(best))
\1	best = NULL;
\1rcu_read_unlock();

\1return best;'''

    return re.sub(pattern, replacement, content)

def fix_return_selected_pattern(content):
    """Fix: return selected ?: READ_ONCE(conn->active_path);"""
    pattern = r'(\t+)(return selected \?: READ_ONCE\(conn->active_path\);)'

    replacement = r'''\1/* Return referenced path per API contract */
\1if (selected && tquic_path_get(selected))
\1	return selected;

\1rcu_read_lock();
\1selected = rcu_dereference(conn->active_path);
\1if (selected && !tquic_path_get(selected))
\1	selected = NULL;
\1rcu_read_unlock();

\1return selected;'''

    return re.sub(pattern, replacement, content)

def fix_return_direct_pattern(content):
    """Fix: return READ_ONCE(conn->active_path);"""
    pattern = r'(\t+)(return READ_ONCE\(conn->active_path\);)'

    replacement = r'''\1struct tquic_path *path;

\1/* Return referenced path per API contract */
\1rcu_read_lock();
\1path = rcu_dereference(conn->active_path);
\1if (path && !tquic_path_get(path))
\1	path = NULL;
\1rcu_read_unlock();

\1return path;'''

    return re.sub(pattern, replacement, content)

def fix_assignment_pattern(content):
    """Fix: selected = READ_ONCE(conn->active_path); (assignment, not return)"""
    # This is trickier - need to add reference taking after assignment
    pattern = r'(\t+)(selected = READ_ONCE\(conn->active_path\);)'

    replacement = r'''\1rcu_read_lock();
\1selected = rcu_dereference(conn->active_path);
\1if (selected && !tquic_path_get(selected))
\1	selected = NULL;
\1rcu_read_unlock();'''

    return re.sub(pattern, replacement, content)

def add_rcupdate_include(content):
    """Add linux/rcupdate.h include if not present."""
    if 'linux/rcupdate.h' in content:
        return content

    # Add after other linux/ includes
    pattern = r'(#include <linux/[^>]+>\n)(?!#include <linux/)'
    replacement = r'\1#include <linux/rcupdate.h>\n'

    return re.sub(pattern, replacement, content, count=1)

def process_file(filepath):
    """Process a single file."""
    print(f"Processing {filepath}...")

    with open(filepath, 'r') as f:
        content = f.read()

    original = content

    # Add include
    content = add_rcupdate_include(content)

    # Apply all transformations
    content = fix_return_best_pattern(content)
    content = fix_return_selected_pattern(content)
    content = fix_return_direct_pattern(content)
    content = fix_assignment_pattern(content)

    if content != original:
        with open(filepath, 'w') as f:
            f.write(content)
        print(f"  ✓ Fixed {filepath}")
        return True
    else:
        print(f"  - No changes needed for {filepath}")
        return False

def main():
    files = [
        'net/tquic/bond/bonding.c',
        'net/tquic/tquic_proc.c',
    ]

    fixed_count = 0
    for filepath in files:
        try:
            if process_file(filepath):
                fixed_count += 1
        except Exception as e:
            print(f"ERROR processing {filepath}: {e}")
            return 1

    print(f"\n✓ Fixed {fixed_count} file(s)")
    return 0

if __name__ == '__main__':
    sys.exit(main())
