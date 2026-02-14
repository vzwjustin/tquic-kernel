#!/usr/bin/env perl
# fix_alloc_null.pl - Add missing NULL checks after kernel allocations
#
# Usage: perl scripts/fix_alloc_null.pl file.c [file2.c ...]
#
# Handles patterns like:
#   var = kzalloc(size, flags);
#   ptr->field = kzalloc(size, flags);
#   multiline kcalloc spanning 2 lines ending with ;
#
# Inserts: if (!var)\n\t\treturn -ENOMEM;

use strict;
use warnings;

foreach my $file (@ARGV) {
    open(my $fh, '<', $file) or do { warn "Cannot open $file: $!\n"; next };
    my @lines = <$fh>;
    close $fh;

    my @out;
    my $modified = 0;

    for (my $i = 0; $i < @lines; $i++) {
        my $line = $lines[$i];
        push @out, $line;

        # Detect allocation on this line (possibly continued on next)
        my $alloc_line = $line;
        my $extra_pushed = 0;

        # Handle multi-line: alloc call starts here but ; is on next line
        if ($line =~ /(?:kzalloc|kmalloc|kcalloc|kvmalloc|kstrdup)\s*\(/ &&
            $line !~ /;\s*$/) {
            # Continuation line
            if ($i + 1 < @lines && $lines[$i + 1] =~ /;\s*$/) {
                push @out, $lines[$i + 1];
                $alloc_line .= $lines[$i + 1];
                $extra_pushed = 1;
                $i++;
            }
        }

        # Match: indent + lvalue = alloc(...);
        # lvalue can be: var, ptr->field, ptr->field.sub, etc.
        if ($alloc_line =~ /^(\s+)([\w>.\-]+)\s*=\s*(?:kzalloc|kmalloc|kcalloc|kvmalloc|kstrdup)\s*\(/) {
            my $indent = $1;
            my $lvalue = $2;

            # Extract the simple variable name for the NULL check
            # For "ptr->field", check "!ptr->field"
            # For "var", check "!var"
            my $check_expr = $lvalue;

            # Verify the alloc line ends with ;
            next unless $alloc_line =~ /;\s*$/;

            # Check if next 2 lines already have a NULL check
            my $ni = $i + 1;
            my $next1 = ($ni < @lines) ? $lines[$ni] : '';
            my $next2 = ($ni + 1 < @lines) ? $lines[$ni + 1] : '';

            # Escape for regex
            my $qe = quotemeta($check_expr);

            # Skip if already has NULL check
            if ($next1 =~ /!${qe}|${qe}\s*==\s*NULL|IS_ERR/ ||
                $next2 =~ /!${qe}|${qe}\s*==\s*NULL|IS_ERR/) {
                next;
            }

            # Also check with just the last identifier (for ptr->x, check !x too)
            my ($simple_var) = ($check_expr =~ /(\w+)$/);
            if ($next1 =~ /!\s*\Q$simple_var\E\b/ ||
                $next2 =~ /!\s*\Q$simple_var\E\b/) {
                next;
            }

            # Skip if this line is inside an if() condition
            if ($alloc_line =~ /^\s*if\s*\(/) {
                next;
            }

            # Skip if line contains return
            if ($alloc_line =~ /^\s*return\b/) {
                next;
            }

            # Insert NULL check
            push @out, "${indent}if (!${check_expr})\n";
            push @out, "${indent}\treturn -ENOMEM;\n";
            $modified++;
        }
    }

    if ($modified) {
        open(my $wfh, '>', $file) or do { warn "Cannot write $file: $!\n"; next };
        print $wfh @out;
        close $wfh;
        print "Fixed $modified allocation(s) in $file\n";
    }
}
