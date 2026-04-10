#!/usr/bin/env python3
"""
w3af Python 2 to Python 3 Migration Script

This script helps migrate the w3af codebase from Python 2 to Python 3.
Run this script to automatically fix common Python 2 -> Python 3 issues.
"""

import os
import re
import sys
from pathlib import Path
from typing import List, Tuple


def find_python_files(root_dir: str) -> List[str]:
    """Find all Python files in the directory."""
    python_files = []
    for root, _, files in os.walk(root_dir):
        for file in files:
            if file.endswith('.py'):
                python_files.append(os.path.join(root, file))
    return python_files


def fix_print_statements(content: str) -> str:
    """Fix Python 2 style print statements."""
    # Match: print 'string' or print "string"
    pattern = r"print\s+(['\"].*?['\"])"
    
    def replace_print(match):
        expr = match.group(1)
        return f"print({expr})"
    
    content = re.sub(pattern, replace_print, content)
    
    # Match: print 'string', (trailing comma)
    pattern2 = r"print\s+(['\"].*?['\"])\s*,"
    content = re.sub(pattern2, replace_print, content)
    
    return content


def fix_raw_input(content: str) -> str:
    """Replace raw_input with input for Python 3."""
    return content.replace('raw_input(', 'input(')


def fix_dict_methods(content: str) -> str:
    """Fix dict methods for Python 3 compatibility."""
    # .iteritems() -> .items()
    content = re.sub(r'\.iteritems\(\)', '.items()', content)
    # .itervalues() -> .values()
    content = re.sub(r'\.itervalues\(\)', '.values()', content)
    # .iterkeys() -> .keys()
    content = re.sub(r'\.iterkeys\(\)', '.keys()', content)
    
    return content


def fix_string_encoding(content: str) -> str:
    """Fix string encoding issues."""
    # Remove u'' string prefixes (Python 3 handles this natively)
    content = re.sub(r"u'(.*?)'", r"'\1'", content)
    content = re.sub(r'u"(.*?)"', r'"\1"', content)
    
    return content


def fix_imports(content: str) -> str:
    """Fix imports for Python 3."""
    # ConfigParser -> configparser
    content = re.sub(r'from ConfigParser import', 'from configparser import', content)
    content = re.sub(r'import ConfigParser', 'import configparser', content)
    
    # Queue -> queue
    content = re.sub(r'from Queue import', 'from queue import', content)
    content = re.sub(r'import Queue', 'import queue', content)
    
    # urllib2 -> urllib.request
    content = re.sub(r'from urllib2 import', 'from urllib.request import', content)
    
    # urlparse -> urllib.parse
    content = re.sub(r'from urlparse import', 'from urllib.parse import', content)
    
    # SimpleHTTPServer -> http.server
    content = re.sub(r'from SimpleHTTPServer import', 'from http.server import', content)
    
    # httplib -> http.client
    content = re.sub(r'from httplib import', 'from http.client import', content)
    
    # xml.parsers.expat -> xml.parsers.expat
    # Already compatible
    
    return content


def fix_exception_syntax(content: str) -> str:
    """Fix old-style exception syntax."""
    # except Exception, e: -> except Exception as e:
    content = re.sub(r'except\s+(\w+),\s*(\w+):', r'except \1 as \2:', content)
    
    return content


def process_file(filepath: str, dry_run: bool = True) -> Tuple[int, str]:
    """Process a single file and fix Python 2/3 issues."""
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            original_content = f.read()
    except Exception as e:
        return 0, f"Error reading {filepath}: {e}"
    
    content = original_content
    
    # Apply fixes
    content = fix_print_statements(content)
    content = fix_raw_input(content)
    content = fix_dict_methods(content)
    content = fix_string_encoding(content)
    content = fix_imports(content)
    content = fix_exception_syntax(content)
    
    if content != original_content:
        if not dry_run:
            try:
                with open(filepath, 'w', encoding='utf-8') as f:
                    f.write(content)
                return 1, f"Fixed {filepath}"
            except Exception as e:
                return 0, f"Error writing {filepath}: {e}"
        else:
            return 1, f"Would fix {filepath}"
    
    return 0, "No changes needed"


def main():
    """Main function."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Migrate w3af from Python 2 to Python 3'
    )
    parser.add_argument(
        'directory',
        nargs='?',
        default='w3af',
        help='Directory to process (default: w3af)'
    )
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Show what would be changed without making changes'
    )
    parser.add_argument(
        '--apply',
        action='store_true',
        help='Apply the changes'
    )
    
    args = parser.parse_args()
    
    if not os.path.exists(args.directory):
        print(f"Error: Directory '{args.directory}' does not exist")
        sys.exit(1)
    
    dry_run = not args.apply
    
    print(f"Scanning {args.directory} for Python files...")
    python_files = find_python_files(args.directory)
    print(f"Found {len(python_files)} Python files")
    
    fixed_count = 0
    error_count = 0
    
    for filepath in python_files:
        fixed, message = process_file(filepath, dry_run)
        if fixed:
            print(message)
            fixed_count += 1
        if "Error" in message:
            error_count += 1
            print(f"  ERROR: {message}", file=sys.stderr)
    
    print(f"\n{'Would be' if dry_run else 'Were'} fixed: {fixed_count} files")
    if error_count > 0:
        print(f"Errors: {error_count}")
    
    if dry_run:
        print("\nThis was a dry run. Run with --apply to make changes.")


if __name__ == '__main__':
    main()