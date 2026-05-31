# IDA Domain API overview

- 官方来源：https://ida-domain.docs.hex-rays.com/getting_started/

Skip to content

IDA Domain API

Getting Started

Initializing search

hexrayssa/ida-domain

IDA Domain API

hexrayssa/ida-domain

- Intro
- Getting Started Getting Started
Table of contents

- Prerequisites
- Installation

- Step 1: Set up IDA SDK Access
- Step 2: Install the Package
- Step 3: Verify Installation

- Your First Script
- Running Scripts Inside IDA
- Troubleshooting
- Next Steps

- FAQ
- Examples
- Usage
Usage

- Overview
- llms.txt

- API Reference
API Reference

- Database
- Flowchart
- Bytes
- Comments
- Entries
- Hooks
- Functions
- Heads
- Imports
- Instructions
- Microcode
- Pseudocode
- Names
- Operands
- Segments
- Signature Files
- Strings
- Types
- Xrefs

Table of contents

- Prerequisites
- Installation

- Step 1: Set up IDA SDK Access
- Step 2: Install the Package
- Step 3: Verify Installation

- Your First Script
- Running Scripts Inside IDA
- Troubleshooting
- Next Steps

# Getting Started

This guide will take you from nothing to a working first script with the IDA Domain API.

## Prerequisites

- Python 3.9 or higher
- IDA Pro 9.1 or higher

## Installation

### Step 1: Set up IDA SDK Access

The IDA Domain API needs access to the IDA SDK. Choose one of these options:

Option A: Set IDADIR Environment Variable

Point to your IDA installation directory:

macOSLinuxWindows

```text
export IDADIR="/Applications/IDA Professional 9.2.app/Contents/MacOS/"

```

```text
export IDADIR="/opt/ida-9.2/"

```

```text
set IDADIR="C:\Program Files\IDA Professional 9.2\"

```

To make this permanent, add the export command to your shell profile (`~/.bashrc`, `~/.zshrc`, etc.).

Option B: Use idapro Python Package

If you already have the `idapro` Python package configured, skip setting `IDADIR`.

### Step 2: Install the Package

For a clean environment, use a virtual environment:

```text
# Create and activate virtual environment
python -m venv ida-env
source ida-env/bin/activate # On Windows: ida-env\Scripts\activate

# Install the package
pip install ida-domain

```

### Step 3: Verify Installation

```text
# test_install.py
try:
from ida_domain import Database
print("✓ Installation successful!")
except ImportError as e:
print(f"✗ Installation failed: {e}")

```

## Your First Script

Create a simple script to explore an IDA database:

```text
# my_first_script.py
import argparse

from ida_domain import Database

def explore_database(db_path):
# Create and open database
with Database.open(path=db_path, save_on_close=False) as db:
# Basic database info
print(f'[+] Opened: {db_path}')
print(f' Architecture: {db.architecture}')
print(f' Entry point: {hex(db.entries[0].address)}')
print(f' Address range: {hex(db.minimum_ea)} - {hex(db.maximum_ea)}')

# Count functions
func_count = len(list(db.functions))
print(f' Functions: {func_count}')

# Count strings
string_count = len(list(db.strings))
print(f' Strings: {string_count}')
print('[+] Database closed')

if __name__ == '__main__':
parser = argparse.ArgumentParser()
parser.add_argument('-f', '--input-file', type=str, required=True)
args = parser.parse_args()
# Run with your IDA input file
explore_database(args.input_file)

```

To run this script:

Run: `python my_first_script.py -f `

Expected output:

```text
✓ Opened: /path/to/sample.idb
Architecture: x86_64
Entry point: 0x1000
Address range: 0x1000 - 0x2000
Functions: 42
Strings: 15
✓ Database closed

```

## Running Scripts Inside IDA

The examples above show library mode - running standalone Python scripts outside IDA. You can also use IDA Domain from inside the IDA GUI for interactive analysis.

When running inside IDA, call `Database.open()` with no arguments to get a handle to the currently open database:

```text
# ida_console_example.py
# Run this from IDA's IDAPython console or via File → Script command
from ida_domain import Database

# Get handle to currently open database (no path needed)
with Database.open() as db:
print(f'Current database: {db.path}')
print(f'Architecture: {db.architecture}')
print(f'Functions: {len(list(db.functions))}')

```

Key difference from library mode:

- No file path argument - database is already open

## Troubleshooting

ImportError: No module named 'ida_domain' - Run `pip install ida-domain` - Check you're in the correct virtual environment

IDA SDK not found - Verify `IDADIR` is set: `echo $IDADIR` - Ensure the path points to your actual IDA installation

Database won't open - Check the file path exists - Ensure the database was created with IDA Pro 9.0+

## Next Steps

- Examples - Complete examples for real-world tasks
- API Reference - Detailed API documentation
- Start your project - Apply these concepts to your reverse engineering work!

Back to top

Previous
Intro

Next
FAQ

Copyright © 2025 Hex-Rays
Made with Material for MkDocs
