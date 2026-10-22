# Calculate and verify a cryptographic hash for a string, stdin, or a file

A fast, simple, and fully-typed utility for calculating and verifying cryptographic hashes of strings, files, and standard input (stdin).

Unlike standard `sha256sum` tools, `hashsum` provides a clean programmatic Python API, making it easy to integrate into other applications, scripts, or GUIs without capturing stdout.

## Features

- **Multiple Sources:** Calculate hashes from a raw string, a file, or piped `stdin`.
- **Verification:** Safely verify files or strings against an expected hash with constant-time comparison to prevent timing attacks.
- **Batch Calculation (`--multi`):** Instantly calculate a curated list of common algorithms (MD5, SHA-1, SHA-256, SHA-512) in a single pass.
- **XOF Support:** Full support for Extendable-Output Functions like `shake_128` and `shake_256`.
- **Clean API:** Use the `calculate()` function to get a structured `HashResult` object without printing anything to the console.
- **Cross-platform:** Works flawlessly on Linux, macOS, and Windows.

## Requirements

- Python 3.12 or higher.
- (Optional) [`uv`](https://github.com/astral-sh/uv) for dependency management and running.

## CLI Usage

You can run the CLI directly using Python or `uv`:

```bash
# Calculate hash of a string
uv run hashsum.py "hello world"

# Calculate hash of a file
uv run hashsum.py -f ./file.bin

# Use a specific algorithm (e.g., sha512, md5)
uv run hashsum.py -a sha512 "hello world"

# Calculate a batch of common hashes at once
uv run hashsum.py --multi "hello world"

# Read from stdin
cat ./file.bin | uv run hashsum.py --stdin --multi

# Verify a hash (returns exit code 0 if OK, 2 if MISMATCH)
uv run hashsum.py -f ./file.bin --verify <expected_hash>

# List all available algorithms in your Python build
uv run hashsum.py --list-algorithms
```

### Exit Codes

- `0`: Success / Hash verified (`OK`).
- `1`: Execution error (e.g., file not found, unknown algorithm, invalid hex).
- `2`: Hash mismatch (`MISMATCH`).

## Programmatic API

You can import `calculate` and use it in your own Python projects. It raises standard exceptions (`ValueError`, `OSError`) and returns a `HashResult` named tuple.

```python
from hashsum import calculate

# 1. Simple string hashing
result = calculate("hello world", algorithm="sha256")
print(result.digests["sha256"])

# 2. Hashing a file with multiple algorithms
result = calculate("./file.bin", file=True, multi=True)
for algo, digest in result.digests.items():
    print(f"{algo}: {digest}")

# 3. Verifying a file
result = calculate("./file.bin", file=True, verify="expected_hash_here")
if result.verified:
    print("File is intact!")
elif result.verified is False:
    print("File is corrupted!")
    for warning in result.warnings:
        print(f"Warning: {warning}")
```

### The `HashResult` Object

The `calculate()` function always returns a `HashResult` object with three fields:

- `digests` (`dict[str, str]`): A dictionary mapping algorithm names to hex-encoded hashes.
- `verified` (`bool | None`): `True` or `False` if `verify` was provided. `None` otherwise.
- `warnings` (`tuple[str, ...]`): A tuple of warning messages (e.g., if the provided expected hash was too short).

## Development

To run the test suite, make sure you have `pytest` installed:

```bash
uv run pytest
```

## License

MIT License
