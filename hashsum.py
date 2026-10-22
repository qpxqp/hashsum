"""Calculate and verify cryptographic hashes for a string, stdin, or file."""

import argparse
import binascii
import hashlib
import hmac
import sys
from functools import partial
from pathlib import Path
from typing import NamedTuple, cast

CHUNK_SIZE = 1024 * 1024  # 1 MiB

# Algorithms set for --multi
MULTI_ALGORITHMS: tuple[str, ...] = (
    # --- MD family (compromised, compatibility only)
    'md5',
    # 'md5-sha1',

    # --- SHA-1 (compromised, compatibility only)
    'sha1',

    # --- SHA-2
    # 'sha224',
    'sha256',
    # 'sha384',
    'sha512',
    # 'sha512_224',
    # 'sha512_256',

    # --- SHA-3
    # 'sha3_224',
    # 'sha3_256',
    # 'sha3_384',
    # 'sha3_512',

    # --- BLAKE2
    # 'blake2b',
    # 'blake2s',

    # --- SHAKE (XOF, length = XOF_LENGTH)
    # 'shake_128',
    # 'shake_256',

    # --- Other
    # 'ripemd160',
    # 'sm3',
)

DEFAULT_ALGORITHM = 'sha256'
XOF_LENGTH = 32  # Output length for XOF algorithms (shake_*) in bytes

# --verify results
MSG_VERIFIED = 'OK'
MSG_MISMATCH = 'MISMATCH'


class HashResult(NamedTuple):
    """Result of the calculate() function."""
    digests: dict[str, str]         # Algorithm: hex-hash pairs
    verified: bool | None = None    # --verify result, None - no verification
    warnings: tuple[str, ...] = ()  # Tuple of warnings


# ---------- error and warning messages ----------

# Low-level errors
ERR_ALGORITHM_UNAVAILABLE = (
    'Algorithm `{algorithm}` is unavailable. '
    'Check the list: --list-algorithms'
)
ERR_EXPECTED_HASH_EMPTY = 'Expected hash is empty'
ERR_EXPECTED_HASH_NOT_HEX = 'Expected hash must be a hex string'

# Hash length mismatch warning
WARN_HASH_LENGTH = (
    'Warning: hash length is {actual}, '
    'expected {expected} for `{algorithm}`'
)

# I/O errors
ERR_IO_STDIN = 'I/O error (stdin): {exc}'
ERR_FILE_NOT_FOUND = 'File not found: {target}'
ERR_IS_DIRECTORY = 'This is a directory, not a file: {target}'
ERR_PERMISSION_DENIED = 'Permission denied for file: {target}'
ERR_IO_FILE = 'I/O error (file {target}): {exc}'

# Generic wrapper for ValueError from business logic
ERR_GENERIC = 'Error: {exc}'

# CLI argument validation errors (parser.error)
ERR_LIST_NO_TARGET = '--list-algorithms does not accept target'
ERR_LIST_WITH_VERIFY = (
    '--list-algorithms and --verify cannot be used together'
)
ERR_STDIN_WITH_TARGET = 'target argument is not used with --stdin'
ERR_NO_TARGET = 'specify a string, file path, or use --stdin'
ERR_MULTI_WITH_VERIFY = '--multi and --verify cannot be used together'
ERR_FILE_AND_STDIN = 'Cannot use both --file and --stdin sources together'


# ---------- parser strings ----------

PARSER_DESCRIPTION = 'Calculate and verify cryptographic hashes.'
PARSER_EPILOG = (
    'Examples:\n'
    '  hashsum "hello world"\n'
    '  hashsum -a sha512 "hello world"\n'
    '  hashsum -f ./file.bin\n'
    '  hashsum -f ./file.bin -a sha512\n'
    '  hashsum --multi "hello world"\n'
    '  hashsum -f ./file.bin --multi\n'
    '  cat ./file.bin | hashsum --stdin --multi\n'
    '  hashsum -f ./file.bin --verify <hash>\n'
    '  cat ./file.bin | hashsum --stdin --verify <hash>\n'
    '  hashsum --list-algorithms'
)
PARSER_ARG_TARGET = (
    'string or file path; '
    'not needed with --stdin or --list-algorithms'
)
PARSER_ARG_FILE = 'treat target as a file path'
PARSER_ARG_STDIN = 'read data from stdin'
PARSER_ARG_MULTI = 'show several common algorithms'
PARSER_ARG_LIST_ALGO = 'show available algorithms and exit'
PARSER_ARG_ALGORITHM = (
    f'algorithm (default: {DEFAULT_ALGORITHM}); '
    f'cannot be used with --multi and --list-algorithms'
)
PARSER_ARG_VERIFY = 'compare result with expected hex hash'

# ---------- utilities ----------

def to_bytes(data: str | bytes) -> bytes:
    """Convert str to bytes (UTF-8), return bytes as is."""
    return data.encode('utf-8') if isinstance(data, str) else data


def available_algorithms() -> list[str]:
    """List of algorithms available in the current Python build."""
    return sorted(hashlib.algorithms_available)


def normalize_algorithm(algorithm: str) -> str:
    """Normalize and validate algorithm name."""
    name = algorithm.strip().lower()
    if name not in hashlib.algorithms_available:
        raise ValueError(
            ERR_ALGORITHM_UNAVAILABLE.format(algorithm=algorithm)
        )
    return name


def _is_xof(name: str) -> bool:
    """XOF algorithms (shake_*) require explicit output length."""
    return name.startswith('shake_')


def _hexdigest(digest, name: str) -> str:
    """hexdigest taking XOF algorithms into account."""
    if _is_xof(name):
        return digest.hexdigest(XOF_LENGTH)
    return digest.hexdigest()


def normalize_expected_hash(
    expected: str,
    algorithm: str | None = None,
) -> tuple[str, str | None]:
    """Check that the expected hash is a hex string.

    If algorithm is provided, additionally checks the hex string length
    against the algorithm's digest_size. For XOF algorithms (shake_*)
    digest_size == 0, and length check is skipped.
    Returns the normalized hash and an optional warning.
    """
    value = expected.strip().lower()
    if not value:
        raise ValueError(ERR_EXPECTED_HASH_EMPTY)
    try:
        binascii.unhexlify(value)
    except (binascii.Error, ValueError) as exc:
        raise ValueError(ERR_EXPECTED_HASH_NOT_HEX) from exc
    warning = None
    if algorithm is not None:
        digest_size = hashlib.new(algorithm).digest_size
        if digest_size > 0:
            expected_length = digest_size * 2
            if len(value) != expected_length:
                warning = WARN_HASH_LENGTH.format(
                    actual=len(value),
                    algorithm=algorithm,
                    expected=expected_length,
                )
    return value, warning


# ---------- hash calculation ----------

def hash_data(data: str | bytes, algorithm: str = DEFAULT_ALGORITHM) -> str:
    """Return hex hash of a string or bytes."""
    name = normalize_algorithm(algorithm)
    digest = hashlib.new(name, to_bytes(data))
    return _hexdigest(digest, name)


def hash_file(path: str | Path, algorithm: str = DEFAULT_ALGORITHM) -> str:
    """Return hex hash of a file, reading it in chunks."""
    name = normalize_algorithm(algorithm)
    if hasattr(hashlib, 'file_digest'):
        with Path(path).open('rb') as f:
            digest = hashlib.file_digest(f, name)
            return _hexdigest(digest, name)
    digest = hashlib.new(name)
    with Path(path).open('rb') as f:
        for chunk in iter(lambda: f.read(CHUNK_SIZE), b''):
            digest.update(chunk)
    return _hexdigest(digest, name)


def hash_stdin(algorithm: str = DEFAULT_ALGORITHM) -> str:
    """Return hex hash of data from stdin."""
    name = normalize_algorithm(algorithm)
    digest = hashlib.new(name)
    while chunk := sys.stdin.buffer.read(CHUNK_SIZE):
        digest.update(chunk)
    return _hexdigest(digest, name)


def hash_multi(data: str | bytes) -> dict[str, str]:
    """Calculate a set of common hashes for a string or bytes."""
    raw = to_bytes(data)
    result: dict[str, str] = {}
    for name in MULTI_ALGORITHMS:
        if name not in hashlib.algorithms_available:
            continue
        digest = hashlib.new(name, raw)
        result[name] = _hexdigest(digest, name)
    return result


def hash_file_multi(path: str | Path) -> dict[str, str]:
    """Calculate a set of common hashes of a file in one pass."""
    digests = {
        name: hashlib.new(name)
        for name in MULTI_ALGORITHMS
        if name in hashlib.algorithms_available
    }
    with Path(path).open('rb') as f:
        for chunk in iter(lambda: f.read(CHUNK_SIZE), b''):
            for digest in digests.values():
                digest.update(chunk)
    return {name: _hexdigest(dig, name) for name, dig in digests.items()}


def hash_stdin_multi() -> dict[str, str]:
    """Calculate a set of common hashes of stdin data in one pass."""
    digests = {
        name: hashlib.new(name)
        for name in MULTI_ALGORITHMS
        if name in hashlib.algorithms_available
    }
    while chunk := sys.stdin.buffer.read(CHUNK_SIZE):
        for digest in digests.values():
            digest.update(chunk)
    return {name: _hexdigest(dig, name) for name, dig in digests.items()}


# ---------- high-level API ----------

def calculate(
    target: str | None = None,
    *,
    file: bool = False,
    stdin: bool = False,
    multi: bool = False,
    algorithm: str = DEFAULT_ALGORITHM,
    verify: str | None = None,
) -> HashResult:
    """Entry point for calculating and verifying hashes programmatically.

    This function does not print anything to stdout/stderr. It returns a
    HashResult object and raises exceptions on errors.

    Args:
        target: The string to hash, or the file path if `file=True`.
            Can be omitted if `stdin=True`.
        file: If True, treats `target` as a file path and reads its contents.
        stdin: If True, reads binary data from `sys.stdin`.
        multi: If True, calculates a predefined set of common algorithms
            (MULTI_ALGORITHMS). When True, `algorithm` and `verify` are ignored.
        algorithm: The name of the hash algorithm (e.g., "sha256", "md5").
            Case-insensitive. Ignored if `multi=True`.
        verify: An optional expected hex digest. If provided, the calculated
            hash is compared against this value using a constant-time
            comparison.

    Returns:
        A HashResult namedtuple containing:
        - digests (dict[str, str]): Mapping of algorithm names to hex hashes.
        - verified (bool | None): True/False if `verify` was provided,
          otherwise None.
        - warnings (tuple[str, ...]): Any warnings (e.g., hash length mismatch).

    Raises:
        ValueError: If no target is provided (and stdin=False), or if the
            algorithm name or expected hash format is invalid.
        OSError: If there is an error reading the file (e.g., file not found,
            permission denied).
    """
    if not stdin and target is None:
        raise ValueError(ERR_NO_TARGET)
    if multi and verify is not None:
        raise ValueError(ERR_MULTI_WITH_VERIFY)
    if file and stdin:
        raise ValueError(ERR_FILE_AND_STDIN)
    tgt = cast(str, target)
    if file:
        hash_single = partial(hash_file, tgt)
        hash_all = partial(hash_file_multi, tgt)
    elif stdin:
        hash_single = hash_stdin
        hash_all = hash_stdin_multi
    else:
        hash_single = partial(hash_data, tgt)
        hash_all = partial(hash_multi, tgt)
    if multi:
        return HashResult(digests=hash_all())
    name = normalize_algorithm(algorithm)
    actual = hash_single(name)
    digests = {name: actual}
    if verify is not None:
        expected, warning = normalize_expected_hash(verify, name)
        ok = hmac.compare_digest(actual, expected)
        return HashResult(
            digests=digests,
            verified=ok,
            warnings=(warning,) if warning else (),
        )
    return HashResult(digests=digests)


# ---------- CLI ----------

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog='hashsum',
        description=PARSER_DESCRIPTION,
        epilog=PARSER_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        'target',
        nargs='?',
        help=PARSER_ARG_TARGET,
    )
    # --- data source ---
    source = parser.add_mutually_exclusive_group()
    source.add_argument(
        '-f', '--file',
        action='store_true',
        help=PARSER_ARG_FILE,
    )
    source.add_argument(
        '--stdin',
        action='store_true',
        help=PARSER_ARG_STDIN,
    )
    # --- output modifiers ---
    output = parser.add_mutually_exclusive_group()
    output.add_argument(
        '--multi',
        action='store_true',
        help=PARSER_ARG_MULTI,
    )
    output.add_argument(
        '--list-algorithms',
        action='store_true',
        help=PARSER_ARG_LIST_ALGO,
    )
    output.add_argument(
        '-a', '--algorithm',
        default=DEFAULT_ALGORITHM,
        help=PARSER_ARG_ALGORITHM,
    )
    parser.add_argument(
        '--verify',
        metavar='HASH',
        help=PARSER_ARG_VERIFY,
    )
    return parser


def _format_dict(result: dict[str, str]) -> str:
    """Format hash dictionary as a string."""
    width = max(len(name) for name in result)
    return ('\n'.join(
        f'{name:<{width}} : {value}'
        for name, value in result.items()
    ))


def _format_io_error(args: argparse.Namespace, exc: OSError) -> str:
    """Format I/O error message."""
    if args.stdin:
        return ERR_IO_STDIN.format(exc=exc)
    if isinstance(exc, FileNotFoundError):
        return ERR_FILE_NOT_FOUND.format(target=args.target)
    elif isinstance(exc, IsADirectoryError):
        return ERR_IS_DIRECTORY.format(target=args.target)
    elif isinstance(exc, PermissionError):
        return ERR_PERMISSION_DENIED.format(target=args.target)
    else:
        return ERR_IO_FILE.format(target=args.target, exc=exc)


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.list_algorithms:
        if args.target is not None:
            parser.error(ERR_LIST_NO_TARGET)
        if args.verify is not None:
            parser.error(ERR_LIST_WITH_VERIFY)
        sys.stdout.write('\n'.join(available_algorithms()) + '\n')
        return 0
    # --- data source ---
    if args.stdin and args.target is not None:
        parser.error(ERR_STDIN_WITH_TARGET)
    if not args.stdin and args.target is None:
        parser.error(ERR_NO_TARGET)
    if args.multi and args.verify is not None:
        parser.error(ERR_MULTI_WITH_VERIFY)
    try:
        result = calculate(
            args.target,
            file=args.file,
            stdin=args.stdin,
            multi=args.multi,
            algorithm=args.algorithm,
            verify=args.verify,
        )
    except OSError as exc:
        sys.stderr.write(_format_io_error(args, exc) + '\n')
        return 1
    except ValueError as exc:
        sys.stderr.write(ERR_GENERIC.format(exc=exc) + '\n')
        return 1
    # --- processing results ---
    for warning in result.warnings:
        sys.stderr.write(warning + '\n')
    if result.verified is not None:
        sys.stdout.write(
            (MSG_VERIFIED if result.verified else MSG_MISMATCH) + '\n'
        )
        return 0 if result.verified else 2
    if args.multi:
        sys.stdout.write(_format_dict(result.digests) + '\n')
        return 0
    sys.stdout.write(next(iter(result.digests.values())) + '\n')
    return 0


if __name__ == '__main__':
    sys.exit(main())
