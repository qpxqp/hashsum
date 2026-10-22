"""Tests for hashsum."""
import hashlib
import io

import pytest

from hashsum import (
    MSG_MISMATCH,
    MSG_VERIFIED,
    MULTI_ALGORITHMS,
    HashResult,
    calculate,
    hash_data,
    hash_file,
    hash_file_multi,
    hash_multi,
    hash_stdin,
    hash_stdin_multi,
    main,
    normalize_algorithm,
    normalize_expected_hash,
)

# Reference values for the string "test"
SHA256_TEST = (
    '9f86d081884c7d659a2feaa0c55ad015'
    'a3bf4f1b2b0b822cd15d6c15b0f00a08'
)
MD5_TEST = '098f6bcd4621d373cade4e832627b4f6'
SHA1_TEST = 'a94a8fe5ccb19ba61c4c0873d391e987982fbbd3'


class FakeStdin:
    """Mock sys.stdin with a binary .buffer."""
    def __init__(self, data: bytes):
        self.buffer = io.BytesIO(data)


class TestEmptyInput:
    def test_empty_string(self) -> None:
        empty_sha256 = (
            'e3b0c44298fc1c149afbf4c8996fb924'
            '27ae41e4649b934ca495991b7852b855'
        )
        assert hash_data('') == empty_sha256


# ---------- hash_data ----------

class TestHashData:
    @pytest.mark.parametrize('algorithm, expected', [
        ('sha256', SHA256_TEST),
        ('md5', MD5_TEST),
        ('sha1', SHA1_TEST),
    ])
    def test_known_vectors(self, algorithm: str, expected: str) -> None:
        assert hash_data('test', algorithm) == expected

    def test_bytes_input(self) -> None:
        assert hash_data(b'test') == SHA256_TEST

    def test_default_algorithm(self) -> None:
        assert hash_data('test') == SHA256_TEST

    def test_utf8_encoding(self) -> None:
        # Cyrillic is encoded in UTF-8
        result = hash_data('тест')
        assert result == hashlib.sha256('тест'.encode()).hexdigest()

    def test_unknown_algorithm_raises(self) -> None:
        with pytest.raises(ValueError, match='unavailable'):
            hash_data('test', 'nope')


# ---------- XOF ----------

class TestXOF:
    @pytest.mark.parametrize('algorithm', ['shake_128', 'shake_256'])
    def test_length(self, algorithm: str) -> None:
        result = hash_data('test', algorithm, xof_len=64)
        assert len(result) == 64 * 2  # 128 hex symbols

    def test_shake_128_differs_from_shake_256(self) -> None:
        assert hash_data('test', 'shake_128') != hash_data('test', 'shake_256')


# ---------- hash_file ----------

class TestHashFile:
    def test_reads_file(self, tmp_path) -> None:
        f = tmp_path / 'data.bin'
        f.write_bytes(b'test')
        assert hash_file(f) == SHA256_TEST

    def test_str_path(self, tmp_path) -> None:
        f = tmp_path / 'data.bin'
        f.write_bytes(b'test')
        assert hash_file(str(f)) == SHA256_TEST

    def test_missing_file(self, tmp_path) -> None:
        with pytest.raises(FileNotFoundError):
            hash_file(tmp_path / 'nope.bin')


class TestHashFileErrors:
    def test_directory_raises(self, tmp_path) -> None:
        # Linux - IsADirectoryError, Windows - PermissionError
        with pytest.raises((IsADirectoryError, PermissionError)):
            hash_file(tmp_path)


# ---------- hash_stdin ----------

class TestHashStdin:
    def test_single(self, monkeypatch) -> None:
        monkeypatch.setattr('sys.stdin', FakeStdin(b'test'))
        assert hash_stdin() == SHA256_TEST

    def test_multi(self, monkeypatch) -> None:
        monkeypatch.setattr('sys.stdin', FakeStdin(b'test'))
        result = hash_stdin_multi()
        assert result['sha256'] == SHA256_TEST


# ---------- hash_multi ----------

class TestHashMulti:
    def test_returns_all_available(self) -> None:
        result = hash_multi('test')
        for alg in MULTI_ALGORITHMS:
            assert alg in result

    def test_sha256_value(self) -> None:
        assert hash_multi('test')['sha256'] == SHA256_TEST


class TestHashFileMulti:
    def test_reads_file(self, tmp_path) -> None:
        f = tmp_path / 'data.bin'
        f.write_bytes(b'test')
        result = hash_file_multi(f)
        assert result['sha256'] == SHA256_TEST


# ---------- normalize_algorithm ----------

class TestNormalizeAlgorithm:
    def test_lowercase(self) -> None:
        assert normalize_algorithm('SHA256') == 'sha256'

    def test_strip(self) -> None:
        assert normalize_algorithm('  sha256  ') == 'sha256'

    def test_unknown(self) -> None:
        with pytest.raises(ValueError, match='unavailable'):
            normalize_algorithm('nope')


# ---------- normalize_expected_hash ----------

class TestNormalizeExpectedHash:
    def test_lowercase(self) -> None:
        value, warning = normalize_expected_hash(SHA256_TEST.upper(), 'sha256')
        assert value == SHA256_TEST
        assert warning is None

    def test_strip(self) -> None:
        value, warning = normalize_expected_hash(f'  {SHA256_TEST}\n', 'sha256')
        assert value == SHA256_TEST
        assert warning is None

    def test_empty(self) -> None:
        with pytest.raises(ValueError, match='empty'):
            normalize_expected_hash('')

    def test_not_hex(self) -> None:
        with pytest.raises(ValueError, match='hex'):
            normalize_expected_hash('zzz')

    def test_wrong_length_warns(self) -> None:
        value, warning = normalize_expected_hash('deadbeef', 'sha256')
        assert value == 'deadbeef'
        assert warning is not None
        assert '64' in warning

    def test_xof_warns_on_wrong_length_with_custom_len(self) -> None:
        # With xof_len=16, 32 hex characters are expected. We'll give it 10.
        _, warning = normalize_expected_hash('a' * 10, 'shake_128', xof_len=16)
        assert warning is not None
        assert '32' in warning

    def test_xof_warns_on_wrong_length(self) -> None:
        # SHAKE uses xof_len (default 32 bytes = 64 hex chars).
        # Providing 10 chars should trigger a warning.
        _, warning = normalize_expected_hash('a' * 10, 'shake_128')
        assert warning is not None
        assert '64' in warning

    def test_xof_custom_len(self) -> None:
        # If we explicitly ask for a 16-byte XOF hash (32 hex chars),
        # providing a 32-char hash should NOT trigger a warning.
        _, warning = normalize_expected_hash('a' * 32, 'shake_128', xof_len=16)
        assert warning is None


# ---------- calculate ----------

class TestCalculateSimple:
    def test_returns_hashresult(self) -> None:
        res = calculate('test')
        assert isinstance(res, HashResult)
        assert res.digests == {'sha256': SHA256_TEST}
        assert res.verified is None
        assert res.warnings == ()

    def test_custom_algorithm(self) -> None:
        res = calculate('test', algorithm='md5')
        assert res.digests == {'md5': MD5_TEST}

    def test_no_target_raises(self) -> None:
        with pytest.raises(ValueError, match='specify a string'):
            calculate(None)


class TestCalculateFile:
    def test_file(self, tmp_path) -> None:
        f = tmp_path / 'data.bin'
        f.write_bytes(b'test')
        res = calculate(str(f), file=True)
        assert res.digests == {'sha256': SHA256_TEST}

    def test_multi_file(self, tmp_path) -> None:
        f = tmp_path / 'data.bin'
        f.write_bytes(b'test')
        res = calculate(str(f), file=True, multi=True)
        assert res.digests['sha256'] == SHA256_TEST


class TestCalculateStdin:
    def test_stdin(self, monkeypatch) -> None:
        monkeypatch.setattr('sys.stdin', FakeStdin(b'test'))
        res = calculate(stdin=True)
        assert res.digests == {'sha256': SHA256_TEST}

    def test_stdin_multi(self, monkeypatch) -> None:
        monkeypatch.setattr('sys.stdin', FakeStdin(b'test'))
        res = calculate(stdin=True, multi=True)
        assert res.digests['sha256'] == SHA256_TEST


class TestCalculateVerify:
    def test_ok(self) -> None:
        res = calculate('test', verify=SHA256_TEST)
        assert res.verified is True
        assert res.warnings == ()

    def test_mismatch(self) -> None:
        res = calculate('test', verify='a' * 64)
        assert res.verified is False
        assert res.warnings == ()

    def test_mismatch_wrong_length_warns(self) -> None:
        res = calculate('test', verify='deadbeef')
        assert res.verified is False
        assert len(res.warnings) == 1
        assert '64' in res.warnings[0]

    def test_case_insensitive(self) -> None:
        res = calculate('test', verify=SHA256_TEST.upper())
        assert res.verified is True

    def test_invalid_hex_raises(self) -> None:
        with pytest.raises(ValueError, match='hex'):
            calculate('test', verify='zzz')

    def test_verify_file(self, tmp_path) -> None:
        f = tmp_path / 'data.bin'
        f.write_bytes(b'test')
        res = calculate(str(f), file=True, verify=SHA256_TEST)
        assert res.verified is True


class TestCalculateMulti:
    def test_multi_string(self) -> None:
        res = calculate('test', multi=True)
        assert res.verified is None
        assert res.warnings == ()
        for alg in MULTI_ALGORITHMS:
            assert alg in res.digests


class TestCalculateConflicts:
    def test_multi_and_verify_raises(self) -> None:
        with pytest.raises(ValueError, match='cannot be used together'):
            calculate('test', multi=True, verify=SHA256_TEST)

    def test_file_and_stdin_raises(self) -> None:
        with pytest.raises(ValueError, match='Cannot use both'):
            calculate('test', file=True, stdin=True)


# ---------- CLI ----------

class TestCLI:
    def test_cli_hash(self, capsys) -> None:
        exit_code = main(["test"])
        assert exit_code == 0
        captured = capsys.readouterr()
        assert captured.out.strip() == SHA256_TEST

    def test_cli_multi(self, capsys) -> None:
        exit_code = main(["test", "--multi"])
        assert exit_code == 0
        captured = capsys.readouterr()
        assert 'sha256' in captured.out
        assert SHA256_TEST in captured.out

    def test_cli_verify_ok(self, capsys) -> None:
        exit_code = main(["test", "--verify", SHA256_TEST])
        assert exit_code == 0
        captured = capsys.readouterr()
        assert MSG_VERIFIED in captured.out

    def test_cli_verify_mismatch(self, capsys) -> None:
        exit_code = main(["test", "--verify", "a" * 64])
        assert exit_code == 2
        captured = capsys.readouterr()
        assert MSG_MISMATCH in captured.out

    def test_cli_warning_on_bad_length(self, capsys) -> None:
        exit_code = main(["test", "--verify", "deadbeef"])
        assert exit_code == 2
        captured = capsys.readouterr()
        assert MSG_MISMATCH in captured.out
        assert 'Warning: hash length is 8' in captured.err

    def test_cli_missing_file(self, capsys) -> None:
        exit_code = main(["-f", "nonexistent_file.bin"])
        assert exit_code == 1
        captured = capsys.readouterr()
        assert 'File not found' in captured.err

    def test_cli_invalid_args(self) -> None:
        with pytest.raises(SystemExit) as exc_info:
            main(["--multi", "--verify", "somehash"])
        assert exc_info.value.code == 2

    def test_cli_directory(self, tmp_path, capsys) -> None:
        exit_code = main(["-f", str(tmp_path)])
        assert exit_code == 1
        captured = capsys.readouterr()
        assert captured.err != ''

    def test_cli_xof_len(self, capsys) -> None:
        # Request 16 bytes (32 hex chars) from shake_128
        exit_code = main(["test", "-a", "shake_128", "--xof-len", "16"])
        assert exit_code == 0
        captured = capsys.readouterr()
        assert len(captured.out.strip()) == 32
