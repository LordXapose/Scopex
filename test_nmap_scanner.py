"""
Tests for the SCOPEX controlled Nmap scanner.
"""

from pathlib import Path
from unittest.mock import patch

import pytest

from scopex.nmap.scanner import (
    NmapExecutionError,
    NmapNotFoundError,
    NmapScanner,
)


def test_scanner_uses_existing_executable():
    scanner = NmapScanner(
        executable=Path(r"C:\Program Files (x86)\Nmap\nmap.exe")
    )

    assert scanner.executable.endswith("nmap.exe")


def test_scanner_rejects_missing_executable():
    with pytest.raises(NmapNotFoundError):
        NmapScanner(
            executable=Path(
                r"C:\does-not-exist\nmap.exe"
            )
        )


def test_build_command():
    scanner = NmapScanner(
        executable="nmap"
    )

    command = scanner.build_command(
        target="203.0.113.10",
        ports="22,80,443",
    )

    assert command == [
        "nmap",
        "-Pn",
        "-sT",
        "-sV",
        "-p",
        "22,80,443",
        "-oX",
        "-",
        "203.0.113.10",
    ]


def test_build_command_rejects_empty_target():
    scanner = NmapScanner(
        executable="nmap"
    )

    with pytest.raises(ValueError):
        scanner.build_command("")


def test_build_command_rejects_empty_ports():
    scanner = NmapScanner(
        executable="nmap"
    )

    with pytest.raises(ValueError):
        scanner.build_command(
            "203.0.113.10",
            "",
        )


@patch("scopex.nmap.scanner.subprocess.run")
def test_scan_returns_xml(mock_run):
    mock_run.return_value.returncode = 0
    mock_run.return_value.stdout = "<nmaprun></nmaprun>"
    mock_run.return_value.stderr = ""

    scanner = NmapScanner(
        executable="nmap"
    )

    result = scanner.scan(
        target="203.0.113.10",
        ports="22",
    )

    assert result == "<nmaprun></nmaprun>"

    mock_run.assert_called_once()

    command = mock_run.call_args.args[0]

    assert command[-1] == "203.0.113.10"
    assert "-oX" in command


@patch("scopex.nmap.scanner.subprocess.run")
def test_scan_uses_shell_false(mock_run):
    mock_run.return_value.returncode = 0
    mock_run.return_value.stdout = "<nmaprun></nmaprun>"
    mock_run.return_value.stderr = ""

    scanner = NmapScanner(
        executable="nmap"
    )

    scanner.scan(
        target="203.0.113.10"
    )

    kwargs = mock_run.call_args.kwargs

    assert kwargs["shell"] is False


@patch("scopex.nmap.scanner.subprocess.run")
def test_scan_rejects_nonzero_exit(mock_run):
    mock_run.return_value.returncode = 2
    mock_run.return_value.stdout = ""
    mock_run.return_value.stderr = "Nmap error"

    scanner = NmapScanner(
        executable="nmap"
    )

    with pytest.raises(NmapExecutionError) as exc_info:
        scanner.scan(
            target="203.0.113.10"
        )

    assert "Nmap exited with code 2" in str(
        exc_info.value
    )


@patch("scopex.nmap.scanner.subprocess.run")
def test_scan_rejects_empty_output(mock_run):
    mock_run.return_value.returncode = 0
    mock_run.return_value.stdout = ""
    mock_run.return_value.stderr = ""

    scanner = NmapScanner(
        executable="nmap"
    )

    with pytest.raises(NmapExecutionError):
        scanner.scan(
            target="203.0.113.10"
        )


@patch("scopex.nmap.scanner.subprocess.run")
def test_scan_handles_timeout(mock_run):
    import subprocess

    mock_run.side_effect = subprocess.TimeoutExpired(
        cmd=["nmap"],
        timeout=300,
    )

    scanner = NmapScanner(
        executable="nmap",
        timeout=300,
    )

    with pytest.raises(NmapExecutionError) as exc_info:
        scanner.scan(
            target="203.0.113.10"
        )

    assert "timed out" in str(
        exc_info.value
    ).lower()


@patch(
    "scopex.nmap.scanner.subprocess.run",
    side_effect=FileNotFoundError(),
)
def test_scan_handles_missing_nmap(mock_run):
    scanner = NmapScanner(
        executable="nmap"
    )

    with pytest.raises(NmapNotFoundError):
        scanner.scan(
            target="203.0.113.10"
        )