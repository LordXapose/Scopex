"""
Controlled Nmap subprocess execution.

This module is responsible only for invoking Nmap and returning
its XML output. It does not parse results or persist database data.
"""

from __future__ import annotations

import subprocess
from pathlib import Path


class NmapScannerError(RuntimeError):
    """Base exception for Nmap scanner failures."""


class NmapNotFoundError(NmapScannerError):
    """Raised when the Nmap executable cannot be found."""


class NmapExecutionError(NmapScannerError):
    """Raised when Nmap execution fails."""


class NmapScanner:
    """
    Execute controlled Nmap scans.

    The scanner never invokes a shell. Arguments are passed directly
    to subprocess.run() as a list.
    """

    DEFAULT_TIMEOUT = 300

    def __init__(
        self,
        executable: str | Path | None = None,
        timeout: int = DEFAULT_TIMEOUT,
    ) -> None:
        self.executable = self._resolve_executable(executable)
        self.timeout = timeout

    @staticmethod
    def _resolve_executable(
        executable: str | Path | None,
    ) -> str:
        """
        Resolve the Nmap executable.

        Explicit filesystem paths must exist.

        Bare executable names such as "nmap" are allowed so that
        subprocess can resolve them through the Windows PATH.
        """

        if executable is not None:
            value = str(executable).strip()

            if not value:
                raise NmapNotFoundError(
                    "Nmap executable cannot be empty."
                )

            path = Path(value)

            # Bare executable name, e.g. "nmap".
            # Let Windows/subprocess resolve it through PATH.
            if (
                len(path.parts) == 1
                and not path.is_absolute()
            ):
                return value

            if path.exists() and path.is_file():
                return str(path)

            raise NmapNotFoundError(
                f"Nmap executable does not exist: {path}"
            )

        windows_candidates = [
            Path(r"C:\Program Files\Nmap\nmap.exe"),
            Path(r"C:\Program Files (x86)\Nmap\nmap.exe"),
        ]

        for candidate in windows_candidates:
            if candidate.exists() and candidate.is_file():
                return str(candidate)

        # Fall back to PATH.
        return "nmap"

    def build_command(
        self,
        target: str,
        ports: str = "1-1024",
    ) -> list[str]:
        """
        Build a controlled Nmap command.

        XML output is written to stdout using -oX -.

        - -Pn prevents host discovery from causing false negatives
          when scanning an explicitly authorized target.
        - -sT uses a TCP connect scan and does not require raw packet
          privileges.
        - -sV enables service/version detection.
        """

        if not target or not target.strip():
            raise ValueError("Nmap target cannot be empty.")

        if not ports or not ports.strip():
            raise ValueError(
                "Nmap port specification cannot be empty."
            )

        return [
            self.executable,
            "-Pn",
            "-sT",
            "-sV",
            "-p",
            ports,
            "-oX",
            "-",
            target.strip(),
        ]

    def scan(
        self,
        target: str,
        ports: str = "1-1024",
    ) -> str:
        """
        Execute Nmap and return its XML output.

        Raises:
            NmapExecutionError:
                If Nmap exits unsuccessfully or times out.
        """

        command = self.build_command(
            target=target,
            ports=ports,
        )

        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                check=False,
                shell=False,
            )

        except FileNotFoundError as exc:
            raise NmapNotFoundError(
                "Nmap executable was not found. "
                "Install Nmap or provide its executable path."
            ) from exc

        except subprocess.TimeoutExpired as exc:
            raise NmapExecutionError(
                f"Nmap scan timed out after {self.timeout} seconds."
            ) from exc

        except OSError as exc:
            raise NmapExecutionError(
                f"Unable to execute Nmap: {exc}"
            ) from exc

        if completed.returncode != 0:
            stderr = completed.stderr.strip()

            message = (
                f"Nmap exited with code {completed.returncode}."
            )

            if stderr:
                message += f" {stderr}"

            raise NmapExecutionError(message)

        if not completed.stdout.strip():
            raise NmapExecutionError(
                "Nmap completed successfully but returned empty XML output."
            )

        return completed.stdout