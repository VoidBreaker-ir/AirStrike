"""
Saved_AP - Wi-Fi Saved Profile Extractor
=========================================

A cross-platform utility that retrieves Wi-Fi SSIDs and their saved
passwords from the operating system's credential store.

Supported platforms:
    - Linux  : Reads NetworkManager connection files under
               /etc/NetworkManager/system-connections/*.nmconnection
    - Windows: Uses `netsh wlan show profiles` and
               `netsh wlan show profiles name=<SSID> key=clear`

Unsupported platforms raise a ValueError.

WARNING:
    Reading saved Wi-Fi passwords may require administrative privileges.
    On Linux, NetworkManager files are typically root-only (mode 0600).
    On Windows, `netsh ... key=clear` requires an elevated shell in
    some configurations. Use responsibly and only on systems you own
    or are authorized to audit.

Usage (as a library):
    from saved_ap import Saved_AP

    s = Saved_AP()
    s.start()               # scan the system, populate s.AP
    print(s.list_AP())      # -> [("MyWiFi", "hunter2"), ...]
    print(s.to_table())     # pretty table (requires `tabulate`)
    s.save("wifi.json", indent=4)

Usage (as a script):
    python saved_ap.py
"""

import os
import json
import subprocess
import platform

try:
    import tabulate as tabulate_module
except ImportError:
    tabulate_module = None


class Saved_AP:
    """
    Extract and manage saved Wi-Fi credentials from the host OS.

    Attributes:
        AP (dict[str, str]):
            Mapping of SSID -> plaintext password (or empty string for
            open networks whose credentials were not recoverable).
        status (bool):
            Whether the OS scan has already been performed. Used to make
            `start()` and `_check()` idempotent so repeated calls do not
            re-query the OS.
    """

    def __init__(self):
        """Initialize an empty store with no scan performed yet."""
        self.AP = {}
        self.status = False

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _run_code(self, text: str, timeout: int = 10) -> str:
        """
        Execute a shell command and return its combined stdout + stderr.

        This is used internally to invoke OS tools such as `netsh` on
        Windows. All exceptions are caught and returned as error strings
        so the caller can keep running without crashing.

        Args:
            text (str): The shell command to execute.
            timeout (int): Seconds to wait before aborting. Default is 10.

        Returns:
            str: Combined stdout and stderr, or an error message prefixed
                 with "Error: ..." if the command failed or timed out.
        """
        try:
            result = subprocess.run(
                text,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            return result.stdout + result.stderr

        except subprocess.TimeoutExpired:
            return f"Error: The command did not complete after {timeout} seconds"
        except Exception as e:
            return f"Error executing command: {e}"

    def _check(self):
        """
        Ensure the OS scan has been performed.

        If `self.status` is False, calls `start()` to populate
        `self.AP`. This is the lazy-load entry point used by public
        methods such as `list_AP()`, `to_table()`, and `save()`.
        """
        if not self.status:
            self.start()

    # ------------------------------------------------------------------
    # Platform-specific scanners
    # ------------------------------------------------------------------

    def linux(self):
        """
        Scan NetworkManager connection files for saved SSIDs/passwords.

        Reads every `*.nmconnection` file inside
        `/etc/NetworkManager/system-connections/` and extracts the
        `psk=` line from each one (the WPA pre-shared key).

        Behavior:
            - Files that are unreadable (typically root-only) are
              silently skipped instead of aborting the scan.
            - Files without a `psk=` line (e.g. open networks, or
              networks using 802.1X) are ignored.
            - Non-UTF-8 bytes are tolerated via errors="ignore".

        Raises:
            FileNotFoundError: If the NetworkManager directory is
                missing (e.g. NetworkManager is not installed or the
                system uses a different network stack).
        """
        path = "/etc/NetworkManager/system-connections"

        if not os.path.isdir(path):
            raise FileNotFoundError(f"NetworkManager path not found: {path}")

        for filename in os.listdir(path):
            if not filename.endswith(".nmconnection"):
                continue

            ssid = filename[: -len(".nmconnection")]
            full_path = os.path.join(path, filename)

            try:
                with open(full_path, encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        line = line.strip()
                        if line.startswith("psk="):
                            self.AP[ssid] = line[4:].strip()
                            break
            except PermissionError:
                # Skip files the current user cannot read.
                continue
            except OSError:
                # Skip any other filesystem-level issue.
                continue

        self.status = True

    def windows(self, timeout: int = 20):
        """
        Scan Windows Wi-Fi profiles via `netsh`.

        Runs two `netsh` commands:
            1. `netsh wlan show profiles`
               -> lists all saved profile names (SSIDs).
            2. `netsh wlan show profiles name="<SSID>" key=clear`
               -> prints details including the plaintext key, which
                  appears on the line "Key Content : <password>".

        Args:
            timeout (int): Per-command timeout in seconds. Default is 20,
                which is intentionally larger than the Linux path because
                `netsh` can be slow on systems with many profiles.

        Notes:
            - The SSID is quoted in the second command to support names
              containing spaces.
            - `split(":", 1)` is used to preserve colons inside SSIDs.
            - Open networks (no "Key Content" line) are simply skipped.
        """
        output = self._run_code("netsh wlan show profiles", timeout=timeout)

        for line in output.splitlines():
            line = line.strip()

            if line.startswith("All User Profile"):
                ssid = line.split(":", 1)[1].strip()

                detail = self._run_code(
                    f'netsh wlan show profiles name="{ssid}" key=clear',
                    timeout=timeout,
                )

                for detail_line in detail.splitlines():
                    detail_line = detail_line.strip()
                    if detail_line.startswith("Key Content"):
                        password = detail_line.split(":", 1)[1].strip()
                        self.AP[ssid] = password
                        break

        self.status = True

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def save(self, namefile: str, *args, **kwargs):
        """
        Serialize the extracted AP dictionary to a JSON file.

        Args:
            namefile (str): Destination file path.
            *args, **kwargs: Forwarded directly to `json.dump`, so
                arguments like `indent=4` or `ensure_ascii=False` work
                as expected.

        Side effects:
            Triggers `_check()` so the OS scan runs on first use.
        """
        self._check()
        with open(namefile, "w", encoding="utf-8") as file:
            json.dump(self.AP, file, *args, **kwargs)

    def list_AP(self):
        """
        Return the extracted credentials as a list of tuples.

        Returns:
            list[tuple[str, str]]: A list of (SSID, password) pairs,
                in insertion order.

        Side effects:
            Triggers `_check()` so the OS scan runs on first use.
        """
        self._check()
        return list(self.AP.items())

    def to_table(self, tablefmt: str = "rounded_grid", *args, **kwargs):
        """
        Render the extracted credentials as a formatted text table.

        Uses the optional `tabulate` package. If `tabulate` is not
        installed, an ImportError is raised with an install hint.

        Args:
            tablefmt (str): Any format supported by `tabulate`
                (e.g. "rounded_grid", "github", "grid", "plain").
                Default is "rounded_grid".
            *args, **kwargs: Additional arguments forwarded to
                `tabulate.tabulate`.

        Returns:
            str: A printable table with headers "SSID" and "Password".

        Raises:
            ImportError: If `tabulate` is not installed.

        Side effects:
            Triggers `_check()` so the OS scan runs on first use.
        """
        self._check()

        if tabulate_module is None:
            raise ImportError(
                "tabulate is not installed. Install it with: pip install tabulate"
            )

        headers = ["SSID", "Password"]
        rows = [[ssid, password] for ssid, password in self.AP.items()]
        return tabulate_module.tabulate(
            rows, headers, *args, tablefmt=tablefmt, **kwargs
        )

    def start(self):
        """
        Detect the current OS and run the appropriate scanner.

        Idempotent: if the scan has already been performed
        (`self.status is True`), this method returns immediately with
        the cached `self.AP` dictionary.

        Returns:
            dict[str, str]: The populated AP mapping.

        Raises:
            ValueError: If the current platform is neither Windows
                nor Linux. macOS and BSD are not supported.
        """
        if self.status:
            return self.AP

        system = platform.system()
        if system == "Windows":
            self.windows()
        elif system == "Linux":
            self.linux()
        else:
            raise ValueError(f"Unsupported platform: {system}")

        return self.AP


# ----------------------------------------------------------------------
# Script entry point
# ----------------------------------------------------------------------

if __name__ == "__main__":
    s = Saved_AP()
    try:
        print(s.to_table())
    except (ImportError, FileNotFoundError, PermissionError) as e:
        print(f"[!] {e}")

    # Save to a file in the current working directory so the example is
    # portable across Windows, Linux, and macOS.
    s.save("file.json", indent=4)