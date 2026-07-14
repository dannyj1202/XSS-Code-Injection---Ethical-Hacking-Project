"""Safety gate for the lab-only MITM injection tool.

Every run must pass three independent checks before a single packet is
touched:

1. The operator explicitly passes ``--i-have-authorization`` (a human
   attestation, not a technical control, but it forces a deliberate act).
2. A ``TARGETS.txt`` allowlist file exists and contains at least one IP.
3. Every IP in that allowlist is RFC1918 private space. This prevents the
   tool from ever being pointed at a public/internet host even by mistake,
   since this project is scoped to isolated lab networks only.
"""

import ipaddress
from pathlib import Path
from typing import Set

# Standard EICAR antivirus test string (not malware). Used as the default,
# always-safe payload body so the tool can be demonstrated end-to-end
# without embedding anything that behaves maliciously.
EICAR_TEST_STRING = r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

# RFC1918 private address space. Targets outside these ranges are rejected
# so the tool cannot be pointed at a public IP even by operator mistake.
_PRIVATE_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)


class SafetyValidationError(Exception):
    """Raised when the safety gate rejects a run configuration."""


def _is_private(ip: str) -> bool:
    """Return True if ``ip`` falls within RFC1918 private address space."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError as exc:
        raise SafetyValidationError(f"'{ip}' in targets file is not a valid IP address") from exc
    return any(addr in network for network in _PRIVATE_NETWORKS)


class SafetyConfig:
    """Loads and validates the target allowlist before any packet is touched."""

    def __init__(self, targets_file: Path) -> None:
        self.targets_file = Path(targets_file)
        self.targets: Set[str] = set()

    def _load_targets(self) -> Set[str]:
        if not self.targets_file.exists():
            raise SafetyValidationError(
                f"Targets file not found: {self.targets_file}. "
                "Create it with one authorized lab IP per line, e.g.:\n"
                f"  echo '192.168.1.101' > {self.targets_file}"
            )

        targets: Set[str] = set()
        for raw_line in self.targets_file.read_text().splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            targets.add(line)

        if not targets:
            raise SafetyValidationError(
                f"Targets file '{self.targets_file}' contains no IP addresses."
            )

        return targets

    def validate(self, i_have_authorization: bool) -> None:
        """Run the full safety gate. Raises SafetyValidationError on any failure.

        On success, populates ``self.targets`` with the validated allowlist.
        """
        if not i_have_authorization:
            raise SafetyValidationError(
                "Refusing to run: pass --i-have-authorization to confirm you "
                "have written authorization for every target in this run."
            )

        targets = self._load_targets()

        non_private = sorted(ip for ip in targets if not _is_private(ip))
        if non_private:
            raise SafetyValidationError(
                "Refusing to run: targets file contains non-RFC1918 (non-private) "
                f"IPs, which this lab-only tool will never target: {non_private}"
            )

        self.targets = targets
