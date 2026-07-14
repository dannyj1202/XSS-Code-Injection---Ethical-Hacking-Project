"""iptables rule management with guaranteed cleanup on exit."""

import subprocess
from dataclasses import dataclass, field


@dataclass
class IptablesRule:
    """Single iptables rule expressed as table/chain/args for -A/-D."""

    table: str = "filter"
    chain: str = "FORWARD"
    args: list[str] = field(default_factory=list)

    def add_cmd(self) -> list[str]:
        cmd = ["iptables"]
        if self.table != "filter":
            cmd.extend(["-t", self.table])
        cmd.extend(["-A", self.chain, *self.args])
        return cmd

    def delete_cmd(self) -> list[str]:
        cmd = ["iptables"]
        if self.table != "filter":
            cmd.extend(["-t", self.table])
        cmd.extend(["-D", self.chain, *self.args])
        return cmd


class IptablesManager:
    """Install and remove the standard lab iptables rules."""

    def __init__(self, queue_num: int = 0, interface: str = "eth0", verbose: bool = False) -> None:
        self.queue_num = queue_num
        self.interface = interface
        self.verbose = verbose
        self.installed = False
        self._rules: list[IptablesRule] = self._default_rules()

    def _default_rules(self) -> list[IptablesRule]:
        return [
            IptablesRule(
                args=[
                    "-p",
                    "tcp",
                    "--dport",
                    "80",
                    "-j",
                    "NFQUEUE",
                    "--queue-num",
                    str(self.queue_num),
                ]
            ),
            IptablesRule(
                table="nat",
                chain="POSTROUTING",
                args=["-o", self.interface, "-j", "MASQUERADE"],
            ),
        ]

    def _run(self, cmd: list[str]) -> bool:
        try:
            subprocess.run(cmd, check=True, capture_output=True, text=True)
            return True
        except (subprocess.CalledProcessError, FileNotFoundError) as exc:
            if self.verbose:
                print(f"iptables command failed ({' '.join(cmd)}): {exc}")
            return False

    def install_rules(self) -> bool:
        """Append the NFQUEUE and MASQUERADE rules."""
        success = True
        for rule in self._rules:
            if not self._run(rule.add_cmd()):
                success = False
        self.installed = success
        if self.verbose and success:
            print("iptables rules installed")
        return success

    def remove_rules(self) -> None:
        """Delete the lab rules. Safe to call even if install_rules() was not used."""
        for rule in reversed(self._rules):
            self._run(rule.delete_cmd())
        self.installed = False
        if self.verbose:
            print("iptables rules flushed")
