"""Tests for iptables rule command generation."""

from src.mitm.iptables_manager import IptablesManager, IptablesRule


def test_nfqueue_rule_commands() -> None:
    rule = IptablesRule(args=["-p", "tcp", "--dport", "80", "-j", "NFQUEUE", "--queue-num", "0"])
    assert rule.add_cmd() == [
        "iptables",
        "-A",
        "FORWARD",
        "-p",
        "tcp",
        "--dport",
        "80",
        "-j",
        "NFQUEUE",
        "--queue-num",
        "0",
    ]
    assert rule.delete_cmd()[1] == "-D"


def test_default_rules_include_masquerade() -> None:
    mgr = IptablesManager(queue_num=0, interface="eth0")
    assert len(mgr._rules) == 2
    assert mgr._rules[1].table == "nat"
