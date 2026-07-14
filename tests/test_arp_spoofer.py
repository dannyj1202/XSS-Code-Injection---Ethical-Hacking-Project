"""Tests for ARP Spoofer."""

import io
from unittest.mock import Mock, mock_open, patch

import pytest

from src.mitm.arp_spoofer import ARPSpoofer


class TestARPSpoofer:
    def test_spoof_skips_target_after_max_retries(self):
        spoofer = ARPSpoofer(targets={"192.168.1.10"}, gateway="192.168.1.1", interface="eth0", verbose=False)
        spoofer.target_macs = {"192.168.1.10": "aa:bb:cc:dd:ee:ff"}
        spoofer.gateway_mac = "11:22:33:44:55:66"
        spoofer.running = True

        call_count = 0

        def failing_send(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            raise Exception("Mock send error")
            
        loop_count = 0
        def mock_sleep(*args, **kwargs):
            nonlocal loop_count
            loop_count += 1
            if loop_count >= 4:
                spoofer.running = False

        with patch("src.mitm.arp_spoofer.send", side_effect=failing_send), patch("time.sleep", side_effect=mock_sleep):  # Speed up test
                spoofer.spoof()

        # It should try 3 times, fail, mark target as max retries,
        # and on the 4th loop it should skip it entirely (not calling send)
        # So send is only called 3 times.
        assert call_count == 3

    def test_spoof_continues_with_other_targets_on_error(self):
        spoofer = ARPSpoofer(targets={"192.168.1.10", "192.168.1.11"}, gateway="192.168.1.1", interface="eth0")
        spoofer.target_macs = {
            "192.168.1.10": "aa:bb:cc:dd:ee:ff",
            "192.168.1.11": "ff:ee:dd:cc:bb:aa"
        }
        spoofer.gateway_mac = "11:22:33:44:55:66"
        spoofer.running = True

        loop_count = 0
        sent_packets = []

        def selective_send(pkt, **kwargs):
            nonlocal loop_count
            if pkt.pdst == "192.168.1.10":
                raise Exception("Error on .10")
            else:
                sent_packets.append(pkt)

            # Break loop after one full iteration
            if pkt.pdst == "192.168.1.11" and pkt.psrc == "192.168.1.1":
                loop_count += 1
                if loop_count >= 1:
                    spoofer.running = False

        with patch("src.mitm.arp_spoofer.send", side_effect=selective_send), patch("time.sleep"):
                spoofer.spoof()

        # Packets for .11 should still be sent
        assert len(sent_packets) > 0
        assert any(p.pdst == "192.168.1.11" for p in sent_packets)

    def test_enable_ip_forwarding_saves_original(self):
        spoofer = ARPSpoofer(targets=set(), gateway="", interface="")

        mock_file = mock_open(read_data="0\n")
        
        with patch("builtins.open", mock_file):
            spoofer._enable_ip_forwarding()
            
        assert spoofer._original_ip_forward == "0"
        mock_file().write.assert_called_with("1")

    def test_restore_ip_forwarding(self):
        spoofer = ARPSpoofer(targets=set(), gateway="", interface="")
        spoofer._original_ip_forward = "0"

        mock_file = mock_open()
        
        with patch("builtins.open", mock_file):
            spoofer._restore_ip_forwarding()
            
        mock_file().write.assert_called_with("0")

    def test_restore_arp_sends_correct_packets(self):
        spoofer = ARPSpoofer(targets={"192.168.1.10"}, gateway="192.168.1.1", interface="eth0")
        spoofer.target_macs = {"192.168.1.10": "aa:bb:cc:dd:ee:ff"}
        spoofer.gateway_mac = "11:22:33:44:55:66"

        sent_packets = []

        def mock_send(pkt, **kwargs):
            sent_packets.append(pkt)

        with patch("src.mitm.arp_spoofer.send", side_effect=mock_send):
            spoofer.restore_arp()

        assert len(sent_packets) == 2

        # Target restore packet: Tell target (.10) the gateway (.1) is at the real gateway MAC
        target_restore = sent_packets[0]
        assert target_restore.pdst == "192.168.1.10"
        assert target_restore.hwdst == "aa:bb:cc:dd:ee:ff"
        assert target_restore.psrc == "192.168.1.1"
        assert target_restore.hwsrc == "11:22:33:44:55:66"

        # Gateway restore packet: Tell gateway (.1) the target (.10) is at the real target MAC
        gateway_restore = sent_packets[1]
        assert gateway_restore.pdst == "192.168.1.1"
        assert gateway_restore.hwdst == "11:22:33:44:55:66"
        assert gateway_restore.psrc == "192.168.1.10"
        assert gateway_restore.hwsrc == "aa:bb:cc:dd:ee:ff"

    def test_cleanup_calls_stop_and_restore(self):
        spoofer = ARPSpoofer(targets=set(), gateway="", interface="")

        with patch.object(spoofer, 'stop') as mock_stop, patch.object(spoofer, '_restore_ip_forwarding') as mock_restore:
                spoofer.cleanup()

        mock_stop.assert_called_once()
        mock_restore.assert_called_once()

    def test_get_mac_raises_on_failure(self):
        spoofer = ARPSpoofer(targets=set(), gateway="", interface="")

        with patch("src.mitm.arp_spoofer.getmacbyip", return_value=None), pytest.raises(Exception, match="Could not resolve MAC"):
                spoofer.get_mac("192.168.1.10")
