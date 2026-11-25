"""Tests for decodash.measure.wifi_link using captured command output."""

from __future__ import annotations

import json
import unittest
from unittest import mock

from decodash.measure import wifi_link

# ---------------------------------------------------------------------------
# macOS fixtures (system_profiler SPAirPortDataType -json)
# ---------------------------------------------------------------------------

MAC_SEQUOIA_6GHZ_BE = json.dumps({
    "SPAirPortDataType": [{
        "spairport_airport_interfaces": [
            {
                "_name": "en0",
                "spairport_airdrop_channel": 149,
                "spairport_caps_airdrop": "spairport_caps_supported",
                "spairport_current_network_information": {
                    "_name": "Home Deco",
                    "spairport_network_channel": "37 (6GHz, 320MHz)",
                    "spairport_network_country_code": "US",
                    "spairport_network_mcs": 11,
                    "spairport_network_phymode": "802.11be",
                    "spairport_network_rate": 2882,
                    "spairport_network_type": "spairport_network_type_station",
                    "spairport_security_mode": "spairport_security_mode_wpa3_personal",
                    "spairport_signal_noise": "-52 dBm / -95 dBm",
                },
                "spairport_other_local_wireless_networks": [{
                    "_name": "Neighbour",
                    "spairport_network_channel": "6 (2GHz, 20MHz)",
                    "spairport_network_phymode": "802.11b/g/n",
                    "spairport_signal_noise": "-80 dBm / -95 dBm",
                }],
                "spairport_status_information": "spairport_status_connected",
                "spairport_supported_channels": ["1 (2GHz)", "36 (5GHz)", "37 (6GHz)"],
                "spairport_supported_phymodes": "802.11 a/b/g/n/ac/ax/be",
                "spairport_wireless_card_type": "Wi-Fi (0x14E4, 0x4388)",
                "spairport_wireless_country_code": "US",
                "spairport_wireless_locale": "FCC",
                "spairport_wireless_mac_address": "aa:bb:cc:dd:ee:ff",
            },
            {
                "_name": "awdl0",
                "spairport_supported_channels": ["6 (2GHz)", "44 (5GHz)"],
                "spairport_wireless_mac_address": "12:34:56:78:9a:bc",
            },
        ],
        "spairport_software_information": {
            "spairport_corewlan_version": "16.0 (1657)",
            "spairport_diagnostics_version": "11.0 (1163)",
        },
    }],
}, indent=2)

MAC_SONOMA_5GHZ_AX = json.dumps({
    "SPAirPortDataType": [{
        "spairport_airport_interfaces": [{
            "_name": "en0",
            "spairport_current_network_information": {
                "_name": "Home Deco",
                "spairport_network_channel": "149 (5GHz, 80MHz)",
                "spairport_network_country_code": "GB",
                "spairport_network_mcs": 9,
                "spairport_network_phymode": "802.11ax",
                "spairport_network_rate": 1201,
                "spairport_network_type": "spairport_network_type_station",
                "spairport_security_mode": "spairport_security_mode_wpa2_personal",
                "spairport_signal_noise": "-58 dBm / -93 dBm",
            },
            "spairport_status_information": "spairport_status_connected",
            "spairport_supported_phymodes": "802.11 a/b/g/n/ac/ax",
        }],
    }],
})

MAC_REDACTED_SSID = json.dumps({
    "SPAirPortDataType": [{
        "spairport_airport_interfaces": [{
            "_name": "en0",
            "spairport_current_network_information": {
                "_name": "<redacted>",
                "spairport_network_channel": 44,
                "spairport_network_phymode": "802.11ac",
                "spairport_network_rate": "866",
                "spairport_signal_noise": "-67 dBm / -91 dBm",
            },
            "spairport_status_information": "spairport_status_connected",
        }],
    }],
})

MAC_NO_NETWORK = json.dumps({
    "SPAirPortDataType": [{
        "spairport_airport_interfaces": [
            {
                "_name": "en0",
                "spairport_status_information": "spairport_status_disconnected",
                "spairport_supported_phymodes": "802.11 a/b/g/n/ac/ax",
                "spairport_wireless_card_type": "Wi-Fi (0x14E4, 0x4378)",
            },
            {"_name": "awdl0"},
        ],
    }],
})

MAC_HARDWARE_PORTS = """
Hardware Port: Ethernet Adapter (en4)
Device: en4
Ethernet Address: 3a:1f:00:aa:bb:01

Hardware Port: Thunderbolt Ethernet Slot 1
Device: en7
Ethernet Address: 64:4b:f0:12:34:56

Hardware Port: Wi-Fi
Device: en0
Ethernet Address: aa:bb:cc:dd:ee:ff

Hardware Port: Thunderbolt Bridge
Device: bridge0
Ethernet Address: 36:0f:a1:00:00:00

VLAN Configurations
===================
"""

MAC_ROUTE_WIFI = """   route to: default
destination: default
       mask: default
    gateway: 192.168.68.1
  interface: en0
      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>
 recvpipe  sendpipe  ssthresh  rtt,msec    rttvar  hopcount      mtu     expire
       0         0         0         0         0         0      1500         0
"""

MAC_ROUTE_ETHERNET = MAC_ROUTE_WIFI.replace("interface: en0", "interface: en7")

MAC_ROUTE_NONE = "route: writing to routing socket: not in table\n"

MAC_IFCONFIG_EN7 = """en7: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
	options=6467<RXCSUM,TXCSUM,VLAN_MTU,TSO4,TSO6,CHANNEL_IO,PARTIAL_CSUM,ZEROINVERT_CSUM>
	ether 64:4b:f0:12:34:56
	inet 192.168.68.120 netmask 0xfffffc00 broadcast 192.168.71.255
	media: autoselect (2500Base-T <full-duplex>)
	status: active
"""

MAC_NETSTAT = """Routing tables

Internet:
Destination        Gateway            Flags               Netif Expire
default            192.168.68.1       UGScg                 en0
127                127.0.0.1          UCS                   lo0
"""

# ---------------------------------------------------------------------------
# Windows fixtures (netsh wlan show interfaces)
# ---------------------------------------------------------------------------

WIN11_BE_6GHZ = """
There is 1 interface on the system:

    Name                   : Wi-Fi
    Description            : Intel(R) Wi-Fi 7 BE200 320MHz
    GUID                   : 1b2c3d4e-5f60-4a7b-8c9d-0e1f2a3b4c5d
    Physical address       : a0:b1:c2:d3:e4:f5
    Interface type         : Primary
    State                  : connected
    SSID                   : Home Deco
    AP BSSID               : 30:68:93:aa:bb:cc
    Band                   : 6 GHz
    Channel                : 37
    Connected Akm-cipher   : [ akm = 00-0f-ac:08, cipher = 00-0f-ac:04 ]
    Network type           : Infrastructure
    Radio type             : 802.11be
    Authentication         : WPA3-Personal
    Cipher                 : CCMP
    Connection mode        : Auto Connect
    Receive rate (Mbps)    : 2882
    Transmit rate (Mbps)   : 2401
    Signal                 : 99%
    Rssi                   : -41
    Profile                : Home Deco
    QoS MSCS Configured         : 0
    QoS Map Configured          : 0
    QoS Map Allowed by Policy   : 0

    Hosted network status  : Not available
"""

WIN10_OLD_NO_RSSI = """
There is 1 interface on the system:

    Name                   : Wi-Fi
    Description            : Intel(R) Wi-Fi 6 AX201 160MHz
    GUID                   : 0a1b2c3d-4e5f-6789-abcd-ef0123456789
    Physical address       : 10:20:30:40:50:60
    State                  : connected
    SSID                   : Home Deco
    BSSID                  : 30:68:93:AA:BB:CD
    Network type           : Infrastructure
    Radio type             : 802.11ax
    Authentication         : WPA2-Personal
    Cipher                 : CCMP
    Connection mode        : Auto Connect
    Channel                : 44
    Receive rate (Mbps)    : 1201
    Transmit rate (Mbps)   : 1201
    Signal                 : 84%
    Profile                : Home Deco

    Hosted network status  : Not available
"""

WIN_DISCONNECTED = """
There is 1 interface on the system:

    Name                   : Wi-Fi
    Description            : Intel(R) Wi-Fi 6E AX211 160MHz
    GUID                   : 0a1b2c3d-4e5f-6789-abcd-ef0123456789
    Physical address       : 10:20:30:40:50:60
    Interface type         : Primary
    State                  : disconnected
    Radio status           : Hardware On
                             Software On

    Hosted network status  : Not available
"""

WIN_NO_WIRELESS = "There is no wireless interface on the system.\n"

# Windows 11 24H2 without Location permission for desktop apps.
WIN_NEEDS_LOCATION = """Network shell commands need location permission to access WLAN information. Turn on Location services on the Location page in Privacy & security settings.

Here is the URI for the Location page in the Settings app:
ms-settings:privacy-location
To open the Location page in the Settings app, hold down the Ctrl key and select the link, or run the following command:
start ms-settings:privacy-location
"""

WIN_ROUTE_PRINT = """===========================================================================
Interface List
 12...a0 b1 c2 d3 e4 f5 ......Intel(R) Wi-Fi 7 BE200 320MHz
 18...00 e0 4c 68 00 01 ......Realtek USB GbE Family Controller
  1...........................Software Loopback Interface 1
===========================================================================

IPv4 Route Table
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0     192.168.68.1   192.168.68.105     50
          0.0.0.0          0.0.0.0     192.168.68.1   192.168.68.106     25
===========================================================================
Persistent Routes:
  Network Address          Netmask  Gateway Address  Metric
          0.0.0.0          0.0.0.0      192.168.1.1  Default
===========================================================================
"""

WIN_ROUTE_PRINT_EMPTY = """IPv4 Route Table
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
===========================================================================
Persistent Routes:
  None
"""

WIN_IPCONFIG = """
Windows IP Configuration


Ethernet adapter Ethernet:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . :

Wireless LAN adapter Wi-Fi:

   Connection-specific DNS Suffix  . :
   Link-local IPv6 Address . . . . . : fe80::1c2d:3e4f:5a6b:7c8d%12
   IPv4 Address. . . . . . . . . . . : 192.168.68.105
   Subnet Mask . . . . . . . . . . . : 255.255.252.0
   Default Gateway . . . . . . . . . : fe80::3268:93ff:feaa:bbcc%12
                                       192.168.68.1
"""

# ---------------------------------------------------------------------------
# Linux fixtures (iw dev <dev> link / info, ip route, /proc/net/route)
# ---------------------------------------------------------------------------

IW_LINK_24_HT20 = """Connected to 30:68:93:aa:bb:01 (on wlp2s0)
	SSID: Home Deco
	freq: 2437
	RX: 4120934 bytes (12034 packets)
	TX: 812345 bytes (4012 packets)
	signal: -61 dBm
	rx bitrate: 72.2 MBit/s MCS 7 short GI
	tx bitrate: 65.0 MBit/s MCS 7

	bss flags:	short-preamble short-slot-time
	dtim period:	1
	beacon int:	100
"""

IW_INFO_24_HT20 = """Interface wlp2s0
	ifindex 3
	wdev 0x1
	addr 10:20:30:40:50:61
	ssid Home Deco
	type managed
	wiphy 0
	channel 6 (2437 MHz), width: 20 MHz, center1: 2437 MHz
	txpower 22.00 dBm
"""

IW_LINK_5_VHT80 = """Connected to 30:68:93:aa:bb:02 (on wlan0)
	SSID: Home Deco
	freq: 5180
	RX: 98765432 bytes (70123 packets)
	TX: 1234567 bytes (9001 packets)
	signal: -55 dBm
	rx bitrate: 866.7 MBit/s VHT-MCS 9 80MHz short GI VHT-NSS 2
	tx bitrate: 780.0 MBit/s VHT-MCS 8 80MHz short GI VHT-NSS 2

	bss flags:	short-slot-time
	dtim period:	3
	beacon int:	100
"""

IW_LINK_6_EHT320 = """Connected to 30:68:93:aa:bb:03 (on wlan0)
	SSID: Home Deco
	freq: 6135.0
	RX: 512345678 bytes (401234 packets)
	TX: 23456789 bytes (120034 packets)
	signal: -48 dBm
	rx bitrate: 2401.9 MBit/s 320MHz EHT-MCS 11 EHT-NSS 2 EHT-GI 0
	tx bitrate: 2882.4 MBit/s 320MHz EHT-MCS 13 EHT-NSS 2 EHT-GI 0

	bss flags:	short-slot-time
	dtim period:	2
	beacon int:	100
"""

IW_INFO_6_EHT320 = """Interface wlan0
	ifindex 4
	wdev 0x1
	addr 10:20:30:40:50:62
	ssid Home Deco
	type managed
	wiphy 0
	channel 37 (6135 MHz), width: 320 MHz, center1: 6105 MHz
	txpower 23.00 dBm
"""

IW_NOT_CONNECTED = "Not connected.\n"

IP_ROUTE_DEFAULT = """default via 192.168.68.1 dev wlan0 proto dhcp src 192.168.68.112 metric 600
default via 192.168.68.1 dev enp3s0 proto dhcp src 192.168.68.113 metric 100
"""

PROC_NET_ROUTE = """Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT
wlan0	00000000	0144A8C0	0003	0	0	600	00000000	0	0	0
wlan0	0044A8C0	00000000	0001	0	0	600	00FCFFFF	0	0	0
"""

NMCLI_WIFI = """no:Neighbour:AA\\:BB\\:CC\\:DD\\:EE\\:FF:6:2437 MHz:130 Mbit/s:40
yes:Home Deco:30\\:68\\:93\\:AA\\:BB\\:CC:37:6135 MHz:2882 Mbit/s:92
"""


def fake_runner(outputs: dict):
    """Build a fake _run that answers from a {command string: output} dict."""
    def run(cmd, timeout):
        return outputs.get(" ".join(cmd))
    return run


class MacParserTests(unittest.TestCase):
    def test_sequoia_6ghz_320mhz_be(self):
        info = wifi_link.parse_macos_system_profiler(MAC_SEQUOIA_6GHZ_BE)
        self.assertEqual(info["type"], "wifi")
        self.assertEqual(info["interface"], "en0")
        self.assertEqual(info["ssid"], "Home Deco")
        self.assertEqual(info["band"], "6GHz")
        self.assertEqual(info["channel"], 37)
        self.assertEqual(info["width_mhz"], 320)
        self.assertEqual(info["phy"], "802.11be")
        self.assertEqual(info["wifi_gen"], 7)
        self.assertEqual(info["rssi_dbm"], -52)
        self.assertEqual(info["noise_dbm"], -95)
        self.assertEqual(info["snr_db"], 43)
        self.assertEqual(info["tx_rate_mbps"], 2882.0)
        self.assertEqual(info["mcs"], 11)
        self.assertIsNone(info.get("bssid"))

    def test_5ghz_80mhz_ax(self):
        info = wifi_link.parse_macos_system_profiler(MAC_SONOMA_5GHZ_AX)
        self.assertEqual(info["band"], "5GHz")
        self.assertEqual(info["channel"], 149)
        self.assertEqual(info["width_mhz"], 80)
        self.assertEqual(info["phy"], "802.11ax")
        self.assertEqual(info["wifi_gen"], 6)
        self.assertEqual(info["rssi_dbm"], -58)
        self.assertEqual(info["snr_db"], 35)
        self.assertEqual(info["tx_rate_mbps"], 1201.0)

    def test_redacted_ssid_and_bare_channel(self):
        info = wifi_link.parse_macos_system_profiler(MAC_REDACTED_SSID)
        self.assertEqual(info["type"], "wifi")
        self.assertIsNone(info["ssid"])
        self.assertEqual(info["channel"], 44)
        self.assertEqual(info["band"], "5GHz")
        self.assertIsNone(info["width_mhz"])
        self.assertEqual(info["wifi_gen"], 5)
        self.assertEqual(info["tx_rate_mbps"], 866.0)

    def test_no_current_network(self):
        info = wifi_link.parse_macos_system_profiler(MAC_NO_NETWORK)
        self.assertNotEqual(info["type"], "wifi")
        self.assertEqual(info["interface"], "en0")
        self.assertIsNone(info.get("ssid"))
        self.assertTrue(info["error"])

    def test_bad_json_does_not_raise(self):
        info = wifi_link.parse_macos_system_profiler("not json{")
        self.assertEqual(info["type"], "unknown")
        self.assertTrue(info["error"])
        self.assertEqual(wifi_link.parse_macos_system_profiler("{}")["type"], "unknown")

    def test_old_channel_formats(self):
        self.assertEqual(wifi_link._parse_mac_channel("149,+1"), (149, "5GHz", 40))
        self.assertEqual(wifi_link._parse_mac_channel("6 (2GHz, 20MHz)"), (6, "2.4GHz", 20))
        self.assertEqual(wifi_link._parse_mac_channel(11), (11, "2.4GHz", None))
        self.assertEqual(wifi_link._parse_mac_channel("37 (6 GHz, 160MHz)"), (37, "6GHz", 160))

    def test_hardware_ports_and_route(self):
        self.assertEqual(wifi_link.parse_macos_hardware_ports(MAC_HARDWARE_PORTS), "en0")
        self.assertEqual(wifi_link.parse_macos_route_get(MAC_ROUTE_ETHERNET),
                         ("192.168.68.1", "en7"))
        self.assertEqual(wifi_link.parse_macos_route_get(MAC_ROUTE_NONE), (None, None))
        self.assertEqual(wifi_link.parse_macos_netstat(MAC_NETSTAT), ("192.168.68.1", "en0"))
        self.assertEqual(wifi_link.parse_ifconfig_media_speed(MAC_IFCONFIG_EN7), 2500)
        self.assertEqual(wifi_link.parse_ifconfig_media_speed(
            "\tmedia: autoselect (10GbaseT <full-duplex>)"), 10000)


class WindowsParserTests(unittest.TestCase):
    def test_win11_be_6ghz_with_rssi(self):
        info = wifi_link.parse_windows_netsh(WIN11_BE_6GHZ)
        self.assertEqual(info["type"], "wifi")
        self.assertEqual(info["interface"], "Wi-Fi")
        self.assertEqual(info["ssid"], "Home Deco")
        self.assertEqual(info["bssid"], "30:68:93:AA:BB:CC")
        self.assertEqual(info["band"], "6GHz")
        self.assertEqual(info["channel"], 37)
        self.assertEqual(info["phy"], "802.11be")
        self.assertEqual(info["wifi_gen"], 7)
        self.assertEqual(info["rx_rate_mbps"], 2882.0)
        self.assertEqual(info["tx_rate_mbps"], 2401.0)
        self.assertEqual(info["signal_pct"], 99)
        self.assertEqual(info["rssi_dbm"], -41)
        self.assertNotIn("rssi_estimated", info)

    def test_old_windows_without_rssi_or_band(self):
        info = wifi_link.parse_windows_netsh(WIN10_OLD_NO_RSSI)
        self.assertEqual(info["type"], "wifi")
        self.assertEqual(info["bssid"], "30:68:93:AA:BB:CD")
        self.assertEqual(info["band"], "5GHz")  # worked out from channel 44
        self.assertEqual(info["channel"], 44)
        self.assertEqual(info["phy"], "802.11ax")
        self.assertEqual(info["wifi_gen"], 6)
        self.assertEqual(info["signal_pct"], 84)
        self.assertEqual(info["rssi_dbm"], -58)  # round(84/2 - 100)
        self.assertTrue(info["rssi_estimated"])

    def test_disconnected_and_no_adapter(self):
        info = wifi_link.parse_windows_netsh(WIN_DISCONNECTED)
        self.assertEqual(info["type"], "unknown")
        self.assertEqual(info["interface"], "Wi-Fi")
        self.assertTrue(info["error"])
        info = wifi_link.parse_windows_netsh(WIN_NO_WIRELESS)
        self.assertEqual(info["type"], "unknown")
        self.assertIn("no Wi-Fi adapter", info["error"])
        self.assertEqual(wifi_link.parse_windows_netsh("")["type"], "unknown")

    def test_gateway_parsing(self):
        self.assertEqual(wifi_link.parse_windows_route_print(WIN_ROUTE_PRINT), "192.168.68.1")
        self.assertIsNone(wifi_link.parse_windows_route_print(WIN_ROUTE_PRINT_EMPTY))
        self.assertEqual(wifi_link.parse_windows_ipconfig_gateway(WIN_IPCONFIG), "192.168.68.1")
        self.assertIsNone(wifi_link.parse_windows_ipconfig_gateway("nothing here"))


class LinuxParserTests(unittest.TestCase):
    def test_24ghz_ht20(self):
        info = wifi_link.parse_linux_iw(IW_LINK_24_HT20, IW_INFO_24_HT20)
        self.assertEqual(info["type"], "wifi")
        self.assertEqual(info["interface"], "wlp2s0")
        self.assertEqual(info["bssid"], "30:68:93:AA:BB:01")
        self.assertEqual(info["ssid"], "Home Deco")
        self.assertEqual(info["band"], "2.4GHz")
        self.assertEqual(info["channel"], 6)
        self.assertEqual(info["width_mhz"], 20)
        self.assertEqual(info["phy"], "802.11n")
        self.assertEqual(info["wifi_gen"], 4)
        self.assertEqual(info["rssi_dbm"], -61)
        self.assertEqual(info["rx_rate_mbps"], 72.2)
        self.assertEqual(info["tx_rate_mbps"], 65.0)

    def test_24ghz_ht20_without_info(self):
        info = wifi_link.parse_linux_iw(IW_LINK_24_HT20)
        self.assertEqual(info["width_mhz"], 20)  # no width token means 20 MHz

    def test_5ghz_vht80(self):
        info = wifi_link.parse_linux_iw(IW_LINK_5_VHT80)
        self.assertEqual(info["band"], "5GHz")
        self.assertEqual(info["channel"], 36)
        self.assertEqual(info["width_mhz"], 80)
        self.assertEqual(info["phy"], "802.11ac")
        self.assertEqual(info["wifi_gen"], 5)
        self.assertEqual(info["rssi_dbm"], -55)
        self.assertEqual(info["rx_rate_mbps"], 866.7)

    def test_6ghz_eht320(self):
        info = wifi_link.parse_linux_iw(IW_LINK_6_EHT320, IW_INFO_6_EHT320)
        self.assertEqual(info["band"], "6GHz")
        self.assertEqual(info["channel"], 37)
        self.assertEqual(info["width_mhz"], 320)
        self.assertEqual(info["phy"], "802.11be")
        self.assertEqual(info["wifi_gen"], 7)
        self.assertEqual(info["rssi_dbm"], -48)
        self.assertEqual(info["tx_rate_mbps"], 2882.4)

    def test_he_and_width_tokens(self):
        link = IW_LINK_5_VHT80.replace(
            "rx bitrate: 866.7 MBit/s VHT-MCS 9 80MHz short GI VHT-NSS 2",
            "rx bitrate: 2401.9 MBit/s 160MHz HE-MCS 11 HE-NSS 2 HE-GI 0 HE-DCM 0",
        ).replace(
            "tx bitrate: 780.0 MBit/s VHT-MCS 8 80MHz short GI VHT-NSS 2",
            "tx bitrate: 1200.9 MBit/s 80P80MHz HE-MCS 11 HE-NSS 1",
        )
        info = wifi_link.parse_linux_iw(link)
        self.assertEqual(info["phy"], "802.11ax")
        self.assertEqual(info["width_mhz"], 160)
        self.assertEqual(wifi_link._width_from_tokens(" VHT80 "), 80)

    def test_not_connected(self):
        info = wifi_link.parse_linux_iw(IW_NOT_CONNECTED)
        self.assertEqual(info["type"], "unknown")
        self.assertTrue(info["error"])

    def test_frequency_conversion(self):
        f = wifi_link._freq_to_band_channel
        self.assertEqual(f(2412), ("2.4GHz", 1))
        self.assertEqual(f(2484), ("2.4GHz", 14))
        self.assertEqual(f(5745), ("5GHz", 149))
        self.assertEqual(f("5955.0"), ("6GHz", 1))
        self.assertEqual(f(7115), ("6GHz", 233))
        self.assertEqual(f(None), (None, None))

    def test_nmcli_fallback(self):
        info = wifi_link.parse_nmcli_wifi(NMCLI_WIFI)
        self.assertEqual(info["type"], "wifi")
        self.assertEqual(info["ssid"], "Home Deco")
        self.assertEqual(info["bssid"], "30:68:93:AA:BB:CC")
        self.assertEqual(info["band"], "6GHz")
        self.assertEqual(info["channel"], 37)
        self.assertEqual(info["signal_pct"], 92)
        self.assertEqual(info["rssi_dbm"], -54)
        self.assertTrue(info["rssi_estimated"])

    def test_gateway_parsing(self):
        self.assertEqual(wifi_link.parse_linux_ip_route(IP_ROUTE_DEFAULT),
                         ("192.168.68.1", "enp3s0"))  # lowest metric wins
        self.assertEqual(wifi_link.parse_linux_ip_route(""), (None, None))
        self.assertEqual(wifi_link.parse_proc_net_route(PROC_NET_ROUTE),
                         ("192.168.68.1", "wlan0"))


class HelperTests(unittest.TestCase):
    def test_phy_generation(self):
        self.assertEqual(wifi_link._norm_phy("802.11be"), ("802.11be", 7))
        self.assertEqual(wifi_link._norm_phy("802.11 a/b/g/n/ac/ax"), ("802.11ax", 6))
        self.assertEqual(wifi_link._norm_phy("802.11ac"), ("802.11ac", 5))
        self.assertEqual(wifi_link._norm_phy("802.11n"), ("802.11n", 4))
        self.assertEqual(wifi_link._norm_phy("802.11g"), ("802.11g", None))
        self.assertEqual(wifi_link._norm_phy(None), (None, None))

    def test_band_guess_from_channel(self):
        self.assertEqual(wifi_link._band_from_channel(1), "2.4GHz")
        self.assertEqual(wifi_link._band_from_channel(36), "5GHz")
        self.assertEqual(wifi_link._band_from_channel(165), "5GHz")
        self.assertEqual(wifi_link._band_from_channel(37), "6GHz")
        self.assertIsNone(wifi_link._band_from_channel(None))


class GetLinkInfoTests(unittest.TestCase):
    def run_with(self, os_name, outputs, **extra):
        patches = [
            mock.patch.object(wifi_link, "_detect_os", return_value=os_name),
            mock.patch.object(wifi_link, "_run", side_effect=fake_runner(outputs)),
        ]
        for name, value in extra.items():
            patches.append(mock.patch.object(wifi_link, name, value))
        for patch in patches:
            patch.start()
        try:
            return wifi_link.get_link_info(timeout=5)
        finally:
            for patch in reversed(patches):
                patch.stop()

    def assert_complete(self, info):
        for key in wifi_link.LINK_KEYS:
            self.assertIn(key, info)
        json.dumps(info)

    def test_macos_wifi(self):
        info = self.run_with("macos", {
            "system_profiler SPAirPortDataType -json": MAC_SEQUOIA_6GHZ_BE,
            "networksetup -listallhardwareports": MAC_HARDWARE_PORTS,
            "route -n get default": MAC_ROUTE_WIFI,
        })
        self.assert_complete(info)
        self.assertEqual(info["os"], "macos")
        self.assertEqual(info["type"], "wifi")
        self.assertEqual(info["width_mhz"], 320)
        self.assertEqual(info["wifi_gen"], 7)
        self.assertIsNone(info["error"])

    def test_macos_ethernet_wins_when_default_route_is_cable(self):
        info = self.run_with("macos", {
            "system_profiler SPAirPortDataType -json": MAC_SEQUOIA_6GHZ_BE,
            "networksetup -listallhardwareports": MAC_HARDWARE_PORTS,
            "route -n get default": MAC_ROUTE_ETHERNET,
            "ifconfig en7": MAC_IFCONFIG_EN7,
        })
        self.assert_complete(info)
        self.assertEqual(info["type"], "ethernet")
        self.assertEqual(info["interface"], "en7")
        self.assertIsNone(info["ssid"])
        self.assertIsNone(info["band"])
        self.assertEqual(info["tx_rate_mbps"], 2500.0)
        self.assertEqual(info["link_speed_mbps"], 2500)

    def test_macos_no_wifi_network_but_cable(self):
        info = self.run_with("macos", {
            "system_profiler SPAirPortDataType -json": MAC_NO_NETWORK,
            "networksetup -listallhardwareports": MAC_HARDWARE_PORTS,
            "route -n get default": MAC_ROUTE_ETHERNET,
        })
        self.assertEqual(info["type"], "ethernet")
        self.assertIsNone(info["error"])

    def test_macos_offline(self):
        info = self.run_with("macos", {
            "system_profiler SPAirPortDataType -json": MAC_NO_NETWORK,
            "networksetup -listallhardwareports": MAC_HARDWARE_PORTS,
            "route -n get default": MAC_ROUTE_NONE,
        })
        self.assertEqual(info["type"], "unknown")
        self.assertTrue(info["error"])

    def test_macos_vpn_keeps_wifi(self):
        info = self.run_with("macos", {
            "system_profiler SPAirPortDataType -json": MAC_SONOMA_5GHZ_AX,
            "networksetup -listallhardwareports": MAC_HARDWARE_PORTS,
            "route -n get default": MAC_ROUTE_WIFI.replace("interface: en0", "interface: utun4"),
        })
        self.assertEqual(info["type"], "wifi")
        self.assertTrue(info["vpn"])

    def test_windows_wifi(self):
        info = self.run_with("windows", {"netsh wlan show interfaces": WIN11_BE_6GHZ})
        self.assert_complete(info)
        self.assertEqual(info["type"], "wifi")
        self.assertEqual(info["band"], "6GHz")

    def test_windows_disconnected_with_gateway_is_ethernet(self):
        info = self.run_with("windows", {
            "netsh wlan show interfaces": WIN_DISCONNECTED,
            "route print 0.0.0.0": WIN_ROUTE_PRINT,
        })
        self.assertEqual(info["type"], "ethernet")
        self.assertIsNone(info["error"])

    def test_windows_no_adapter_no_gateway_is_unknown(self):
        info = self.run_with("windows", {
            "netsh wlan show interfaces": WIN_NO_WIRELESS,
            "route print 0.0.0.0": WIN_ROUTE_PRINT_EMPTY,
            "ipconfig": "Windows IP Configuration\n",
        })
        self.assertEqual(info["type"], "unknown")
        self.assertTrue(info["error"])

    def test_windows_location_permission_is_not_called_ethernet(self):
        info = self.run_with("windows", {
            "netsh wlan show interfaces": WIN_NEEDS_LOCATION,
            "route print 0.0.0.0": WIN_ROUTE_PRINT,
        })
        self.assertEqual(info["type"], "unknown")
        self.assertIn("Location", info["error"])
        self.assertTrue(info["needs_location_permission"])

    def test_linux_wifi(self):
        info = self.run_with("linux", {
            "ip route show default": "default via 192.168.68.1 dev wlan0 proto dhcp metric 600\n",
            "iw dev wlan0 link": IW_LINK_6_EHT320,
            "iw dev wlan0 info": IW_INFO_6_EHT320,
        }, _sys_wireless=lambda dev: dev == "wlan0")
        self.assert_complete(info)
        self.assertEqual(info["type"], "wifi")
        self.assertEqual(info["interface"], "wlan0")
        self.assertEqual(info["width_mhz"], 320)

    def test_linux_ethernet(self):
        def read_text(path):
            return "1000\n" if path == "/sys/class/net/enp3s0/speed" else None
        info = self.run_with("linux", {
            "ip route show default": "default via 192.168.68.1 dev enp3s0 proto dhcp metric 100\n",
        }, _sys_wireless=lambda dev: False, _read_text=read_text)
        self.assertEqual(info["type"], "ethernet")
        self.assertEqual(info["interface"], "enp3s0")
        self.assertEqual(info["tx_rate_mbps"], 1000.0)

    def test_linux_nmcli_fallback_when_iw_missing(self):
        info = self.run_with("linux", {
            "ip route show default": "default via 192.168.68.1 dev wlan0 proto dhcp metric 600\n",
            "nmcli -t -f ACTIVE,SSID,BSSID,CHAN,FREQ,RATE,SIGNAL device wifi list "
            "ifname wlan0 --rescan no": NMCLI_WIFI,
        }, _sys_wireless=lambda dev: dev == "wlan0")
        self.assertEqual(info["type"], "wifi")
        self.assertEqual(info["band"], "6GHz")

    def test_never_raises(self):
        with mock.patch.object(wifi_link, "_detect_os", return_value="macos"), \
                mock.patch.object(wifi_link, "_run", side_effect=RuntimeError("boom")):
            info = wifi_link.get_link_info()
        self.assert_complete(info)
        self.assertEqual(info["type"], "unknown")
        self.assertIn("boom", info["error"])
        with mock.patch.object(wifi_link, "_detect_os", return_value="other"):
            info = wifi_link.get_link_info()
        self.assertEqual(info["os"], "other")
        self.assertTrue(info["error"])


class DefaultGatewayTests(unittest.TestCase):
    def gateway(self, os_name, outputs, **extra):
        patches = [
            mock.patch.object(wifi_link, "_detect_os", return_value=os_name),
            mock.patch.object(wifi_link, "_run", side_effect=fake_runner(outputs)),
        ] + [mock.patch.object(wifi_link, k, v) for k, v in extra.items()]
        for patch in patches:
            patch.start()
        try:
            return wifi_link.default_gateway()
        finally:
            for patch in reversed(patches):
                patch.stop()

    def test_macos(self):
        self.assertEqual(self.gateway("macos", {"route -n get default": MAC_ROUTE_WIFI}),
                         "192.168.68.1")
        self.assertEqual(self.gateway("macos", {"netstat -rn -f inet": MAC_NETSTAT}),
                         "192.168.68.1")

    def test_linux(self):
        self.assertEqual(self.gateway("linux", {"ip route show default": IP_ROUTE_DEFAULT}),
                         "192.168.68.1")
        self.assertEqual(self.gateway("linux", {}, _read_text=lambda p: PROC_NET_ROUTE),
                         "192.168.68.1")

    def test_windows(self):
        self.assertEqual(self.gateway("windows", {"route print 0.0.0.0": WIN_ROUTE_PRINT}),
                         "192.168.68.1")
        self.assertEqual(self.gateway("windows", {"ipconfig": WIN_IPCONFIG}), "192.168.68.1")

    def test_never_raises(self):
        with mock.patch.object(wifi_link, "_detect_os", side_effect=RuntimeError("x")):
            self.assertIsNone(wifi_link.default_gateway())



# ---------------------------------------------------------------------------
# Adversarial review tests: odd input, failed tools and edge frequencies
# ---------------------------------------------------------------------------

WIN_GERMAN_CONNECTED = """
Es ist 1 Schnittstelle auf dem System vorhanden:

    Name                   : WLAN
    Beschreibung           : Intel(R) Wi-Fi 6 AX201 160MHz
    Status                 : Verbunden
    SSID                   : Zuhause
    BSSID                  : 30:68:93:aa:bb:cc
    Funktyp                : 802.11ax
    Kanal                  : 44
    Signal                 : 84%
"""

WIN_SERVICE_OFF = "The Wireless AutoConfig Service (wlansvc) is not running.\n"


class ReviewEdgeCaseTests(unittest.TestCase):
    def run_with(self, os_name, outputs):
        with mock.patch.object(wifi_link, "_detect_os", return_value=os_name), \
                mock.patch.object(wifi_link, "_run", side_effect=fake_runner(outputs)):
            return wifi_link.get_link_info(timeout=5)

    def test_frequency_edges(self):
        conv = wifi_link._freq_to_band_channel
        self.assertEqual(conv("2484"), ("2.4GHz", 14))
        self.assertEqual(conv("2484.0"), ("2.4GHz", 14))
        self.assertEqual(conv(2412), ("2.4GHz", 1))
        self.assertEqual(conv(2472), ("2.4GHz", 13))
        self.assertEqual(conv(5935), ("6GHz", 2))
        self.assertEqual(conv(5955), ("6GHz", 1))
        self.assertEqual(conv(6695), ("6GHz", 149))  # same number as a 5 GHz channel
        self.assertEqual(conv(5745), ("5GHz", 149))
        self.assertEqual(conv(7115), ("6GHz", 233))
        self.assertEqual(conv(5885), ("5GHz", 177))
        # Japan's 4.9 GHz channels must not come out negative
        self.assertEqual(conv(4920), ("5GHz", 184))
        self.assertEqual(conv(4980), ("5GHz", 196))
        self.assertEqual(conv("garbage"), (None, None))
        self.assertEqual(conv(60480), (None, None))

    def test_6ghz_channel_numbers_that_overlap_5ghz_or_24ghz(self):
        link = IW_LINK_6_EHT320.replace("freq: 6135.0", "freq: 6695")
        info = wifi_link.parse_linux_iw(link)
        self.assertEqual((info["band"], info["channel"]), ("6GHz", 149))
        link = IW_LINK_6_EHT320.replace("freq: 6135.0", "freq: 5975")
        info = wifi_link.parse_linux_iw(link)
        self.assertEqual((info["band"], info["channel"]), ("6GHz", 5))
        win = WIN11_BE_6GHZ.replace("Channel                : 37",
                                    "Channel                : 149")
        self.assertEqual(wifi_link.parse_windows_netsh(win)["band"], "6GHz")
        win = WIN11_BE_6GHZ.replace("Channel                : 37",
                                    "Channel                : 5")
        self.assertEqual(wifi_link.parse_windows_netsh(win)["band"], "6GHz")
        mac = MAC_SEQUOIA_6GHZ_BE.replace("37 (6GHz, 320MHz)", "5 (6GHz, 160MHz)")
        info = wifi_link.parse_macos_system_profiler(mac)
        self.assertEqual((info["band"], info["channel"], info["width_mhz"]), ("6GHz", 5, 160))

    def test_non_finite_json_numbers_do_not_crash(self):
        text = json.dumps({"SPAirPortDataType": [{"spairport_airport_interfaces": [{
            "_name": "en0",
            "spairport_current_network_information": {
                "_name": "Home Deco",
                "spairport_network_channel": float("inf"),
                "spairport_network_mcs": float("nan"),
                "spairport_network_rate": float("inf"),
                "spairport_network_phymode": "802.11ax",
            }}]}]})
        info = wifi_link.parse_macos_system_profiler(text)
        self.assertEqual(info["type"], "wifi")
        self.assertIsNone(info["channel"])
        self.assertIsNone(info["tx_rate_mbps"])
        self.assertNotIn("mcs", info)
        self.assertEqual(info["wifi_gen"], 6)

    def test_parsers_never_crash_on_garbage(self):
        import random
        rng = random.Random(1234)
        pieces = ["Connected to", "SSID:", "freq:", "signal:", "rx bitrate:", "MBit/s",
                  "EHT-MCS", "HE", "VHT80", "Name", "State", "connected", " : ", ":",
                  "\n", "\t", "-", "9999999999999999999999", "nan", "inf", "%", "GHz",
                  "MHz", "(", ")", "802.11", "be", "Rssi", "Channel", "Band", "{", "}",
                  "\x00", "é", "default", "via", "dev", "metric"]
        parsers = (wifi_link.parse_windows_netsh, wifi_link.parse_linux_iw,
                   wifi_link.parse_macos_system_profiler, wifi_link.parse_nmcli_wifi,
                   wifi_link.parse_windows_route_print, wifi_link.parse_windows_ipconfig_gateway,
                   wifi_link.parse_linux_ip_route, wifi_link.parse_proc_net_route,
                   wifi_link.parse_macos_route_get, wifi_link.parse_macos_hardware_ports,
                   wifi_link.parse_macos_netstat, wifi_link.parse_ifconfig_media_speed)
        for _ in range(300):
            text = "".join(rng.choice(pieces) for _ in range(rng.randint(0, 40)))
            for parser in parsers:
                parser(text)
        for weird in ("", "null", "[]", "{}", '{"SPAirPortDataType": 5}',
                      '{"SPAirPortDataType": [{"spairport_airport_interfaces": [5, null]}]}',
                      '{"SPAirPortDataType": [{"spairport_airport_interfaces": [{"_name": 7, '
                      '"spairport_current_network_information": {"_name": 5, '
                      '"spairport_signal_noise": [1, 2], "spairport_network_channel": true}}]}]}'):
            self.assertIsInstance(wifi_link.parse_macos_system_profiler(weird), dict)

    def test_run_survives_an_endless_timeout(self):
        import sys
        out = wifi_link._run([sys.executable, "-c", "print('hi')"], float("inf"))
        self.assertEqual((out or "").strip(), "hi")
        out = wifi_link._run([sys.executable, "-c", "print('hi')"], float("nan"))
        self.assertEqual((out or "").strip(), "hi")

    def test_run_times_out_instead_of_hanging(self):
        import sys
        import time
        started = time.monotonic()
        out = wifi_link._run([sys.executable, "-c", "import time; time.sleep(30)"], 0.5)
        self.assertIsNone(out)
        self.assertLess(time.monotonic() - started, 10)

    def test_macos_wifi_report_failed_but_route_uses_wifi_is_not_ethernet(self):
        info = self.run_with("macos", {
            # system_profiler timed out (no output)
            "networksetup -listallhardwareports": MAC_HARDWARE_PORTS,
            "route -n get default": MAC_ROUTE_WIFI,
        })
        self.assertEqual(info["type"], "wifi")
        self.assertEqual(info["interface"], "en0")
        self.assertTrue(info["error"])
        # A broken report is treated the same way.
        info = self.run_with("macos", {
            "system_profiler SPAirPortDataType -json": "{not json",
            "networksetup -listallhardwareports": MAC_HARDWARE_PORTS,
            "route -n get default": MAC_ROUTE_WIFI,
        })
        self.assertEqual(info["type"], "wifi")
        # ...but a cable on en7 is still a cable.
        info = self.run_with("macos", {
            "networksetup -listallhardwareports": MAC_HARDWARE_PORTS,
            "route -n get default": MAC_ROUTE_ETHERNET,
        })
        self.assertEqual(info["type"], "ethernet")

    def test_windows_netsh_failed_is_not_called_ethernet(self):
        info = self.run_with("windows", {"route print 0.0.0.0": WIN_ROUTE_PRINT})
        self.assertEqual(info["type"], "unknown")
        self.assertTrue(info["error"])

    def test_windows_non_english_is_not_called_ethernet(self):
        info = self.run_with("windows", {
            "netsh wlan show interfaces": WIN_GERMAN_CONNECTED,
            "route print 0.0.0.0": WIN_ROUTE_PRINT,
        })
        self.assertEqual(info["type"], "unknown")
        self.assertIn("English", info["error"])
        self.assertIn("English", wifi_link.parse_windows_netsh(WIN_GERMAN_CONNECTED)["error"])

    def test_windows_service_off_with_gateway_is_ethernet(self):
        info = self.run_with("windows", {
            "netsh wlan show interfaces": WIN_SERVICE_OFF,
            "route print 0.0.0.0": WIN_ROUTE_PRINT,
        })
        self.assertEqual(info["type"], "ethernet")
        info = self.run_with("windows", {
            "netsh wlan show interfaces": WIN_NO_WIRELESS,
            "route print 0.0.0.0": WIN_ROUTE_PRINT,
        })
        self.assertEqual(info["type"], "ethernet")

    def test_windows_subprocess_hides_console_window(self):
        recorded = {}

        def fake_run(cmd, **kwargs):
            recorded.update(kwargs)
            raise FileNotFoundError("netsh")

        with mock.patch.object(wifi_link, "_NO_WINDOW", 0x08000000), \
                mock.patch.object(wifi_link.subprocess, "run", side_effect=fake_run):
            self.assertIsNone(wifi_link._run(["netsh", "wlan", "show", "interfaces"], 2))
        self.assertEqual(recorded.get("creationflags"), 0x08000000)
        self.assertEqual(recorded.get("stdin"), wifi_link.subprocess.DEVNULL)
        self.assertTrue(0 < recorded.get("timeout") <= 2)

    def test_ethernet_never_keeps_wifi_fields(self):
        info = self.run_with("macos", {
            "system_profiler SPAirPortDataType -json": MAC_SEQUOIA_6GHZ_BE,
            "networksetup -listallhardwareports": MAC_HARDWARE_PORTS,
            "route -n get default": MAC_ROUTE_ETHERNET,
        })
        self.assertEqual(info["type"], "ethernet")
        for key in ("ssid", "band", "channel", "rssi_dbm", "noise_dbm", "snr_db", "phy",
                    "wifi_gen", "width_mhz"):
            self.assertIsNone(info[key], key)
        self.assertNotIn("mcs", info)
        json.dumps(info)

    def test_redacted_and_odd_ssids(self):
        for raw in ("<redacted>", " <REDACTED> ", "<hidden>", "", "   "):
            self.assertIsNone(wifi_link._clean_ssid(raw), raw)
        self.assertEqual(wifi_link._clean_ssid("Café Wi-Fi"), "Café Wi-Fi")
        self.assertIsNone(wifi_link._clean_ssid(None))
        self.assertIsNone(wifi_link._clean_ssid(42))


if __name__ == "__main__":
    unittest.main()
