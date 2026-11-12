"""Offline unit tests: parsing, scope validation and a mocked end-to-end run.

No test sends network traffic; external tools are replaced by canned output.
Run from the repository root:  python3 -m unittest discover -v
"""

import contextlib
import io
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import main as cli
from scanner import (
    common,
    host_discovery,
    os_detection,
    ping_sweep,
    report_generator,
    risk_analysis,
    service_detection,
)

NETDISCOVER_OUTPUT = """\
 192.168.56.101  08:00:27:aa:bb:cc      1      60  PCS Systemtechnik GmbH
 192.168.56.1    0a:00:27:00:00:00      1      60  Unknown vendor
 192.168.56.101  08:00:27:aa:bb:cc      1      60  PCS Systemtechnik GmbH
"""

PING_OUTPUT = """\
Starting Nmap 7.94 ( https://nmap.org ) at 2026-10-29 12:00 IST
Nmap scan report for router.lan (192.168.56.1)
Host is up (0.00040s latency).
Nmap scan report for 192.168.56.101
Host is up (0.00051s latency).
Nmap done: 256 IP addresses (2 hosts up) scanned in 2.50 seconds
"""

SERVICE_OUTPUT = """\
Nmap scan report for 192.168.56.101
Host is up (0.00050s latency).
Not shown: 995 closed tcp ports (reset)
PORT    STATE  SERVICE      VERSION
21/tcp  open   ftp          vsftpd 2.3.4
22/tcp  open   ssh          OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
23/tcp  closed telnet
445/tcp open   microsoft-ds Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
"""

OS_OUTPUT = """\
Device type: general purpose
Running: Linux 2.6.X
OS details: Linux 2.6.9 - 2.6.33
Network Distance: 1 hop
"""


def fake_run_command(args, timeout=300, needs_root=False):
    if args[0] == "netdiscover":
        out = NETDISCOVER_OUTPUT
    elif "-sn" in args:
        out = PING_OUTPUT
    elif "-sV" in args:
        out = SERVICE_OUTPUT
    elif "-O" in args:
        out = OS_OUTPUT
    else:
        raise AssertionError(f"unexpected command: {args}")
    return common.CommandResult(out, "", 0)


class LoggingCleanupMixin:
    def tearDown(self):
        for handler in list(common.LOGGER.handlers):
            handler.close()
            common.LOGGER.removeHandler(handler)


class ValidationTests(unittest.TestCase):
    def test_network_is_normalised(self):
        self.assertEqual(str(common.validate_network("192.168.1.7/24")), "192.168.1.0/24")

    def test_bad_networks_rejected(self):
        for value in ("0.0.0.0/0", "10.0.0.0/8", "8.8.8.0/24", "fe80::/64", "nonsense", "224.0.0.0/24"):
            with self.subTest(value=value):
                with self.assertRaises(common.ScopeError):
                    common.validate_network(value)

    def test_public_allowed_only_with_flag(self):
        self.assertEqual(str(common.validate_network("8.8.8.0/24", allow_public=True)), "8.8.8.0/24")

    def test_target_validation(self):
        self.assertEqual(str(common.validate_target("192.168.1.10")), "192.168.1.10")
        for value in ("8.8.8.8", "0.0.0.0", "224.0.0.1", "-oX x", "192.168.1.10; rm -rf /", "::1"):
            with self.subTest(value=value):
                with self.assertRaises(common.ScopeError):
                    common.validate_target(value)

    def test_port_ranges(self):
        self.assertEqual(common.parse_port_range("22"), (22, 22))
        self.assertEqual(common.parse_port_range("1-1024"), (1, 1024))
        for value in ("0-10", "100-10", "1-70000", "abc", "-5", ""):
            with self.subTest(value=value):
                with self.assertRaises(common.ScopeError):
                    common.parse_port_range(value)


class RunCommandTests(unittest.TestCase):
    def test_missing_tool(self):
        with mock.patch("scanner.common.shutil.which", return_value=None):
            with self.assertRaises(common.ScanError):
                common.run_command(["nmap", "-sn", "10.0.0.1"])

    def test_root_required(self):
        with mock.patch("scanner.common.shutil.which", return_value="/usr/bin/nmap"), \
                mock.patch("scanner.common.is_root", return_value=False):
            with self.assertRaises(common.ScanError):
                common.run_command(["nmap", "-O", "10.0.0.1"], needs_root=True)


class ParserTests(unittest.TestCase):
    def test_host_discovery_dedupes_and_sorts(self):
        hosts = host_discovery.extract_hosts(NETDISCOVER_OUTPUT)
        self.assertEqual([h["IP"] for h in hosts], ["192.168.56.1", "192.168.56.101"])

    def test_ping_sweep_hostnames(self):
        self.assertEqual(
            ping_sweep.extract_hosts(PING_OUTPUT),
            [
                {"IP": "192.168.56.1", "Hostname": "router.lan", "Status": "Up"},
                {"IP": "192.168.56.101", "Hostname": "N/A", "Status": "Up"},
            ],
        )

    def test_service_command_port_spec(self):
        self.assertEqual(service_detection.build_command("10.0.0.5", 1, 1024),
                         ["nmap", "-sV", "-p", "1-1024", "10.0.0.5"])
        self.assertEqual(service_detection.build_command("10.0.0.5", 22, 22)[3], "22")

    def test_service_parsing(self):
        services = service_detection.extract_services(SERVICE_OUTPUT)
        self.assertEqual(len(services), 4)
        self.assertEqual(services[1]["Version"], "OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)")
        self.assertEqual(services[2]["Version"], "Unknown")

    def test_os_parsing(self):
        info = os_detection.extract_os_info(OS_OUTPUT)
        self.assertEqual(info["Running"], "Linux 2.6.X")
        self.assertEqual(info["Network Distance"], "1 hop")
        guess = os_detection.extract_os_info("Running (JUST GUESSING): Linux 3.X|4.X (90%)")
        self.assertEqual(guess["Running"], "Linux 3.X|4.X (90%)")
        self.assertEqual(os_detection.extract_os_info("")["Running"], "Unknown")


class RiskAnalysisTests(unittest.TestCase):
    def test_aliases_and_closed_ports(self):
        services = [
            {"Port": "21/tcp", "State": "open", "Service": "ftp", "Version": "x"},
            {"Port": "23/tcp", "State": "closed", "Service": "telnet", "Version": "Unknown"},
            {"Port": "445/tcp", "State": "open", "Service": "microsoft-ds", "Version": "x"},
            {"Port": "3389/tcp", "State": "open", "Service": "ms-wbt-server", "Version": "x"},
            {"Port": "53/udp", "State": "open", "Service": "domain?", "Version": "Unknown"},
        ]
        names = [f["Name"] for f in risk_analysis.analyze_services(services)]
        self.assertEqual(sorted(names), ["dns", "ftp", "rdp", "smb"])

    def test_os_analysis_does_not_crash(self):
        self.assertEqual(risk_analysis.analyze_os({"Running": "Linux 5.X"})[0]["Level"], "Low")
        self.assertEqual(risk_analysis.analyze_os({"Running": "Microsoft Windows 10"})[0]["Level"], "Medium")
        self.assertEqual(risk_analysis.analyze_os({})[0]["Level"], "Unknown")

    def test_findings_sorted_by_severity(self):
        services = [{"Port": "22/tcp", "State": "open", "Service": "ssh", "Version": "x"},
                    {"Port": "21/tcp", "State": "open", "Service": "ftp", "Version": "x"}]
        levels = [f["Level"] for f in risk_analysis.analyze(services, {"Running": "Linux"})]
        self.assertEqual(levels, ["High", "Low", "Low"])


class ReportTests(unittest.TestCase):
    def test_report_without_results(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertIn("not found", report_generator.generate_report(tmp))


class PipelineTests(LoggingCleanupMixin, unittest.TestCase):
    ARGS = ["--subnet", "192.168.56.0/24", "--target", "192.168.56.101",
            "--ports", "1-1024", "--authorized"]

    def run_cli(self, tmp, extra=()):
        argv = self.ARGS + ["--output-dir", tmp] + list(extra)
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return cli.main(argv)

    def test_full_run(self):
        with tempfile.TemporaryDirectory() as tmp, \
                mock.patch.object(common, "run_command", side_effect=fake_run_command):
            self.assertEqual(self.run_cli(tmp), 0)
            report = (Path(tmp) / "network_assessment_report.txt").read_text()
            for expected in ("router.lan", "vsftpd 2.3.4", "Linux 2.6.X", "Name: smb", "Name: ftp"):
                self.assertIn(expected, report)
            self.assertNotIn("Name: telnet", report)

    def test_failed_step_is_reported_not_hidden(self):
        def flaky(args, timeout=300, needs_root=False):
            if args[0] == "netdiscover":
                raise common.ScanError("'netdiscover' requires root privileges.")
            return fake_run_command(args, timeout, needs_root)

        with tempfile.TemporaryDirectory() as tmp, \
                mock.patch.object(common, "run_command", side_effect=flaky):
            self.assertEqual(self.run_cli(tmp), 1)
            report = (Path(tmp) / "network_assessment_report.txt").read_text()
            self.assertIn("host_discovery.txt not found", report)

    def test_public_scope_refused(self):
        with tempfile.TemporaryDirectory() as tmp, \
                mock.patch.object(common, "run_command", side_effect=fake_run_command) as runner:
            argv = ["--subnet", "8.8.8.0/24", "--target", "8.8.8.8", "--authorized", "--output-dir", tmp]
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(cli.main(argv), 2)
            runner.assert_not_called()


if __name__ == "__main__":
    unittest.main()
