import unittest
from unittest.mock import patch, MagicMock
from app.core.recon import Recon

class TestRecon(unittest.TestCase):
    def setUp(self):
        """Set up a Recon instance for testing."""
        self.target = "example.com"
        self.recon = Recon(self.target)

    def test_init(self):
        """Test Recon class initialization."""
        self.assertEqual(self.recon.target, self.target)
        self.assertEqual(self.recon.subdomains, [])
        self.assertEqual(self.recon.ports, {})

    @patch("dns.resolver.Resolver")
    def test_enumerate_subdomains_success(self, mock_resolver):
        """Test enumerate_subdomains with successful DNS resolution."""
        # Mock DNS resolver responses
        mock_instance = MagicMock()
        mock_resolver.return_value = mock_instance
        mock_instance.resolve.side_effect = [
            [MagicMock(rdata="ns1.example.com")],  # NS record for target
            [MagicMock()],  # A record for www.example.com
            Exception("NXDOMAIN"),  # No A record for api.example.com
            [MagicMock()],  # A record for dev.example.com
            Exception("NXDOMAIN"),  # No A record for staging.example.com
            Exception("NXDOMAIN"),  # No A record for test.example.com
        ]

        # Call the method
        subdomains = self.recon.enumerate_subdomains()

        # Expected subdomains
        expected = ["www.example.com", "dev.example.com"]
        self.assertEqual(subdomains, expected)
        self.assertEqual(self.recon.subdomains, expected)
        mock_instance.resolve.assert_called()
        calls = mock_instance.resolve.call_args_list
        self.assertEqual(len(calls), 6)  # 1 NS + 5 subdomain A queries
        self.assertEqual(calls[0][0][0], self.target)  # NS query for target
        self.assertEqual(calls[1][0][0], "www.example.com")  # A query for www

    @patch("dns.resolver.Resolver")
    def test_enumerate_subdomains_failure(self, mock_resolver):
        """Test enumerate_subdomains when DNS resolution fails."""
        # Mock DNS resolver to raise an exception
        mock_instance = MagicMock()
        mock_resolver.return_value = mock_instance
        mock_instance.resolve.side_effect = Exception("DNS server error")

        # Call the method
        subdomains = self.recon.enumerate_subdomains()

        # Expect empty list on failure
        self.assertEqual(subdomains, [])
        self.assertEqual(self.recon.subdomains, [])
        mock_instance.resolve.assert_called_once_with(self.target, "NS")

    @patch("nmap.PortScanner")
    def test_scan_ports_success(self, mock_nmap):
        """Test scan_ports with successful port scan."""
        # Mock nmap scan results
        mock_nm = MagicMock()
        mock_nmap.return_value = mock_nm
        mock_nm.all_hosts.return_value = [self.target]
        mock_nm.__getitem__.return_value.all_protocols.return_value = ["tcp"]
        mock_nm.__getitem__.return_value.__getitem__.return_value.keys.return_value = [80, 443]
        mock_nm.__getitem__.return_value.__getitem__.return_value.__getitem__.return_value = {
            "state": "open"
        }

        # Call the method
        ports = self.recon.scan_ports()

        # Expected ports
        expected = {80: "open", 443: "open"}
        self.assertEqual(ports, expected)
        self.assertEqual(self.recon.ports, expected)
        mock_nm.scan.assert_called_once_with(self.target, arguments="-sS -p 1-65535 --open")

    @patch("nmap.PortScanner")
    def test_scan_ports_failure(self, mock_nmap):
        """Test scan_ports when nmap scan fails."""
        # Mock nmap to raise an exception
        mock_nm = MagicMock()
        mock_nmap.return_value = mock_nm
        mock_nm.scan.side_effect = Exception("Nmap error")

        # Call the method
        ports = self.recon.scan_ports()

        # Expect empty dict on failure
        self.assertEqual(ports, {})
        self.assertEqual(self.recon.ports, {})
        mock_nm.scan.assert_called_once_with(self.target, arguments="-sS -p 1-65535 --open")

    @patch("nmap.PortScanner")
    def test_scan_ports_no_open_ports(self, mock_nmap):
        """Test scan_ports when no open ports are found."""
        # Mock nmap with no open ports
        mock_nm = MagicMock()
        mock_nmap.return_value = mock_nm
        mock_nm.all_hosts.return_value = [self.target]
        mock_nm.__getitem__.return_value.all_protocols.return_value = []
        
        # Call the method
        ports = self.recon.scan_ports()

        # Expect empty dict when no protocols/ports found
        self.assertEqual(ports, {})
        self.assertEqual(self.recon.ports, {})
        mock_nm.scan.assert_called_once_with(self.target, arguments="-sS -p 1-65535 --open")


if __name__ == "__main__":
    unittest.main()
