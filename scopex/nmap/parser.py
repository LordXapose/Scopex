"""
Parser for Nmap XML output.
"""

from __future__ import annotations

import ipaddress
import xml.etree.ElementTree as ET

from scopex.nmap.models import NmapHostResult, NmapPort


class NmapParseError(ValueError):
    """Raised when Nmap XML cannot be parsed."""


class NmapParser:
    """
    Convert Nmap XML into structured SCOPEX models.
    """

    def parse(self, xml_data: str) -> list[NmapHostResult]:
        """
        Parse Nmap XML containing zero or more hosts.
        """

        if not xml_data or not xml_data.strip():
            raise NmapParseError(
                "Nmap XML input cannot be empty."
            )

        try:
            root = ET.fromstring(xml_data)
        except ET.ParseError as exc:
            raise NmapParseError(
                f"Invalid Nmap XML: {exc}"
            ) from exc

        if root.tag != "nmaprun":
            raise NmapParseError(
                "Invalid Nmap XML: expected <nmaprun> root element."
            )

        results: list[NmapHostResult] = []

        for host_element in root.findall("host"):
            results.append(
                self._parse_host(host_element)
            )

        return results

    def _parse_host(
        self,
        host_element: ET.Element,
    ) -> NmapHostResult:
        """
        Parse a single Nmap host.
        """

        address_element = host_element.find("address")

        if address_element is None:
            raise NmapParseError(
                "Nmap host is missing an address."
            )

        address = address_element.get("addr")

        if not address:
            raise NmapParseError(
                "Nmap host address is empty."
            )

        address_type = address_element.get(
            "addrtype",
            self._infer_address_type(address),
        )

        status_element = host_element.find("status")

        status = "unknown"

        if status_element is not None:
            status = status_element.get(
                "state",
                "unknown",
            )

        hostnames: list[str] = []

        hostnames_element = host_element.find("hostnames")

        if hostnames_element is not None:
            for hostname_element in hostnames_element.findall(
                "hostname"
            ):
                hostname = hostname_element.get("name")

                if hostname:
                    hostnames.append(hostname)

        ports: list[NmapPort] = []

        ports_element = host_element.find("ports")

        if ports_element is not None:
            for port_element in ports_element.findall("port"):
                ports.append(
                    self._parse_port(port_element)
                )

        os_name = None
        os_accuracy = None

        os_element = host_element.find("os")

        if os_element is not None:
            os_match = os_element.find("osmatch")

            if os_match is not None:
                os_name = os_match.get("name")

                accuracy = os_match.get("accuracy")

                if accuracy is not None:
                    try:
                        os_accuracy = int(accuracy)
                    except ValueError:
                        os_accuracy = None

        return NmapHostResult(
            address=address,
            address_type=address_type,
            hostnames=tuple(hostnames),
            status=status,
            ports=tuple(ports),
            os_name=os_name,
            os_accuracy=os_accuracy,
        )

    def _parse_port(
        self,
        port_element: ET.Element,
    ) -> NmapPort:
        """
        Parse a single Nmap port.
        """

        port_value = port_element.get("portid")

        if not port_value:
            raise NmapParseError(
                "Nmap port is missing portid."
            )

        try:
            port = int(port_value)
        except ValueError as exc:
            raise NmapParseError(
                f"Invalid Nmap port number: {port_value}"
            ) from exc

        protocol = port_element.get(
            "protocol",
            "unknown",
        )

        state = "unknown"

        state_element = port_element.find("state")

        if state_element is not None:
            state = state_element.get(
                "state",
                "unknown",
            )

        service_name = None
        product = None
        version = None
        extra_info = None

        service_element = port_element.find("service")

        if service_element is not None:
            service_name = service_element.get("name")
            product = service_element.get("product")
            version = service_element.get("version")
            extra_info = service_element.get("extrainfo")

        return NmapPort(
            port=port,
            protocol=protocol,
            state=state,
            service_name=service_name,
            product=product,
            version=version,
            extra_info=extra_info,
        )

    @staticmethod
    def _infer_address_type(address: str) -> str:
        """
        Infer IPv4/IPv6 when Nmap does not provide addrtype.
        """

        try:
            parsed = ipaddress.ip_address(address)
        except ValueError:
            return "unknown"

        if parsed.version == 4:
            return "ipv4"

        return "ipv6"