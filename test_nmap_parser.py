"""
Tests for the SCOPEX Nmap XML parser.
"""

import pytest

from scopex.nmap.parser import NmapParseError, NmapParser


NMAP_XML = """\
<?xml version="1.0" encoding="UTF-8"?>
<nmaprun>
    <host>
        <status state="up"/>

        <address
            addr="203.0.113.10"
            addrtype="ipv4"
        />

        <hostnames>
            <hostname
                name="server.example.com"
                type="PTR"
            />
        </hostnames>

        <ports>
            <port protocol="tcp" portid="22">
                <state
                    state="open"
                    reason="syn-ack"
                />
                <service
                    name="ssh"
                    product="OpenSSH"
                    version="9.6"
                    extrainfo="protocol 2.0"
                />
            </port>

            <port protocol="tcp" portid="443">
                <state
                    state="open"
                    reason="syn-ack"
                />
                <service
                    name="https"
                    product="nginx"
                    version="1.24.0"
                />
            </port>

            <port protocol="tcp" portid="8080">
                <state
                    state="closed"
                    reason="reset"
                />
            </port>
        </ports>
    </host>
</nmaprun>
"""


def test_parser_extracts_host():
    parser = NmapParser()

    results = parser.parse(NMAP_XML)

    assert len(results) == 1

    host = results[0]

    assert host.address == "203.0.113.10"
    assert host.address_type == "ipv4"
    assert host.status == "up"


def test_parser_extracts_hostname():
    parser = NmapParser()

    results = parser.parse(NMAP_XML)

    assert results[0].hostnames == (
        "server.example.com",
    )


def test_parser_extracts_ports():
    parser = NmapParser()

    results = parser.parse(NMAP_XML)

    assert len(results[0].ports) == 3


def test_parser_extracts_service_information():
    parser = NmapParser()

    results = parser.parse(NMAP_XML)

    ssh = results[0].ports[0]

    assert ssh.port == 22
    assert ssh.protocol == "tcp"
    assert ssh.state == "open"
    assert ssh.service_name == "ssh"
    assert ssh.product == "OpenSSH"
    assert ssh.version == "9.6"
    assert ssh.extra_info == "protocol 2.0"


def test_parser_handles_port_without_service():
    parser = NmapParser()

    results = parser.parse(NMAP_XML)

    closed_port = results[0].ports[2]

    assert closed_port.port == 8080
    assert closed_port.state == "closed"
    assert closed_port.service_name is None
    assert closed_port.product is None
    assert closed_port.version is None


def test_parser_handles_multiple_hosts():
    xml = """\
    <nmaprun>
        <host>
            <status state="up"/>
            <address addr="203.0.113.10" addrtype="ipv4"/>
        </host>

        <host>
            <status state="up"/>
            <address addr="2001:db8::10" addrtype="ipv6"/>
        </host>
    </nmaprun>
    """

    parser = NmapParser()

    results = parser.parse(xml)

    assert len(results) == 2
    assert results[0].address == "203.0.113.10"
    assert results[0].address_type == "ipv4"
    assert results[1].address == "2001:db8::10"
    assert results[1].address_type == "ipv6"


def test_parser_handles_empty_host_list():
    parser = NmapParser()

    results = parser.parse(
        "<nmaprun></nmaprun>"
    )

    assert results == []


def test_parser_rejects_empty_input():
    parser = NmapParser()

    with pytest.raises(NmapParseError):
        parser.parse("")


def test_parser_rejects_invalid_xml():
    parser = NmapParser()

    with pytest.raises(NmapParseError):
        parser.parse("<nmaprun>")


def test_parser_rejects_wrong_root_element():
    parser = NmapParser()

    with pytest.raises(NmapParseError):
        parser.parse("<root></root>")


def test_parser_rejects_host_without_address():
    parser = NmapParser()

    xml = """
    <nmaprun>
        <host>
            <status state="up"/>
        </host>
    </nmaprun>
    """

    with pytest.raises(NmapParseError):
        parser.parse(xml)


def test_parser_infers_address_type():
    parser = NmapParser()

    xml = """
    <nmaprun>
        <host>
            <status state="up"/>
            <address addr="203.0.113.20"/>
        </host>
    </nmaprun>
    """

    results = parser.parse(xml)

    assert results[0].address_type == "ipv4"