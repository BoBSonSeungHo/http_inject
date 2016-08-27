import pypcap
import pcap

from ipaddr import IPv4Address, IPv6Address
from scapy.all import *  
from socket import socket, AF_INET, SOCK_STREAM


    def __init__(self, request_object):
        """
        :param req_obj: HTTPRequest Object
        """
        self.request= request_object
        self.sock = self._make_socket

    def _302_payload(self):
        resp = "HTTP/1.1 302 Moved Permanently\r\n"
        resp += "Location: gilgil.net\r\n"
        resp += "\r\n"

        return resp

    def _make_socket(self):
        s = socket(AF_INET, SOCK_STREAM)
        s.connect((self.reqest.source_ipaddress, self.request.sport))
        return s


    def __init__(self, method, host, uri, dst_ip, user_agent, src_ip, src_port):
        self.method = method
        self.uri = uri
        self.user_agent = user_agent
        self.host = host
        self.dst_ip = str(dst_ip)
        self.src_ip = str(src_ip)
        self.sport = src_port

    def __repr__(self):
        return "<HTTPRequest %s>" % self.host

    def __str__(self):
        return "{0} {2} {1} ( {3} ) \"{4}\"".format(self.method, self.host, self.uri, self.dst_ip, self.user_agent)


    def __init__(self, interface):
        self.interface = interface
        self.pcap = pcap.pcap(interface, promisc=True)
        self.pcap.setfilter('tcp dst port 80')

    def __repr__(self):
        return "<HTTPMonitor %s>" % self.interface

    def requests(self):
        for ts, buf in self.pcap:
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                ip = eth.data
                tcp = ip.data

