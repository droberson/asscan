#!/usr/bin/env python3

"""
TODO: cli for rate
TODO: cli to adjust timeouts
TODO: cli for interface/ip address to use
TODO: select interface with SO_BINDTODEVICE (setsockopt 25)
TODO: logging that isnt completely terrible
TODO: daemonize (to avoid screen/tmux)
TODO: ignore list
"""

import sys
import time
import socket
import random
import json
import termios
import argparse
import string

from fcntl import ioctl
from select import select
from struct import pack, unpack
from concurrent.futures import ThreadPoolExecutor

import requests

from dmfrbloom import timefilter

from cidrchunk import CIDRChunk
from pypacket import Packet


# lol "scripting".. change this if you want to do something useful.
def http_banner(url):
    time.sleep(12) # Wait a couple seconds longer than the time filter
                   # so this doesn't log multiple SYN|ACKs. lol
    banner = requests.get(url)
    print("\n", url, banner.headers["Server"], "\n")


def valid_port(port):
    """ valid_port() - Validate a port number.
    Args:
        port (int) - Port number to validate.
    Returns:
        True if port is a valid port number.
        False if port is not a valid port number.
    """
    try:
        if int(port) > 0 and int(port) < 65536:
            return True
    except ValueError:
        return False
    return False


def build_portlist(portlist):
    """ build_portlist() - Build list of ports from Nmap syntax.
    Args:
        portlist (str) - Nmap notation port list. Ex: 1-1024,5555,8080
    Returns:
        Unique list of ports derived from portlist on success.
        Empty list if portstring is invalid.
    """
    final = []
    allowed = set(string.digits + "-,")
    if (set(portlist) <= allowed) is False:
        return list()
    if portlist == "-":
        return [port for port in range(65536)]
    ports = portlist.split(",")
    for port in ports:
        if "-" in str(port):
            tmp = port.split("-")
            if len(tmp) != 2:
                return list()
            if int(tmp[0]) > int(tmp[1]):
                return list()
            final += range(int(tmp[0]), int(tmp[1]) + 1)
            continue
        final.append(int(port))
    if all(valid_port(port) for port in final) is True:
        return list(set(final))
    return list()


# https://stackoverflow.com/questions/166506/finding-local-ip-addresses-using-pythons-stdlib
def get_ip():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("10.255.255.255", 1))
        result = sock.getsockname()[0]
    except:
        result = "127.0.0.1"
    finally:
        sock.close()
    return result


def terminal_size():
    ws_struct = pack("HHHH", 0, 0, 0, 0)
    height, width, _, _ = unpack("HHHH", ioctl(0, termios.TIOCGWINSZ, ws_struct))
    return width, height


def checksum(msg):
    result = 0

    for byte in range(0, len(msg), 2):
        word = (msg[byte] + (msg[byte + 1] << 8))
        result += word

    result = (result >> 16) + (result & 0xffff)
    result += (result >> 16)

    return ~result & 0xffff


def scan(rawsock, saddr, daddr, port):
    ip_ihl = 5
    ip_ver = 4
    ip_tos = 0
    ip_tot_len = 0
    ip_id = 0
    ip_frag_off = 0
    ip_ttl = 255
    ip_proto = socket.IPPROTO_TCP
    ip_check = 0
    ip_saddr = socket.inet_aton(saddr)
    ip_daddr = socket.inet_aton(daddr)
    ip_ihl_ver = (ip_ver << 4) + ip_ihl
    ip_header = pack("!BBHHHBBH4s4s",
                     ip_ihl_ver,
                     ip_tos,
                     ip_tot_len,
                     ip_id,
                     ip_frag_off,
                     ip_ttl,
                     ip_proto,
                     ip_check,
                     ip_saddr,
                     ip_daddr)

    tcp_source = random.randint(1024, 65535)
    tcp_dest = port
    tcp_seq = random.randint(0, 10000000)
    tcp_ack_seq = 0
    tcp_doff = 5

    tcp_fin = 0
    tcp_syn = 1
    tcp_rst = 0
    tcp_psh = 0
    tcp_ack = 0
    tcp_urg = 0
    tcp_window = 1024
    tcp_check = 0
    tcp_urg_ptr = 0
    tcp_offset_res = (tcp_doff << 4) + 0
    tcp_flags = tcp_fin \
                + (tcp_syn << 1) \
                + (tcp_rst << 2) \
                + (tcp_psh << 3) \
                + (tcp_ack << 4) \
                + (tcp_urg << 5)

    tcp_header = pack("!HHLLBBHHH",
                      tcp_source,
                      tcp_dest,
                      tcp_seq,
                      tcp_ack_seq,
                      tcp_offset_res,
                      tcp_flags,
                      tcp_window,
                      tcp_check,
                      tcp_urg_ptr)
    data = b""

    source_address = socket.inet_aton(daddr)
    dest_address = socket.inet_aton(saddr)
    placeholder = 0
    protocol = socket.IPPROTO_TCP
    tcp_length = len(tcp_header) + len(data)

    pseudoheader = pack("!4s4sBBH",
                        source_address,
                        dest_address,
                        placeholder,
                        protocol,
                        tcp_length) + tcp_header + data

    tcp_check = checksum(pseudoheader)

    tcp_header = pack("!HHLLBBH",
                      tcp_source,
                      tcp_dest,
                      tcp_seq,
                      tcp_ack_seq,
                      tcp_offset_res,
                      tcp_flags,
                      tcp_window) \
                      + pack("H", tcp_check) \
                      + pack("!H", tcp_urg_ptr)
    rawpacket = ip_header + tcp_header + data
    rawsock.sendto(rawpacket, (daddr, 0))
    return True



def main():
    description = "asscan.py"
    parser = argparse.ArgumentParser(description=description)

    parser.add_argument(
        "hosts",
        action="store",
        nargs="+",
        help="host(s) to scan: 127.0.0,1, 10.0.0.0/8, ...")

    parser.add_argument(
        "-p",
        "--ports",
        action="store",
        help="port(s) to scan (Nmap style): 22, 10-100, -")

    args = parser.parse_args()

    if not args.ports:
        parser.print_help()
        print("[-] Must specify ports")
        exit()
    ports = build_portlist(args.ports)

    if not args.hosts:
        parser.print_help()
        print("[-] Must specify hosts")
        exit()

    my_ip = get_ip()

    # This filter should be 99.999% accurate @ 16.6kpps
    time_filter = timefilter.TimeFilter(500000, 0.001, 10)
    target_generator = CIDRChunk(*args.hosts)
    executor = ThreadPoolExecutor(max_workers=8)

    rawsock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    rawsock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    # Setting this stops "permission denied" errors when sending to a
    # broadcast address. I've only had this problem on VMWare networks.
    rawsock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    targets = []

    start = time.time()
    total = len(targets)
    ticks = 0
    scanned = 0
    found = 0
    done = False

    while True:
        readable, writable, exceptions = select([rawsock], [rawsock], [rawsock], 0.001)
        ticks += 1
        if ticks % 100 == 0 and not done:
            elapsed = time.time() - start
            width, _ = terminal_size()
            outstr = "\r%d scanned. %d found. %d pps. run time %d" % \
                     (scanned, found, scanned/elapsed, elapsed)
            sys.stderr.write(outstr.ljust(width - 1))
        elif done:
            width, _ = terminal_size()
            sys.stderr.write("\rDone. Waiting %d seconds...".ljust(width) % \
                             (20 - (time.time() - done)))

        for ready in readable:
            data = rawsock.recvfrom(1024)
            data = b'AAAAAADDDDDD\x08\x00' + data[0] # add bogus ethernet header
            packet = Packet(data)
            if packet.tcpflags == "SA": # Received a SYN|ACK
                if time_filter.lookup(packet.saddr + ":" + str(packet.sport)):
                    # Log open port
                    found += 1
                    result = {}
                    result["timestamp"] = time.time()
                    result["ip"] = packet.saddr
                    result["port"] = packet.sport
                    result["ttl"] = packet.ttl
                    with open("log.json", "a") as fp:
                        fp.write(json.dumps(result) + "\n")

                    # Secondary scan for open port
                    if packet.sport in [80, 8080, 8000]:
                        executor.submit(http_banner, "http://" + packet.saddr + ":" + str(packet.sport))

        #for ready in writable:

        try:
            # rate limit 1kpps
            if not done and scanned / (time.time() - start) > 1000:
                time.sleep(0.001)
                continue

            scanned += 1
            ip_address, port = targets[-1]
            time_filter.add(ip_address + ":" + str(port))
            targets.pop()

            scan(rawsock, my_ip, ip_address, port)
        except IndexError:
            # Grab a new chunk of ips to scan
            tmp = target_generator.get(1024)
            for port in ports:
                targets += [[ip, port] for ip in tmp]
            random.shuffle(targets)

            # Check if there are any more ips to scan
            if targets == []:
                if not done:
                    sys.stderr.write("\n")
                    sys.stderr.write("\rDone. Waiting 20 seconds...")
                    done = time.time()
                elif time.time() - done > 20: # wait for stragglers
                    exit()

        for ready in exceptions:
            # TODO havent ever hit here. is it necessary?
            print("e", ready)

    return True


if __name__ == "__main__":
    main()
