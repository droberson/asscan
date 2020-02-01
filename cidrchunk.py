import socket
from struct import pack, unpack


def netmask_from_bits(bits):
    """ netmask_from_bits() -- Generate a netmask based on CIDR.

    Example:
        >>> netmask_from_bits(24)
        4294967040
        >>> long_to_ip(netmask_from_bits(24))
        '255.255.255.0'

    Args:
        bits (int) - Number of bits in netmask.

    Returns:
        Integer representing netmask.
    """
    netmask = unpack("!I", pack("!I", (1 << 32) - (1 << (32 - int(bits)))))[0]
    return netmask & 0xffffffff


def ip_to_long(ip_address):
    tmp = socket.inet_aton(ip_address)
    return unpack("!L", tmp)[0]


def long_to_ip(ip_address):
    return socket.inet_ntoa(pack("!L", ip_address))


def valid_ipv4(ip_address):
    """ valid_ipv4() -- Validate an IP address.
    Args:
        ip_address (str) - IP address to validate.
    Returns:
        True if ip_address is valid.
        False if ip_address is not valid.
    """
    try:
        socket.inet_aton(ip_address)
    except socket.error:
        return False
    return True


def valid_cidr(cidr):
    """ valid_cidr() -- Validate CIDR network notation inputs.
    Args:
        cidr (str) - CIDR network to validate:
    Returns:
        True if cidr is valid.
        False if cidr is invalid.
    """
    if "/" not in cidr:
        return False

    network, mask = cidr.split("/")

    try:
        mask = int(mask)
    except ValueError:
        return False

    if valid_ipv4(network) == False:
        return False
    if mask > 32 or mask < 0:
        return False

    return True


class CIDRChunk():
    def __init__(self, *ranges):
        self.total = 0
        self.counter = 0
        self.networks = []

        self.networks = [x for x in ranges if valid_cidr(x) or valid_ipv4(x)]
        if len(self.networks) != len(ranges):
            raise ValueError("Invalid IP or CIDR provided.")

        for x in self.networks:
            if "/" not in x:
                self.total += 1
                continue
            network, mask = x.split("/")
            netmask = netmask_from_bits(mask)
            first = (ip_to_long(network) & netmask) & 0xffffffff
            last = (ip_to_long(network) | ~netmask) & 0xffffffff
            self.total += (last - first)

    def get(self, amount):
        result = []
        tmp_list = self.networks.copy()

        for x in tmp_list:
            if len(result) >= amount:
                return result

            if "/" not in x:
                self.counter = 0
                result += [x]
                self.networks.remove(x)
                continue

            network, mask = x.split("/")
            netmask = netmask_from_bits(mask)
            first = (ip_to_long(network) & netmask) & 0xffffffff
            last = (ip_to_long(network) | ~netmask) & 0xffffffff

            for y in range(first + self.counter, last + 1):
                self.counter += 1
                result += [long_to_ip(y)]

                if len(result) >= amount:
                    return result

            self.counter = 0
            self.networks.remove(x)

        return result
