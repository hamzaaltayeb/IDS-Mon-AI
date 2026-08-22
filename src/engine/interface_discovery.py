import os
import socket
import fcntl
import struct
import scapy.all as scapy

class InterfaceDiscovery:
    """
    Dynamically discovers and inspects host network interfaces on Linux / Parrot OS.
    """
    @staticmethod
    def get_ip_address(ifname):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            return socket.inet_ntoa(fcntl.ioctl(
                s.fileno(),
                0x8915,  # SIOCGIFADDR
                struct.pack('256s', ifname[:15].encode('utf-8'))
            )[20:24])
        except Exception:
            return None

    @staticmethod
    def get_mac_address(ifname):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            info = fcntl.ioctl(
                s.fileno(),
                0x8927,  # SIOCGIFHWADDR
                struct.pack('256s', ifname[:15].encode('utf-8'))
            )
            return ':'.join(['%02x' % b for b in info[18:24]])
        except Exception:
            return None

    @classmethod
    def get_all_interfaces(cls):
        try:
            iface_names = scapy.get_if_list()
        except Exception:
            iface_names = ['lo']

        # Ensure lo is present
        if 'lo' not in iface_names:
            iface_names.insert(0, 'lo')

        result = []
        for ifname in set(iface_names):
            is_up = False
            operstate_path = f'/sys/class/net/{ifname}/operstate'
            if os.path.exists(operstate_path):
                try:
                    with open(operstate_path, 'r') as f:
                        state = f.read().strip().lower()
                        is_up = (state == 'up' or state == 'unknown')
                except Exception:
                    is_up = True
            else:
                is_up = True

            is_loopback = (ifname == 'lo')
            if is_loopback:
                iface_type = 'Loopback'
            elif ifname.startswith('wl') or 'wifi' in ifname or 'wlan' in ifname:
                iface_type = 'Wi-Fi'
            elif ifname.startswith('tun') or ifname.startswith('tap') or ifname.startswith('docker') or ifname.startswith('veth'):
                iface_type = 'Virtual/Tunnel'
            else:
                iface_type = 'Ethernet'

            ipv4 = cls.get_ip_address(ifname)
            mac = cls.get_mac_address(ifname)

            desc = f"{ifname} ({iface_type})"
            if ipv4 and ipv4 != 'None':
                desc += f" - IPv4: {ipv4}"
            if not is_up:
                desc += " [DOWN]"

            result.append({
                'name': ifname,
                'type': iface_type,
                'is_up': is_up,
                'ipv4': ipv4 or 'None',
                'mac': mac or 'None',
                'is_loopback': is_loopback,
                'description': desc
            })

        # Sort: active physical interfaces first, then loopback
        return sorted(result, key=lambda x: (not x['is_up'], x['is_loopback'], x['name']))

    @classmethod
    def get_default_active_interface(cls):
        interfaces = cls.get_all_interfaces()
        # Prefer physical active interface with IPv4
        for iface in interfaces:
            if not iface['is_loopback'] and iface['is_up'] and iface['ipv4'] != 'None':
                return iface['name']
        for iface in interfaces:
            if not iface['is_loopback'] and iface['is_up']:
                return iface['name']
        return 'lo'
