#!/usr/bin/python3
import sys
import struct
import wrapper
import threading
import time
from wrapper import recv_from_any_link, send_to_link, get_switch_mac, get_interface_name

class BPDU:
    def __init__(self, src_mac, root_bridge_id, sender_bridge_id, sender_path_cost, interface, message_age = 0, max_age = 20, hello_time = 0, forward_delay = 0,):
        self.dst_mac = bytes.fromhex("0180C2000000")
        self.src_mac = src_mac
        self.llc_length = 38
        self.dsap = 0x42
        self.ssap = 0x42
        self.control = 0x03
        self.bpdu_header = 0x00
        self.flags = 0x00
        self.root_bridge_id = root_bridge_id
        self.sender_path_cost = sender_path_cost
        self.sender_bridge_id = sender_bridge_id
        self.port_id = interface
        self.message_age = message_age
        self.max_age = max_age
        self.hello_time = hello_time
        self.forward_delay = forward_delay


    @classmethod
    def from_data(cls, data):
        src_mac = data[6:12]
        root_bridge_id = int.from_bytes(data[22:30], byteorder='big')
        sender_path_cost = int.from_bytes(data[30:34], byteorder='big')
        sender_bridge_id = int.from_bytes(data[34:42], byteorder='big')
        port_id = int.from_bytes(data[42:44], byteorder='big')
        message_age = int.from_bytes(data[44:46], byteorder='little')

        return cls(src_mac, root_bridge_id, sender_bridge_id, sender_path_cost, port_id, message_age)
    
    def __str__(self):
        return f"Dst MAC: {self.dst_mac}\nSrc MAC: {self.src_mac}\nLLC_Length: {self.llc_length}\nRoot Bridge ID: {self.root_bridge_id} ({self.root_bridge_id.to_bytes(8)})\nRoot Path Cost: {self.sender_path_cost}\nSender Bridge ID: {self.sender_bridge_id} ({self.sender_bridge_id.to_bytes(8)})\nPort ID: {self.port_id}\nMessage age: {self.message_age}\nMax age: {self.max_age}\nHello time: {self.hello_time}\nForward delay: {self.forward_delay}\n"
        

    def create_package(self):
        # network byte order elements (big-endian)
        bpdu_package = struct.pack("!6s6sHBBBIBQIQH", self.dst_mac, self.src_mac, self.llc_length, 
                                   self.dsap, self.ssap, self.control, self.bpdu_header, self.flags,
                                   self.root_bridge_id, self.sender_path_cost, self.sender_bridge_id, self.port_id)
        
        # host byte order elements (little-endian)
        bpdu_package += struct.pack("HHHH", self.message_age, self.max_age, self.hello_time, self.forward_delay)
        
        # add pading
        bpdu_package += struct.pack("8s", bytes(8))

        return bpdu_package


def parse_ethernet_header(data):
    # Unpack the header fields from the byte array
    #dest_mac, src_mac, ethertype = struct.unpack('!6s6sH', data[:14])
    dest_mac = data[0:6]
    src_mac = data[6:12]
    
    # Extract ethertype. Under 802.1Q, this may be the bytes from the VLAN TAG
    ether_type = (data[12] << 8) + data[13]

    vlan_id = -1
    # Check for VLAN tag (0x8100 in network byte order is b'\x81\x00')
    if ether_type == 0x8200:
        vlan_tci = int.from_bytes(data[14:16], byteorder='big')
        vlan_id = vlan_tci & 0x0FFF  # extract the 12-bit VLAN ID
        ether_type = (data[16] << 8) + data[17]

    return dest_mac, src_mac, ether_type, vlan_id


def create_vlan_tag(vlan_id):
    # 0x8100 for the Ethertype for 802.1Q
    # vlan_id & 0x0FFF ensures that only the last 12 bits are used
    return struct.pack('!H', 0x8200) + struct.pack('!H', vlan_id & 0x0FFF)

 
def send_bpdu_every_sec(own_bridge_id, root_info, trunk_interfaces_states):
    # get root_bridge_id and root_path_cost from mutable container in order to reflect changes
    root_bridge_id = root_info[0]
    root_path_cost = root_info[1]

    while True:
        if root_bridge_id == own_bridge_id:
            for i in trunk_interfaces_states.keys():
                if trunk_interfaces_states[i] == "Listening":
                    bpdu = BPDU(get_switch_mac(), root_bridge_id, own_bridge_id, root_path_cost, i)
                    pack = bpdu.create_package()
                    send_to_link(i, pack, len(pack))
                    # if __debug__:
                    #     print("[STP] Sending BDPU to trunk interface ", get_interface_name(i))
        time.sleep(1)


def check_bpdu_package(data, own_bridge_id, root_info, trunk_interfaces_states, recv_port):
    # get root_bridge_id and root_path_cost from mutable container in order to reflect changes
    root_bridge_id = root_info[0]
    root_path_cost = root_info[1]
    root_port = root_info[2]

    bpdu = BPDU.from_data(data)
    
    # the package exceded the age limit so it is dropped
    if bpdu.message_age >= bpdu.max_age:
        return

    # there is a new root bridge
    if bpdu.root_bridge_id < root_bridge_id:
        root_bridge_id = bpdu.root_bridge_id
        root_path_cost = bpdu.sender_path_cost + 10
        root_port = recv_port

        # check if this switch was root bridge
        if root_info[0] == own_bridge_id:
            for i in trunk_interfaces_states.keys():
                if i != root_port:
                    trunk_interfaces_states[i] = "Blocking"

        trunk_interfaces_states[root_port] = "Listening" # Root

        # forward package to all other trunk ports
        bpdu.sender_bridge_id = own_bridge_id
        bpdu.sender_path_cost = root_path_cost
        bpdu.message_age += 1
        pack = bpdu.create_package()

        for i in trunk_interfaces_states.keys():
            send_to_link(i, pack, len(pack))

    # the root bridge is the same
    elif bpdu.root_bridge_id == root_bridge_id:
        # check for shorter path on root_port
        if recv_port == root_port and bpdu.sender_path_cost + 10 < root_path_cost:
            root_path_cost = bpdu.sender_path_cost + 10

        # check if the port should be designated
        elif recv_port != root_port and bpdu.sender_path_cost > root_path_cost:
            trunk_interfaces_states[recv_port] = "Listening" # Designated

    elif bpdu.sender_bridge_id == own_bridge_id:
        trunk_interfaces_states[recv_port] = "Blocking"

    else:
        return
    
    root_info[0] = root_bridge_id
    root_info[1] = root_path_cost
    root_info[2] = root_port
    

def forward_package_from_access(recv_interface, data, new_data, length, mac_table, interfaces, vlan_map, trunk_interfaces_states):
    dest_mac, src_mac, ethertype, vlan_id = parse_ethernet_header(data)
    
    # check if the destination is access type, with a known mac and in the same vlan
    if dest_mac in mac_table and vlan_map[mac_table[dest_mac]] == vlan_map[recv_interface]:
        send_to_link(mac_table[dest_mac], data, length)
        if __debug__:
            print("[SWITCH] Sending to access interface ", get_interface_name(mac_table[dest_mac]))
    
    # check if the destination is trunk, with a known mac
    elif dest_mac in mac_table and vlan_map[mac_table[dest_mac]] == 'T' and trunk_interfaces_states[mac_table[dest_mac]] == "Listening":
        send_to_link(mac_table[dest_mac], new_data, len(new_data))
        if __debug__:
            print("[SWITCH] Sending to trunk interface ", get_interface_name(mac_table[dest_mac]))
    
    # destination mac is unkown or broadcast is sent
    else:
        for i in interfaces:
            # send to all access interfaces in the same vlan 
            if i != recv_interface and vlan_map[recv_interface] == vlan_map[i]:
                send_to_link(i, data, length)
                if __debug__:
                    print("[SWITCH] Sending to access interface ", get_interface_name(i))
            # send to all trunk interfaces
            elif i != recv_interface and vlan_map[i] == 'T' and trunk_interfaces_states[i] == "Listening":
                send_to_link(i, new_data, len(new_data))
                if __debug__:
                    print("[SWITCH] Sending to trunk interface ", get_interface_name(i))


def forward_package_from_trunk(recv_interface, data, new_data, length, mac_table, interfaces, vlan_map, trunk_interfaces_states):
    dest_mac, src_mac, ethertype, vlan_id = parse_ethernet_header(data)
    
    # check if the destination is access type, with a known mac and 
    # the destination vlan is the same with the tag
    if dest_mac in mac_table and vlan_map[mac_table[dest_mac]] == str(vlan_id):
        send_to_link(mac_table[dest_mac], new_data, len(new_data))
        if __debug__:
            print("[SWITCH] Sending to access interface ", get_interface_name(mac_table[dest_mac]))
    
    #check if the destination is trunk, with a known mac
    elif dest_mac in mac_table and vlan_map[mac_table[dest_mac]] == 'T' and trunk_interfaces_states[mac_table[dest_mac]] == "Listening":
        send_to_link(mac_table[dest_mac], data, length)
        if __debug__:
            print("[SWITCH] Sending to trunk interface ", get_interface_name(mac_table[dest_mac]))

    #destination mac is unkown or broadcast is sent
    else:
        for i in interfaces:
            # send to all access interfaces in the same vlan 
            if i != recv_interface and str(vlan_id) == vlan_map[i]:
                send_to_link(i, new_data, len(new_data))
                if __debug__:
                    print("[SWITCH] Sending to access interface ", get_interface_name(i))
            # send to all trunk interfaces
            elif i != recv_interface and vlan_map[i] == 'T' and trunk_interfaces_states[i] == "Listening":
                send_to_link(i, data, length)
                if __debug__:
                    print("[SWITCH] Sending to trunk interface ", get_interface_name(i))


def forward_package(recv_interface, data, length, mac_table, interfaces, vlan_map, trunk_interfaces_states):
    dest_mac, src_mac, ethertype, vlan_id = parse_ethernet_header(data)
    
    mac_table[src_mac] = recv_interface

    #print debug info
    if __debug__:
        # Print the MAC src and MAC dst in human readable format
        dest_mac = ':'.join(f'{b:02x}' for b in dest_mac)
        src_mac = ':'.join(f'{b:02x}' for b in src_mac)
        print("---------------------------------------------")
        print("                [FRAME INFO]")
        print(f'Destination MAC: {dest_mac}')
        print(f'Source MAC: {src_mac}')
        print(f'EtherType: {ethertype}')
        print(f'Vlan ID: {vlan_id}')
        print("\n")
        print("[SWITCH] Received frame of size {} on interface {}".format(length, get_interface_name(recv_interface)))
    

    # new_data is the header with the vlan tag if it doesn't have it 
    # or without the vlan tag if it does have it
    if vlan_id == -1:
        new_data = data[0:12] + create_vlan_tag(int(vlan_map[recv_interface])) + data[12:]
    else:
        new_data = data[0:12] + data[16:]

    
    # came from access interface
    if vlan_id == -1:
        forward_package_from_access(recv_interface, data, new_data, length, mac_table, interfaces, vlan_map, trunk_interfaces_states)
    
    # came from trunk interface
    else:
        forward_package_from_trunk(recv_interface, data, new_data, length, mac_table, interfaces, vlan_map, trunk_interfaces_states)
        
    
    if __debug__:
        print("---------------------------------------------\n")

def init_stp(switch_priority, interfaces, trunk_interfaces_states, vlan_map):
    # bridge id is formed by concatenating the mac to the priority bytes, resulting an 8 byte integer
    own_bridge_id = int.from_bytes(switch_priority.to_bytes(2) + get_switch_mac())
    root_bridge_id = own_bridge_id
    root_path_cost = 0
    root_port = -1

    # At first, the switch thinks that it is root bridge, so all trunk interfaces are listening
    for i in interfaces:
        if vlan_map[i] == 'T':
            trunk_interfaces_states[i] = "Listening" # Designated
    
    return own_bridge_id, [root_bridge_id, root_path_cost, root_port]

def main():
    switch_id = sys.argv[1]

    # MAC -> inteface
    mac_table = dict()

    # interface -> vlan
    vlan_map = dict()

    # trunk interface -> state
    trunk_interfaces_states = dict()

    # init returns the max interface number. Our interfaces
    # are 0, 1, 2, ..., init_ret value + 1
    num_interfaces = wrapper.init(sys.argv[2:])
    interfaces = range(0, num_interfaces)
    
    try:
        with open("configs/switch{}.cfg".format(switch_id)) as f:
            # set switch priority
            switch_priority = int(f.readline().strip())
            
            # Set the vlan for each interface.
            lines = f.readlines()
            for line in lines:
                split_line = line.strip().split(" ")
                for i in interfaces:
                    if split_line[0] == get_interface_name(i):
                        vlan_map[i] = split_line[1]
    except FileNotFoundError:
        print("[ERROR] Cannot open switch config file.")
        exit(1)

    # init STP
    own_bridge_id, root_info = init_stp(switch_priority, interfaces,
                                        trunk_interfaces_states, vlan_map)

    # print debug info
    if __debug__:
        print("# Starting switch with id {}".format(switch_id), flush=True)
        print("[INFO] Switch MAC", ':'.join(f'{b:02x}' for b in get_switch_mac()))
        print("[INFO] Switch Priority: ", switch_priority)
        print("[INFO] VLAN MAP: ", vlan_map)
        print("[INFO] Trunk interfaces states: ", trunk_interfaces_states)
        print("[INFO] Bridge ID: ", own_bridge_id, f"({own_bridge_id.to_bytes(8)})")
        print("\n")
    
    # Create and start a new thread that deals with sending BDPU
    t = threading.Thread(target=send_bpdu_every_sec, 
                         args=(own_bridge_id, root_info, trunk_interfaces_states))
    t.start()


    while True:
        interface, data, length = recv_from_any_link()

        if data[0:6] == bytes.fromhex("0180C2000000"):
            check_bpdu_package(data, own_bridge_id, root_info, trunk_interfaces_states, interface)
            
        else:
            forward_package(interface, data, length, mac_table, interfaces, vlan_map, trunk_interfaces_states)


if __name__ == "__main__":
    main()
