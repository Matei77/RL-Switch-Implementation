#!/usr/bin/python3
import sys
import struct
import wrapper
import threading
import time
from wrapper import recv_from_any_link, send_to_link, get_switch_mac, get_interface_name

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

def send_bdpu_every_sec():
    while True:
        # TODO Send BDPU every second if necessary
        time.sleep(1)



def forward_package(recv_interface, data, length, mac_table, interfaces, vlan_map):
    dest_mac, src_mac, ethertype, vlan_id = parse_ethernet_header(data)

    # Print the MAC src and MAC dst in human readable format
    dest_mac = ':'.join(f'{b:02x}' for b in dest_mac)
    src_mac = ':'.join(f'{b:02x}' for b in src_mac)

    #print debug info
    if __debug__:
        print("---------------------------------------------")
        print("                [FRAME INFO]")
        print(f'Destination MAC: {dest_mac}')
        print(f'Source MAC: {src_mac}')
        print(f'EtherType: {ethertype}')
        print(f'Vlan ID: {vlan_id}')
        print("\n")
        print("[SWITCH] Received frame of size {} on interface {}".format(length, get_interface_name(recv_interface)))
    
    mac_table[src_mac] = recv_interface
    
    # new_data is the header with the vlan tag if it doesn't have it 
    # or without the vlan tag if it does have it
    if vlan_id == -1:
        new_data = data[0:12] + create_vlan_tag(int(vlan_map[recv_interface])) + data[12:]
    else:
        new_data = data[0:12] + data[16:]

    
    # came from access type interface
    if vlan_id == -1:
        # check if the destination is access type, with a known mac and in the same vlan
        if dest_mac in mac_table and vlan_map[mac_table[dest_mac]] == vlan_map[recv_interface]:
            send_to_link(mac_table[dest_mac], data, length)
            if __debug__:
                print("[SWITCH] Sending to access interface ", get_interface_name(mac_table[dest_mac]))
        
        # check if the destination is trunk, with a knwon mac
        elif dest_mac in mac_table and vlan_map[mac_table[dest_mac]] == 'T':
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
                elif i != recv_interface and vlan_map[i] == 'T':
                    send_to_link(i, new_data, len(new_data))
                    if __debug__:
                        print("[SWITCH] Sending to trunk interface ", get_interface_name(i))
    
    # came from trunk
    else:
        # check if the destination is access type, with a known mac and 
        # the destination vlan is the same with the tag
        if dest_mac in mac_table and vlan_map[mac_table[dest_mac]] == str(vlan_id):
            send_to_link(mac_table[dest_mac], new_data, len(new_data))
            if __debug__:
                print("[SWITCH] Sending to access interface ", get_interface_name(mac_table[dest_mac]))
        
        #check if the destination is trunk, with a known mac
        elif dest_mac in mac_table and vlan_map[mac_table[dest_mac]] == 'T':
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
                elif i != recv_interface and vlan_map[i] == 'T':
                    send_to_link(i, data, length)
                    if __debug__:
                        print("[SWITCH] Sending to trunk interface ", get_interface_name(i))
    
    if __debug__:
        print("---------------------------------------------\n")


def main():
    # init returns the max interface number. Our interfaces
    # are 0, 1, 2, ..., init_ret value + 1
    switch_id = sys.argv[1]

    mac_table = dict()
    vlan_map = dict()

    num_interfaces = wrapper.init(sys.argv[2:])
    interfaces = range(0, num_interfaces)
    
    # Set the vlan for each interface.
    # The vlan_map dictionary is mapping the interface number to the vlan.
    try:
        with open("configs/switch{}.cfg".format(switch_id)) as f:
            lines = f.readlines()
            for line in lines:
                split_line = line.strip().split(" ")
                for i in interfaces:
                    if split_line[0] == get_interface_name(i):
                        vlan_map[i] = split_line[1]
    except FileNotFoundError:
        print("[ERROR] Cannot open switch config file.")
        exit(1)

    # print debug info
    if __debug__:
        print("# Starting switch with id {}".format(switch_id), flush=True)
        print("[INFO] Switch MAC", ':'.join(f'{b:02x}' for b in get_switch_mac()))
        print("[INFO] VLAN MAP: ", vlan_map)
        print("\n")
    
    # Create and start a new thread that deals with sending BDPU
    t = threading.Thread(target=send_bdpu_every_sec)
    t.start()


    while True:
        interface, data, length = recv_from_any_link()
        
        forward_package(interface, data, length, mac_table, interfaces, vlan_map)

        # TODO: Implement STP support


if __name__ == "__main__":
    main()
