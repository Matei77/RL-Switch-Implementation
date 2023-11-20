1 2 3

**Name: Ionescu Matei-Ștefan**  
**Group: 333CAb**

# RL Homework #1 - Switch Implementation
The program implements the core functions of a switch. It is able to forward packages taking the
interface VLAN into consideration and make sure loops are not present in the network using STP.

## Implementation

### Initialization
When the program starts, the switch will initialize its values. The following variables will be
used:

- **mac_table** - this represents a dictionary that will map a mac address to an interface

- **vlan_map** - this represents a dictionary that will map an interface to its VLAN

- **trunk_interfaces_states** -  this represents a dictionary that will map a trunk interface to
                                 its state ("Blocking" or "Listening")

- **own_bridge_id** - this represent the ID of the switch and is formed by concatenating the mac to
                      the priority bytes, resulting an 8 byte integer

- **root_info** - this represents a list which contains the root_bridge_id, root_path_cost and
                  root_port. A list is used so the changes of these values are refected across all
                  functions

The switch priority and the VLAN of each interface is read from the config file.

### Receiving Packages
After the initialization is completed, the program will start listening for packages. When a
package is received, the switch will check the destination MAC. If the destination MAC is
*01:80:C2:00:00:00*, the package is a BPDU package and it will be inspected according to the STP
protocol. Otherwise, the package needs to be forwarded.

### Forwarding Packages
When the package needs to be forwarded, the `forward_package()` function is called. This function
will update the **mac_table** by mapping the source MAC of the package to the interface on which
the package was received.

If the interface of the destination MAC is known and on "Listening", the package will be sent to
the destination if the VLAN matches. Otherwise, if the interface of the destination MAC is unknown
or a broadcast is sent, the package will be forwarded on all access interfaces in the same VLAN and
on all "Listening" trunk interfaces, except the one it came from.

### VLAN
- if the package came from an access interface and is going to a trunk interface, the 802.1q header
  is added.
- if the package came from an access interface and is going to another access interface, the
  package is not modified
- if the package came form a trunk interface and is going to another trunk interface, the package
  is not modified
- if the package came form a trunk interface and is going to an access interface, the 802.1q header
  is removed.

In order to meet these requirements, when a package is received from a trunk interface the
`forward_package_from_trunk()` function is called, and when a package is received from an access
interface the `forward_package_from_access()` function is called.

### STP
The `BPDU` class is used to send BPDU packages. The class contains all the fields of the BPDU
package structure.

Another thread, running the `send_bpdu_every_sec()` function, is sending every second BPDU packages
to all interfaces if the switch is the root bridge of the network.

When a BPDU package is received, the `check_bpdu_package()` function is called and it will update
the **root_info** and it will change the **trunk_interface_states** according to a simplified STP
algorithm.
