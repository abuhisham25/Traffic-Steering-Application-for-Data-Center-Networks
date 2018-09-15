""" 
Workshop In Communication Networks - Final Project - Topology File
Laith Abu-Omar [08609931-4] (abuhisham), Abdelmoute Ewiwi [30851125-2] (abdele)
This file represents the fat tree topolgy we used in Parts 1 & 2 of the Project.
"""

from mininet.topo import Topo

def int2dpid( dpid ):
        try:
            dpid = hex( dpid )[ 2: ]
            dpid = '0' * ( 16 - len( dpid ) ) + dpid
            return dpid
        except IndexError:
            raise Exception( 'Unable to derive default datapath ID - '
                             'please either specify a dpid or use a '
                             'canonical switch name such as s23.' )

class Edge:
    """Represents an edge between two entities"""
    
    def __init__(self, left, right):
        self.left = left
        self.right = right


class FatTreeTopology( Topo ):
    """ 
    This topology class emulates a data center network as a folded clos network (fat tree),
    with two levels of switches, 2 core switches in the first level, and 4 ToR switches
    in the second level. Each ToR switch is connected to 2 hosts, and is also connected to 
    both core switches above it.
    """
    
    def __init__( self ):
        """Create custom topo."""

        Topo.__init__( self )

        # Set Node IDs for hosts and switches

        # Add switches
        switches = [
                self.addSwitch('s100', dpid=int2dpid(100)),
                self.addSwitch('s101', dpid=int2dpid(101)),
                # self.addSwitch('s300', dpid=int2dpid(300)),
                # self.addSwitch('s301', dpid=int2dpid(301)),
                # self.addSwitch('s302', dpid=int2dpid(302)),
                # self.addSwitch('s303', dpid=int2dpid(303))
            ]
        
        # Add hosts
        hosts = [
                self.addHost('h1', ip='10.0.0.10/24'),
                self.addHost('h2', ip='10.0.0.20/24'),
                self.addHost('h3', ip='10.0.0.30/24'),
                self.addHost('h4', ip='10.0.0.40/24'),
                # self.addHost('h5', ip='10.0.0.50/24'),
                # self.addHost('h6', ip='10.0.0.60/24'),
                # self.addHost('h7', ip='10.0.0.70/24'),
                # self.addHost('h8', ip='10.0.0.80/24')
                # self.addHost('h9', ip='10.0.0.90/24')
            ]

        # Add Edges (core - ToR, and ToR - host)
        edges = [   
                    Edge(switches[0],   switches[1]),
                    # Edge(switches[0],   switches[3]),
                    # Edge(switches[0],   switches[4]),
                    # Edge(switches[0],   switches[5]),
                    # Edge(switches[1],   switches[2]),
                    # Edge(switches[1],   switches[3]),
                    # Edge(switches[1],   switches[4]),
                    # Edge(switches[1],   switches[5]),
                    Edge(hosts[0],      switches[0]), 
                    Edge(hosts[1],      switches[0]), 
                    Edge(hosts[2],      switches[1]),
                    Edge(hosts[3],      switches[1])
                    # Edge(hosts[4],      switches[4]),
                    # Edge(hosts[5],      switches[4]),
                    # Edge(hosts[6],      switches[5]),
                    # Edge(hosts[7],      switches[5])
                    # Edge(hosts[8],      switches[5])
            ]

        for edge in edges:
            self.addLink( edge.left, edge.right )
        

topos = { 'FatTreeTopology': ( lambda: FatTreeTopology() ) }