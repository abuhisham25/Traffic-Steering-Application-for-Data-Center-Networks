"""
Workshop in Communication Networks - Final Project
Laith Abu-Omar [08609931-4] (abuhisham), Abdelmoute Ewiwi [30851125-2] (abdele)
basic2LevelTSA.py -- Parts 1 & 2
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of
from utils import *
import time
from pox.lib.packet.lldp import lldp, chassis_id, port_id, ttl, end_tlv
from pox.lib.packet.ethernet import ethernet
from pox.lib.addresses import EthAddr, IPAddr
from pox.lib.packet.arp import arp
from pox.lib.packet.ipv4 import ipv4
from random import randint  # @see installNonNFToRRules and installNFToRRules

log = core.getLogger()

CONFIG_FILENAME = '/home/mininet/policyConfig'
NF_VLAN = 2
NF_DPID = 3
NF_PORT = 4
VLAN_DONE = 1
VLAN_SPECIAL = 0

services = {}       # NFs and IP address of servicing host of serving host, gateway switch and port
policies = []       # List of all Policy objects (@see Class Policy)
coreSwitches = []
switchesConn = {}   # Switches DPID and Connection object of the switch
configHelper = {1 : False, 2 : False , 3 : []}
hostsLocation = {}




class Tutorial (object):
    """
    A Tutorial object is created for each switch that connects.
    A Connection object for that switch is passed to the __init__ function.
    """
    def __init__ (self, connection):
        self.connection = connection
        self.switchTable = {}
        switchesConn[str(self.connection.dpid)] = self.connection

        # if this is a Core switch, save its DPID. @see installNonNFToRRules() and installNFToRRules()
        if int(self.connection.dpid) in range(100, 200):
            coreSwitches.append(str(self.connection.dpid))

        # This binds our PacketIn event listener
        connection.addListeners(self)

    def _handle_PacketIn (self, event):
        """
        Handles packet in messages from the switch.
        """
  
        packet = event.parsed # Packet is the original L2 packet sent by the switch
        packet_in = event.ofp # packet_in is the OpenFlow packet sent by the switch
        src = str(packet.src)
        dst = str(packet.dst)
        inPort = int(packet_in.in_port)
        switch = str(self.connection.dpid)

        if not packet.parsed:
            log.warning("Ignoring incomplete packet")
            return

        # Ignore IPv6 discovery messages
        if "33:33:00:00:00:" in str(packet.dst):
            return

        # Catching ARP reply packets used for detecting NFs locations
        if packet.type == ethernet.ARP_TYPE:
            arpPacket = packet.payload

            if arpPacket.opcode == arp.REPLY:
                ipSrc = arpPacket.protosrc

                for nf in services:
                    if services[nf][1] == str(ipSrc):
                        if not services[nf][0]:
                            services[nf][0] = True
                            services[nf].append(str(self.connection.dpid))
                            services[nf].append(str(packet_in.in_port))
                            # log.debug("enter arp_reply section src is "+src +" dst is "+dst+" inport "+str(inPort))
                            return

        if packet.type == ethernet.LLDP_TYPE:
            self.discoverNF()

        if packet.type != ethernet.LLDP_TYPE:
            if int(switch) in range(100,200):
                if hostsLocation.get(dst) is not None:
                    dstSwitch = hostsLocation[dst][0]
                    dstPort = Discovery.getPort(int(switch),int(dstSwitch))
                    # log.debug("Core Switch s" + switch + " forwarding packet with VLAN_SPECIAL to s" + dstSwitch + " through port " + str(dstPort))
                    self.send_packet(packet_in.buffer_id, packet_in.data, int(dstPort), inPort)
            else:
                if hostsLocation.get(src) is None:
                    # log.debug("New host found: [" + src + ", " + switch + ", " + str(inPort) + "]")
                    hostsLocation[src] = [switch,inPort]
                if hostsLocation.get(dst) is None:

                    # corePort = str(coreSwitches[randint(0, (len(coreSwitches) - 1))])
                    coreSwitch = coreSwitches[0]
                    corePort = Discovery.getPort(int(switch), int(coreSwitch))
                    # log.debug("ToR Switch s" + switch + " forwarding packet with VLAN_DONE to s" + coreSwitch + " through port " + str(corePort) + " and to hosts ------- " + "src is "+src+" dst is "+dst+" inport is "+str(inPort))
                    self.unknownSend(packet_in.buffer_id,packet_in.data,corePort,inPort,switch)

                elif hostsLocation[dst][0] == switch:
                    dstPort = hostsLocation[dst][1]
                    # log.debug("ToR Switch s" + switch + " forwarding packet with VLAN_SPECIAL to host" + " through port " + str(dstPort))
                    self.send_packet(packet_in.buffer_id, packet_in.data, int(dstPort), inPort, True)
                else:


                    # corePort = str(coreSwitches[randint(0, (len(coreSwitches) - 1))])

                    coreSwitch = coreSwitches[0]
                    corePort = Discovery.getPort(int(switch), int(coreSwitch))
                    # log.debug("ToR Switch s" + switch + " forwarding packet after setting VLAN_SPECIAL to s" + coreSwitch + " through port " + str(corePort))
                    self.knownSend(packet_in.buffer_id,packet_in.data,corePort,inPort)


    def knownSend(self, buffer_id, raw_data, out_port, in_port):
        """
        Sends packet to known host
        """

        msg = of.ofp_packet_out()
        msg.in_port = in_port
        if buffer_id != -1 and buffer_id is not None:
            # We got a buffer ID from the switch; use that
            msg.buffer_id = buffer_id
        else:
            # No buffer ID from switch -- we got the raw data
            if raw_data is None:
                # No raw_data specified -- nothing to send!
                return
            msg.data = raw_data
    
        # Add an action to send to the specified port
        action1 = of.ofp_action_vlan_vid(vlan_vid = VLAN_SPECIAL)
        action2 = of.ofp_action_output(port = out_port)
        msg.actions.append(action1)
        msg.actions.append(action2)
    
        # Send message to switch
        self.connection.send(msg)


    def unknownSend(self,buffer_id, raw_data, out_port, in_port,switch):
        """
        Sends packet to unknown host
        """

        msg = of.ofp_packet_out()
        msg.in_port = in_port
        if buffer_id != -1 and buffer_id is not None:
            # We got a buffer ID from the switch; use that
            msg.buffer_id = buffer_id
        else:
            # No buffer ID from switch -- we got the raw data
            if raw_data is None:
                # No raw_data specified -- nothing to send!
                return
            msg.data = raw_data
    
        # Add an action to send to the specified port
        action1 = of.ofp_action_vlan_vid(vlan_vid = VLAN_DONE)
        action2 = of.ofp_action_output(port = out_port)
        
        msg.actions.append(action1)
        msg.actions.append(action2)
        allPorts = [int(p) for p in Discovery.graph.nodes[int(switch)].connection.ports]
        corePorts = Discovery.getPorts(int(switch))
        hostPorts = list(set(allPorts) - set(corePorts))
        for p in hostPorts:
            if p < of.OFPP_MAX :
                action3 = of.ofp_action_vlan_vid()
                action4 = of.ofp_action_output(port = p)
                msg.actions.append(action3)
                msg.actions.append(action4)

        # Send message to switch
        self.connection.send(msg)



    def send_packet (self, buffer_id, raw_data, out_port, in_port, vlan_clear = False):
        """
        Sends a packet out of the specified switch port.
        If buffer_id is a valid buffer on the switch, use that. Otherwise,
        send the raw data in raw_data.
        The "in_port" is the port number that packet arrived on.  Use
        OFPP_NONE if you're generating this packet.
        """

        # We tell the switch to take the packet with id buffer_if from in_port 
        # and send it to out_port
        # If the switch did not specify a buffer_id, it must have specified
        # the raw data of the packet, so in this case we tell it to send
        # the raw data
        msg = of.ofp_packet_out()
        msg.in_port = in_port
        if buffer_id != -1 and buffer_id is not None:
            # We got a buffer ID from the switch; use that
            msg.buffer_id = buffer_id
        else:
            # No buffer ID from switch -- we got the raw data
            if raw_data is None:
                # No raw_data specified -- nothing to send!
                return
            msg.data = raw_data
    
        # Add an action to send to the specified port
        if vlan_clear:
            action = of.ofp_action_vlan_vid()
            msg.actions.append(action)

        action = of.ofp_action_output(port = out_port)
        msg.actions.append(action)
    
        # Send message to switch
        self.connection.send(msg)


    def discoverNF(self):
        """
        Loops over the services dictionary and calls getNFLocation() which 
        sends ARP requests to the serving hosts in order to determine
        the locations of the NFs.
        """

        entered = False
        for nf in services:
            if not services[nf][0]:
                entered = True
                hostIP = services[nf][1]
                self.getNFLocation(hostIP)

        if not entered and not configHelper[1]:
            log.debug(str(services))
            configHelper[1] = True

        if not entered and not configHelper[2]:
            configHelper[2] = True
            Tutorial.deleteAllRules()
            Tutorial.installPolicyRules()
            # log.debug(str(RulesTable()))

        if not entered:
            newSwitches = list(set(Discovery.switchNodes) - set(configHelper[3]))
            if len(newSwitches) > 0:
                Tutorial.deleteAllRules()
                Tutorial.installPolicyRules()
                configHelper[3] = []
                configHelper[3] = [i for i in Discovery.switchNodes]
                # log.debug(str(RulesTable()))

    def getNFLocation(self, ipAddress):
        """
        sends ARP requests to the serving hosts in order to determine
        the locations of the NFs.
        """

        r = arp()
        r.opcode = arp.REQUEST
        r.protodst = IPAddr(ipAddress)
        e = ethernet(type=ethernet.ARP_TYPE, dst=EthAddr("FF:FF:FF:FF:FF:FF"))
        e.set_payload(r)
        msg = of.ofp_packet_out(data = e.pack())
        allPorts = [int(p) for p in Discovery.graph.nodes[int(str(self.connection.dpid))].connection.ports]
        corePorts = Discovery.getPorts(int(str(self.connection.dpid)))
        hostPorts = list(set(allPorts) - set(corePorts))
        for p in hostPorts:
            if p < of.OFPP_MAX:
                action = of.ofp_action_output(port = p)
                msg.actions.append(action)
        if int(self.connection.dpid) in range(300,400):
            self.connection.send(msg)

    @staticmethod
    def installPolicyRules():
        """
        Installs policy rules on all switches according to the parsed policyConfig
        file
        """

        for switch in switchesConn:
            if int(switch) in range(100, 200):
                Tutorial.installCoreRules(switch)
                if not configHelper[2]:
                    return
            elif switch not in [services[i][NF_DPID] for i in services]:
                Tutorial.installNonNFToRRules(switch)
                if not configHelper[2]:
                    return
            else:
                Tutorial.installNFToRRules(switch)
                if not configHelper[2]:
                    return

            Tutorial.installPolicyDoneRule(switch)


    @staticmethod
    def installCoreRules(switch):
        """
        Installs rules for Core switch
        """

        for pol in policies:
            mList = pol.match
            cList = pol.chain

            if len(cList) == 0:
                return

            fm = Tutorial.matchBuilder(mList)
            fm.match.dl_vlan = of.OFP_VLAN_NONE
            nfSwitch = services[cList[0]][NF_DPID]
            nfPort = Discovery.getPort(int(switch), int(nfSwitch))
            if nfPort is None:
                configHelper[2] = False
                return

            action = of.ofp_action_output(port = int(nfPort))
            fm.actions.append(action)
            RulesTable.addRule(switch,mList,None,nfPort)
            switchesConn[switch].send(fm)

            if len(cList) >= 2:
                for i in range(len(cList) - 1):
                    nfSwitch = services[cList[(i + 1)]][NF_DPID]
                    prevNfSwitch = services[cList[i]][NF_DPID]
                    if nfSwitch != prevNfSwitch:
                        fm = Tutorial.matchBuilder(mList)
                        fm.match.dl_vlan = services[cList[i]][NF_VLAN]
                        nfPort = Discovery.getPort(int(switch), int(nfSwitch))
                        if nfPort is None:
                            configHelper[2] = False
                            return

                        action = of.ofp_action_output(port = int(nfPort))
                        fm.actions.append(action)
                        RulesTable.addRule(switch,mList,services[cList[i]][NF_VLAN],nfPort)
                        switchesConn[switch].send(fm)

    @staticmethod
    def installNonNFToRRules(switch):
        """
        Installs rules for ToR switches that don't have NFs
        connected to them
        """

        for pol in policies:
            mList = pol.match

            fm = Tutorial.matchBuilder(mList)
            fm.match.dl_vlan = of.OFP_VLAN_NONE

            # corePort = str(coreSwitches[randint(0, (len(coreSwitches) - 1))])

            coreSwitch = coreSwitches[0]
            corePort = Discovery.getPort(int(switch), int(coreSwitch))
            if corePort is None:
                configHelper[2] = False
                return

            action = of.ofp_action_output(port = int(corePort))
            fm.actions.append(action)
            RulesTable.addRule(switch,mList,None,corePort)
            switchesConn[switch].send(fm)

    @staticmethod
    def installNFToRRules(switch):
        """
        Installs rules to ToR switches that have one or more NF
        connected to them
        """

        for pol in policies:
            mList = pol.match
            cList = pol.chain

            lastNFSwitch = services[cList[(len(cList) - 1)]][NF_DPID]
            if lastNFSwitch == switch:
                fm = Tutorial.matchBuilder(mList)
                fm.match.in_port = int(services[cList[(len(cList) - 1)]][NF_PORT])
                action = of.ofp_action_output(port = of.OFPP_CONTROLLER)
                fm.actions.append(action)
                RulesTable.addRule(switch,mList,"null","controller port",services[cList[(len(cList) - 1)]][NF_PORT])
                switchesConn[switch].send(fm)


            if len(cList) >= 2:
                for i in range(len(cList) - 1):
                    nfSwitch = services[cList[i]][NF_DPID]
                    if nfSwitch == switch:
                        nf2Switch = services[cList[(i + 1)]][NF_DPID]
                        if nf2Switch == switch:
                            fm = Tutorial.matchBuilder(mList)
                            nfPort = services[cList[i]][NF_PORT]
                            nfTag = services[cList[i]][NF_VLAN]
                            nf2Port = services[cList[(i + 1)]][NF_PORT]
                            fm.match.in_port = int(nfPort)
                            action = of.ofp_action_output(port = int(nf2Port))
                            fm.actions.append(action)
                            RulesTable.addRule(switch,mList,"null",nf2Port,nfPort)
                            switchesConn[switch].send(fm)
                        else:
                            fm = Tutorial.matchBuilder(mList)
                            nfPort = services[cList[i]][NF_PORT]


                            # corePort = str(coreSwitches[randint(0, (len(coreSwitches) - 1))])



                            coreSwitch = coreSwitches[0]
                            corePort = Discovery.getPort(int(switch), int(coreSwitch))
                            if corePort is None:
                                configHelper[2] = False
                                return

                            nfTag = services[cList[i]][NF_VLAN]
                            fm.match.in_port = int(nfPort)
                            action1 = of.ofp_action_vlan_vid(vlan_vid = int(nfTag))
                            action2 = of.ofp_action_output(port = int(corePort))
                            fm.actions.append(action1)
                            fm.actions.append(action2)
                            RulesTable.addRule(switch,mList,"null",corePort,nfPort,nfTag)
                            switchesConn[switch].send(fm)

        for pol2 in policies:
            mList = pol2.match
            cList = pol2.chain

            fm = Tutorial.matchBuilder(mList)


            # corePort = str(coreSwitches[randint(0, (len(coreSwitches) - 1))])

            if services[cList[0]][NF_DPID] != switch:
                coreSwitch = coreSwitches[0]
                corePort = Discovery.getPort(int(switch), int(coreSwitch))
                if corePort is None:
                    configHelper[2] = False
                    return

                fm.match.dl_vlan = of.OFP_VLAN_NONE
                action = of.ofp_action_output(port = int(corePort))
                fm.actions.append(action)
                RulesTable.addRule(switch,mList,None,corePort)
                switchesConn[switch].send(fm)

            for c in cList:
                nfSwitch = services[c][NF_DPID]
                cIndx = cList.index(c)
                if nfSwitch == switch:
                    if cIndx == 0 or (cIndx > 0 and services[cList[(cIndx - 1)]][NF_DPID] != switch):
                        if cIndx == 0:
                            allPorts = [int(p) for p in Discovery.graph.nodes[int(switch)].connection.ports]
                        else:
                            allPorts = Discovery.getPorts(int(switch))
                        for p in allPorts:
                            if p < of.OFPP_MAX and p != int(services[c][NF_PORT]):
                                fm = Tutorial.matchBuilder(mList)
                                fm.match.in_port = int(p)
                                nfPort = services[c][NF_PORT]
                                if cIndx == 0:
                                    fm.match.dl_vlan = of.OFP_VLAN_NONE
                                    RulesTable.addRule(switch,mList,None,nfPort,p)
                                else:
                                    fm.match.dl_vlan = services[cList[(cIndx - 1)]][NF_VLAN]
                                    RulesTable.addRule(switch,mList,services[cList[(cIndx - 1)]][NF_VLAN],nfPort,p)
                                action1 = of.ofp_action_vlan_vid()
                                action2 = of.ofp_action_output(port = int(nfPort))
                                fm.actions.append(action1)
                                fm.actions.append(action2)
                                switchesConn[switch].send(fm)


    @staticmethod
    def installPolicyDoneRule(switch):
        """
        Installs rules for packets that were successfully 
        """

        if int(switch) in range(100, 200):
            fm = of.ofp_flow_mod()
            fm.match.dl_vlan = VLAN_DONE
            action = of.ofp_action_output(port = of.OFPP_FLOOD)
            fm.actions.append(action)
            RulesTable.addRule(switch,"core flood to all ports",VLAN_DONE,"flood ports")
            switchesConn[switch].send(fm)
        else:
            fm = of.ofp_flow_mod()
            fm.match.dl_vlan = VLAN_DONE
            allPorts = [int(p) for p in Discovery.graph.nodes[int(switch)].connection.ports]
            corePorts = Discovery.getPorts(int(switch))
            hostPorts = list(set(allPorts) - set(corePorts))
            RulesTable.addRule(switch," TOR flood to all hosts ",VLAN_DONE,"all hosts ports")
            action = of.ofp_action_vlan_vid()
            fm.actions.append(action)
            for p in hostPorts:
                if p < of.OFPP_MAX:
                    action = of.ofp_action_output(port = p)
                    fm.actions.append(action)

            switchesConn[switch].send(fm)

    @staticmethod
    def matchBuilder(matchList):
        """
        Builds the match object of the flow rule according to the match list of the
        current policy
        """

        fm = of.ofp_flow_mod()
        for l in matchList:
            if l[0] == "in_port":
                fm.match.in_port = int(l[1])

            elif l[0] == "eth_src":
                fm.match.dl_src = EthAddr(l[1])

            elif l[0] == "eth_dst":
                fm.match.dl_dst = EthAddr(l[1])

            elif l[0] == "dl_vlan_pcp":
                fm.match.dl_vlan_pcp = int(l[1])

            elif l[0] == "eth_type":
                fm.match.dl_type = int(l[1], 16)

            elif l[0] == "nw_tos":
                fm.match.nw_tos = int(l[1])

            elif l[0] == "ip_proto" or l[0] == "arp_opcode":
                fm.match.nw_proto = int(l[1])

            elif l[0] == "ipv4_src":
                fm.match.nw_src = IPAddr(l[1])

            elif l[0] == "ipv4_dst":
                fm.match.nw_dst = IPAddr(l[1])

            elif l[0] == "tcp_src" or l[0] == "udp_src":
                fm.match.tp_src = int(l[1])

            elif l[0] == "tcp_dst" or l[0] == "udp_dst":
                fm.match.tp_dst = int(l[1])

        return fm

    @staticmethod
    def deleteAllRules():
        """
        Deletes all the rules for all switches in the network
        """

        for s in switchesConn:
            fm = of.ofp_flow_mod()
            fm.command = of.OFPFC_DELETE
            switchesConn[s].send(fm)

class Discovery:
    """
    This class is responsible for maintining the image of the network and dealing
    with loop issues, link failures, and any other stability concern.
    It makes sure the network remains stable, and that packets sent arrive at
    their destination successfully. It is responsible for keeping the elements
    of the network in tpuch, and running kruskal in order to find the minimum
    spanning tree when needed.
    """

    __metaclass__ = SingletonType

    LLDP_DST_ADDR = '\x01\x80\xc2\x00\x00\x0e'  # destination MAC address of LLDP packet. @see send_lldp_packet()
    LLDP_INTERVAL = 1      # interval for LLDP packet sending. @see send_lldp_packet() 
    switchTimers = {}      # Timer object for each switch used to send LLDP packets. @see send_lldp_packet()
    switchAddedPorts = {}  # contains the ports added by a switch before the connectionUp event. @see _handle_ConnectionUp()
    graph = Graph()        # Graph object of the network. @see Graph() in utils
    switchNodes = []

    def __init__(self):
        core.openflow.addListeners(self)

    def _handle_ConnectionUp(self, event):
        """
        Handles the event of connection up of the switch. 
        In other words, it is called when the switch turns
        on for the first time.
        """

        # adding missing ports as requested by the switch using _handle_PortStatus()
        if int(str(event.dpid)) in Discovery.switchAddedPorts:
            AdditionalPorts = Discovery.switchAddedPorts[int(str(event.dpid))]
            for port in AdditionalPorts:
                if port not in event.ofp.ports:
                    event.ofp.ports.append(port)

        # starting LLDP timer
        self.add_lldp_rule_to_flowtable(ethernet.LLDP_TYPE, Discovery.LLDP_DST_ADDR, of.OFPP_CONTROLLER, event)
        Discovery.switchTimers[int(str(event.dpid))] = Timer(Discovery.LLDP_INTERVAL, self.send_lldp_packet, [event], True)
        # adding switch to the network graph
        Discovery.graph.add_node(int(str(event.dpid)), event)
        Discovery.switchNodes.append(str(event.dpid))

    def _handle_ConnectionDown(self, event):
        """
        Handles the event of connection down of the switch.
        In other words, it is called when the switch turns off.
        """

        # stopping LLDP timer
        Discovery.switchTimers[int(str(event.dpid))].stop()
        # removing switch from network graph
        Discovery.graph.remove_node(int(str(event.dpid)))

        # deleting links connected to the switch, if any remained
        switchEdges = {}
        for edge in Discovery.graph.edges:
            switchEdges[edge] = Discovery.graph.edges[edge]

        for (u,v) in switchEdges:
            if u == int(str(event.dpid)) or v == int(str(event.dpid)):
                del Discovery.graph.edges[(u,v)]
        
        # clearing entries in global arrays if used by the switch
        if int(str(event.dpid)) in Discovery.switchAddedPorts:
            del Discovery.switchAddedPorts[int(str(event.dpid))]

    def _handle_PortStatus(self, event):
        """
        Handles the events of ports. Whether it is addition, or removal of
        one of the switch's ports.
        """
        
        # a port is deleted (i.e. the link is down)
        if event.ofp.desc.config == 1:
            edges = Discovery.graph.edges
            for (u, v) in edges:
                if (u == int(str(event.dpid)) and edges[(u,v)][0] == int(event.port)) or (v == int(str(event.dpid)) and edges[(u,v)][1] == int(event.port)):
                    edgeToRemove = Discovery.graph.get_edge(u, v)
                    port1 = str(edgeToRemove[0])
                    port2 = str(edgeToRemove[1])

                    log.debug("Removing existing link - (s" + str(u) + ", " + port1 + ")" + " <==> " +\
                              "(s" + str(v) + ", " + port2 + ")" + " -- Port Closed")
                    Discovery.graph.delete_edge(u, v)
                    return
        
        # a port is added (i.e. the switch is requesting to add a missing port)
        elif event.added:
            if int(str(event.dpid)) not in Discovery.switchAddedPorts:
                Discovery.switchAddedPorts[int(str(event.dpid))] = []
            
            if int(str(event.dpid)) in Discovery.graph.nodes:
                switchEvent = Discovery.graph.nodes[int(str(event.dpid))]
                if event.ofp.desc not in switchEvent.ofp.ports:
                    switchEvent.ofp.ports.append(event.ofp.desc)
            else:
                Discovery.switchAddedPorts[int(str(event.dpid))].append(event.ofp.desc)

    def _handle_PacketIn(self, event):
        """
        Handles packet in messages from the switch.
        """

        packet = event.parsed # Packet is the original L2 packet sent by the switch
        packet_in = event.ofp
        if not packet.parsed:
            log.warning("Ignoring incomplete packet")
            return

        # Ignore IPv6 discovery messages
        if "33:33:00:00:00:" in str(packet.dst):
            return

        # Ignore non LLDP packets
        if packet.type != ethernet.LLDP_TYPE:
            return

        if packet.type == ethernet.LLDP_TYPE:
            packet_in = event.ofp # packet_in is the OpenFlow packet sent by the switch
            recvSwitch = int(str(event.dpid))
            recvPort = packet_in.in_port
            lldp_p = packet.payload
            ch_id = lldp_p.tlvs[0]
            po_id = lldp_p.tlvs[1]
            r_dpid = int(ch_id.id)
            r_port = int(po_id.id)

            edge = Discovery.graph.get_edge(recvSwitch, r_dpid)
            if edge is None :
                self.addEdge(recvSwitch,r_dpid,[recvPort,r_port])

    def addEdge(self, u, v, edgeData):
        """
        Adds an edge to the graph of the network whenever such an edge is detected
        by receiving an LLDP from a neighbour switch in _handle_PacketIn()
        """

        log.debug("New link is found - (s" + str(u) + ", " + str(edgeData[0]) + ")" + " <==> " +\
                  "(s" + str(v) + ", " + str(edgeData[1]) + ")")
        Discovery.graph.add_edge(u,v,edgeData)

    def add_lldp_rule_to_flowtable(self, pktType, dstMac, outPort, event):
        """
        Defines the action of the flow mod, which is determining the output port,
        and then calling the method send_learning_flow_mod() in order to send
        the flow entry to the switch
        """

        action = of.ofp_action_output(port = outPort)

        # Use send_flow_mod_by_in_port to send an ofp_flow_mod to the switch with an output action
        # to flood the packet and any future packets that are similar to it
        self.send_lldp_flow_mod(pktType, dstMac, action, event)

    def send_lldp_flow_mod(self, pktType, dstMac, action, event):
        """
        Constructs the flow mod and applies the required matches as requested.
        These are: in_port, source MAC, and destination MAC
        Then it appends the action to forward the packet to the specified
        out_port using the action parameter received from the method
        add_learning_rule_to_flowtable().
        Finally, it sends the flow mod to the switch and by that
        installs the flow entry
        """

        fm = of.ofp_flow_mod()
        fm.match.dl_type = pktType
        fm.match.dl_dst = dstMac

        fm.actions.append(action)

        # Send message to switch
        event.connection.send(fm)

    def send_lldp_packet(self, event):
        """
        Sends LLDP packet to all neighbour switches by iterating over 
        the ports of the switch and sending the packet to each one
        apart from the controller. This function is called each second
        from each switch with the help of the Timer object set
        for each switch.

        Note: This function is an exact copy to the code given
        in Appendix B of the Exercise description.
        """

        dst = Discovery.LLDP_DST_ADDR       # == '\x01\x80\xc2\x00\x00\x0e'

        for p in event.ofp.ports:
            if p.port_no < of.OFPP_MAX:
                # Build LLDP packet
                src = str(p.hw_addr)
                port = p.port_no
                
                lldp_p = lldp() # create LLDP payload
                ch_id = chassis_id() # Add switch ID part
                ch_id.subtype = 1
                ch_id.id = str(event.dpid)
                lldp_p.add_tlv(ch_id)
                po_id = port_id() # Add port ID part
                po_id.subtype = 2
                po_id.id = str(port)
                lldp_p.add_tlv(po_id)
                tt = ttl() # Add TTL
                tt.ttl = Discovery.LLDP_INTERVAL # == 1
                lldp_p.add_tlv(tt)
                lldp_p.add_tlv(end_tlv())
                
                ether = ethernet() # Create an Ethernet packet
                ether.type = ethernet.LLDP_TYPE # Set its type to LLDP
                ether.src = src # Set src, dst
                ether.dst = dst
                ether.payload = lldp_p # Set payload to be the LLDP payload
                
                # send LLDP packet
                pkt = of.ofp_packet_out(action = of.ofp_action_output(port = port))
                pkt.data = ether
                event.connection.send(pkt)

    @staticmethod
    def getPorts(switchID):
        """
        Retreives all of the ports of the switch with the given
        switchID from the given dictionary of edges, and returns
        the list of ports found.
        """

        dictionary = Discovery.graph.edges
        result = []
        for (x , y) in dictionary:
            if x == switchID:
                result.append(int(dictionary[(x,y)][0]))
            elif y == switchID:
                result.append(int(dictionary[(x,y)][1]))
        return result

    @staticmethod
    def getPort(switchID1, switchID2):
        """
        Returns the port that connects switchID1
        with switchID2.
        """

        dictionary = Discovery.graph.edges
        for (x , y) in dictionary:
            if x == switchID1 and y == switchID2:
                return dictionary[(x,y)][0]
            elif y == switchID1 and x == switchID2: 
                return dictionary[(x,y)][1]
        return None



class Policy:
    """
    Represents a policy from the configurations file.
    Has two fields: match list, and chain list.
    """

    def __init__(self, matchList, chainList):
        self.match = matchList
        self.chain = chainList

class RulesTable:
    """
    Represents the table of all rules installed on the switches
    of the network. Used in order to get a clear image of the 
    behavior of the switches, and to see what rules are
    installed on each switch.
    """

    rules = {}
    class Rule:
        """
        Represents a single rule installed on a switch in the network.
        """

        def __init__(self,mList,vlan,outputPort,inPort=None,newVlan=None):
            self.mList = mList
            self.vlan = vlan
            self.inPort = inPort
            self.outputPort = outputPort
            self.newVlan = newVlan

        def __str__(self):
            result = "matchList is "+str(self.mList)
            result+="\n"
            if self.vlan!="null":
                result =result+"VLAN = "+str(self.vlan)
            if self.inPort !=None:
                result=result+"\ninPort = "+str(self.inPort)
            result+="\n---------------action---------"
            result+="\noutput port = "+str(self.outputPort)
            if self.newVlan != None:
                result = result+"\nchange vlan to newVlan = "+str(self.newVlan)
            return result+"\n---------------end action---------\n\n"

    
    @staticmethod
    def addRule(switch,mList,vlan,outputPort,inPort=None,newVlan=None):
        """
        adds a rule to the RulesTable of the given switch
        """
           
        r = RulesTable.Rule(mList,vlan,outputPort,inPort,newVlan)
        ind=RulesTable.rules.get(int(switch))
        if(ind ==None):
            RulesTable.rules[int(switch)]=[r]
        else:
            ind.append(r)

    def __str__(self):
        result = "\n\n****************************************** Rules Report ******************************************\n"
        for s in RulesTable.rules:
            result+="\n$$$$$$$$$$$$$$$$$$$ Switch rules s = "+str(s)+" $$$$$$$$$$$$$$$$$$$\n\n"
            for rule in RulesTable.rules[s]:
                result +=str(rule)
            result+="\n$$$$$$$$$$$$$$$$$$$ End switch rules $$$$$$$$$$$$$$$$$$$\n"
        RulesTable.rules = {}
        return result+"\n****************************************** end Rules Report ******************************************\n"



def launch ():
    """
    Starts the component
    """

    [serv, pol] = parseConfigFile()

    for i in serv:
        services[i] = serv[i]

    for j in pol:
        policies.append(j)


    def start_switch (event):
        log.debug("Controlling %s" % (event.connection,))
        Tutorial(event.connection)

    core.openflow.addListenerByName("ConnectionUp", start_switch)
    core.register("discovery", Discovery())


def parseConfigFile():
    """
    Reads the policies configuration file.
    extracts and returns the services alongside the policies from it
    """

    f = open(CONFIG_FILENAME, "r")

    services = {}
    policies = []
    vlanCounter = 2
    line = f.readline()
    line = line.strip().replace("\n","")
    while line != '':
        temp = line.split(" ")
        if temp[0].strip() == "service":
            line = line.replace("service","")
            line = line.strip()
            temp2 = line.split(" ")
            services[temp2[0].strip()]=[False,line.replace(temp2[0],"").strip(), vlanCounter]
            vlanCounter += 1
        else:
            line = line.replace("policy","").strip()
            line = line.replace("match","").strip()
            temp2 = line.split("chain")
            policyMatchList = []
            firstPart = temp2[0].strip().split(",")
            for i in firstPart:
                i = i.replace("[","").strip()
                i = i.replace("]","").strip()
                policyMatchList.append([j.strip() for j in i.split("=")])


            chain  = temp2[1].strip().replace("[","").replace("]","").strip().split(",")
            chainList = [j.strip() for j in chain]
            # log.debug("pol Match: " + str(policyMatchList) + "   pol Chain: " + str(chainList))
            policyObj = Policy(policyMatchList, chainList)
            policies.append(policyObj)
        line = f.readline()

    global VLAN_SPECIAL
    VLAN_SPECIAL = vlanCounter + 1

    f.close()

    # log.debug("services:  " + str(services))

    return [services, policies]