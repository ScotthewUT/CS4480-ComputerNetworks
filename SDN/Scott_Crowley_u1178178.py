# Scott Crowley (u1178178)
# CS4480 - PA 2: Software Difined Networking
# 26 March 2020

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib.mac import haddr_to_int
from ryu.lib.packet import arp
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import ipv4
from ryu.lib.packet import packet
from ryu.ofproto import ofproto_v1_3

class SimpleSwitch13(app_manager.RyuApp):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    VIRTUAL_IP = '10.0.0.10'
    H5_IP = '10.0.0.5'
    H5_MAC = '00:00:00:00:00:05'
    H5_PORT = 5
    H6_IP = '10.0.0.6'
    H6_MAC = '00:00:00:00:00:06'
    H6_PORT = 6
    selector = 5


    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}


    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)


    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id, priority=priority, match=match, instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst)

        datapath.send_msg(mod)


    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        dst_mac = eth.dst
        src_mac = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.mac_to_port[dpid][src_mac] = in_port
        if dst_mac in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst_mac]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst_mac, eth_src=src_mac)
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 10, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 10, match, actions)

        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            header = pkt.get_protocol(arp.arp)
            if header.dst_ip == self.VIRTUAL_IP and header.opcode == arp.ARP_REQUEST:
                reply = self.arp_reply(header.src_ip, header.src_mac)
                actions = [parser.OFPActionOutput(in_port)]
                packet_out = parser.OFPPacketOut(datapath=datapath, in_port=ofproto.OFPP_ANY, data=reply.data, actions=actions, buffer_id=0xffffffff)
                datapath.send_msg(packet_out)
                return

        if eth.ethertype == ether_types.ETH_TYPE_IP:
            ip_header = pkt.get_protocol(ipv4.ipv4)
            success = self.route_ip_packet(datapath, in_port, ip_header, parser, dst_mac, src_mac)
            if success:
                return

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    
    def arp_reply(self, dst_ip, dst_mac):
        target_ip = dst_ip
        target_mac = dst_mac
        src_ip = self.VIRTUAL_IP

        if self.selector == 5:
            src_mac = self.H5_MAC
            self.selector = 6
        else:
            src_mac = self.H6_MAC
            self.selector = 5

        pkt = packet.Packet()
        pkt.add_protocol(ethernet.ethernet(dst=dst_mac, src=src_mac, ethertype=ether_types.ETH_TYPE_ARP))
        pkt.add_protocol(arp.arp(opcode=arp.ARP_REPLY, src_mac=src_mac, src_ip=src_ip, dst_mac=target_mac, dst_ip=target_ip))
        pkt.serialize()
        return pkt


    def route_ip_packet(self, datapath, in_port, ip_header, parser, dst_mac, src_mac):
        success = False

        if ip_header.dst == self.VIRTUAL_IP:
            if dst_mac == self.H5_MAC:
                server_dst_ip = self.H5_IP
                server_out_port = self.H5_PORT
            else:
                server_dst_ip = self.H6_IP
                server_out_port = self.H6_PORT

            match = parser.OFPMatch(in_port=in_port, eth_type=ether_types.ETH_TYPE_IP, ip_proto=ip_header.proto, ipv4_dst=self.VIRTUAL_IP)
            actions = [parser.OFPActionSetField(ipv4_dst=server_dst_ip), parser.OFPActionOutput(server_out_port)]
            self.add_flow(datapath, 20, match, actions)

            match = parser.OFPMatch(in_port=server_out_port, eth_type=ether_types.ETH_TYPE_IP, ip_proto=ip_header.proto, ipv4_src=server_dst_ip, eth_dst=src_mac)
            actions = [parser.OFPActionSetField(ipv4_src=self.VIRTUAL_IP), parser.OFPActionOutput(in_port)]
            self.add_flow(datapath, 20, match, actions)

            success = True

        return success

