from operator import attrgetter
from ryu.app import simple_switch_13
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
from ryu.lib.packet import packet_base
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp
import math
import scipy.stats

class DetectionEntropy(simple_switch_13.SimpleSwitch13, packet_base.PacketBase):

    def __init__(self, tcp, ipv4, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)
        self.tcp_packets = tcp.tcp(bits=(tcp.TCP_SYN & tcp.TCP_ACK))
        self.logger.info(self.tcp_packets.has_flags(tcp.TCP_SYN, tcp.TCP_ACK))

    @set_ev_cls(ofp_event.EventOFPStateChange,[MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                #self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                #self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]

    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(10)

    def _request_stats(self, datapath):
        #self.logger.debug('send stats request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)


    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body
        self.count = 0
        self.byte = []
        self.byte_count_constant = 1000 # for example
        self.packet_count_constant = 500  # for example
        for stat in sorted([flow for flow in body if flow.priority == 1],
                            key=lambda flow: (flow.match['in_port'],
                            flow.match['eth_dst'])):
                            self.cache = stat

        self.byte_count = stat.byte_count
        self.packet_count = stat.packet_count
        if(self.byte_count > self.byte_count_constant and self.packet_count > self.packet_count_constant):
            self.destination = stat.match['eth_dst']
            self.in_port = stat.match['in_port']
            self.destination_id = ev.msg.datapath.id
        self.logger.info("______________________________Ethernet dst victim_________________________________________________")
        self.logger.info(ds)
        self.logger.info("______________________________Ethernet dst Attacker_______________________________________________")
        print ('DPID    :',self.destination_id)
        print ('IN_PORT :',self.in_port)
        self.logger.info("__________________________________________ Byte count so far______________________________________")
        byte.append(stat.byte_count)
        self.logger.info(byte)
        self.logger.info("_________________________________________No of bytes in each host_________________________________")
        self.logger.info(byte[-1])
        b1=byte[-1]
        self.logger.info(byte[-2])
        b2=byte[-2]
        self.logger.info("_________________________________________________N value__________________________________________")
        N=b1+b2
        self.logger.info(N)
        self.logger.info("_____________________________________________Entropy Ratio________________________________________")
        self.bytes_in_each_port = [b1, b2]
        self.entropy = scipy.stats.entropy(self.bytes_in_each_port)
        self.logger.info(self.entropy)
        pkt = tcp.tcp(bits=(tcp.TCP_SYN & tcp.TCP_ACK))
        self.logger.info(pkt.has_flags(tcp.TCP_SYN, tcp.TCP_ACK))
        if (pkt!="True"):
            self.count = self.count + 1
        self.logger.info(count)
