from operator import attrgetter
from ryu.app import simple_switch_13
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
from ryu.lib.packet import packet_base
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp


byte=[]

class SimpleMonitor13(simple_switch_13.SimpleSwitch13,packet_base.PacketBase):

    def __init__(self, *args, **kwargs):
        super(SimpleMonitor13, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)
	pkt = tcp.tcp(bits=(tcp.TCP_SYN & tcp.TCP_ACK))
	print(pkt.has_flags(tcp.TCP_SYN, tcp.TCP_ACK))






    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
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
	count=0

        #self.logger.info('datapath         '
         #                'in-port  eth-dst           '
           #              'out-port packets  bytes')
        #self.logger.info('---------------- '
         #                '-------- ----------------- '
          #               '-------- -------- --------')
        for stat in sorted([flow for flow in body if flow.priority == 1],
                           key=lambda flow: (flow.match['in_port'],
                                             flow.match['eth_dst'])):

            #self.logger.info('%016x %8x %17s %8x %8d %8d',
             #                ev.msg.datapath.id,
              #               stat.match['in_port'], stat.match['eth_dst'],
               #              stat.instructions[0].actions[0].port,
                #             stat.packet_count,stat.byte_count)
	    global byte
	    K=1000
	    C=500
	    AC=stat.byte_count
	    count=stat.packet_count
	    if(AC>K and count>C):
		ds=[]
		ds=stat.match['eth_dst']
		in_port=stat.match['in_port']
		d_id=ev.msg.datapath.id
		#import ethip
		print("______________________________Ethernet dst victim_________________________________________________")
		print(ds)
		''''global eth
		if eth.ethertype == ether_types.ETH_TYPE_IP:
                	ip = pkt.get_protocol(ipv4.ipv4)
                	#srcip = ip.src
                	dstip = ip.dst
                	match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                       	                 ipv4_src=srcip,

                         	               )
		print(match)'''
		#print(ip)
		print("______________________________Ethernet dst Attacker_______________________________________________")
		print 'DPID    :',d_id
		print 'IN_PORT :',in_port



	    import math
	    print("__________________________________________ Byte count so far______________________________________")
	    byte.append(stat.byte_count)
	    print(byte)

	    print("_________________________________________No of bytes in each host_________________________________")
	    print(byte[-1])
	    b1=byte[-1]
	    print(byte[-2])
	    b2=byte[-2]
	    print("_________________________________________________N value__________________________________________")
            #N=float(b1)+float(b2)
	    N=b1+b2
	    print(N)
	    print("_____________________________________________Entropy Ratio________________________________________")
	    p1=float(b1)/N*(math.log(float(b1),2)/N)
	    p2=float(b2)/N*(math.log(float(b2),2)/N)
	    print(abs(p1-p2))
	    ent=abs(p1-p2)
	    pkt = tcp.tcp(bits=(tcp.TCP_SYN & tcp.TCP_ACK))
	    print(pkt.has_flags(tcp.TCP_SYN, tcp.TCP_ACK))
	    if (pkt!="True"):
		count=count+1
		print(count)
	    #print(1-p*(abs(math.log(p,2))))
	    #p1=1-p*(abs(math.log(p,2)))
    	    #print(p1/math.log(2,2))
