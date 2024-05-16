from ryu.ofproto import ofproto_v1_3_parser
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types,tcp,ipv4
import datetime
import time
#import tabulate 
from ryu.base import app_manager

startCommStruct = []
endCommStruct = []
timeStruct = []

#Durata=[]
#Connessioni=[]
def write_to_file(text):
    with open("sdn-labs/progetto/BURSTT/output.txt","a") as file:
        file.write(text+"\n")

# This implements a learning switch in the controller
# The switch sends all packets to the controller
# The controller implements the MAC table using a python dictionary
# If the MAC dst is known, add rule to the switch
class PsrSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(PsrSwitch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

    # execute at switch registration
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        self.mac_to_port[datapath.id] = {}

        match = parser.OFPMatch()
        actions = [
            parser.OFPActionOutput(
                ofproto.OFPP_CONTROLLER,
                ofproto.OFPCML_NO_BUFFER
            )
        ]
        inst = [
            parser.OFPInstructionActions(
                ofproto.OFPIT_APPLY_ACTIONS,
                actions
            )
        ]
        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=1,
            match=match,
            instructions=inst
        )
        datapath.send_msg(mod)


    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        dpid = datapath.id
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)


        assert eth is not None

        dst = eth.dst
        src = eth.src

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

#        self.logger.info("packet in %s %s %s %s %s", dpid, src, dst, in_port, out_port)

        actions = [
            parser.OFPActionOutput(out_port)
        ]

        assert msg.buffer_id == ofproto.OFP_NO_BUFFER

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=msg.data
        )
        datapath.send_msg(out)
        ip = pkt.get_protocol(ipv4.ipv4)
        tcp_header=pkt.get_protocol(tcp.tcp)


        if ip and tcp_header:

            #startTimeStruc.append((tcp_header.src_port,tcp_header.dst_port,ip.src,ip.dst))
            #dst_port=tcp_header.dst_port
            #src_ip = ip.src
            #dst_ip = ip.dst

            if tcp_header.has_flags(tcp.TCP_SYN) and not tcp_header.has_flags(tcp.TCP_ACK):
                self.logger.info("SYN packet detected")
                temp_init=int(time.time()*1000) #ms tempo di inizio connessione
                
                isAlreadyRegister = 0
                for start in range(len(startCommStruct)):
                    if startCommStruct[start][0] == tcp_header.src_port and startCommStruct[start][1] == tcp_header.dst_port and startCommStruct[start][2] == ip.src and startCommStruct[start][3] == ip.dst:
                        isAlreadyRegister = 1

                if isAlreadyRegister == 0:        
                    startCommStruct.append([tcp_header.src_port,tcp_header.dst_port,ip.src,ip.dst,temp_init])
                #if len(init_array)>1:
                    #between_connections=int(init_array[-1])-int(init_array[-2])
                    #global lista
                    #lista.append(str(between_connections))
                    #print('Tempo tra connessioni:ms',between_connections)
                    #t = [int(i) for i in lista]
                    #if len(t)>5:
                    #    t=t[-5:]
                    #t_connection_mean=sum(t)/len(t)
                    #Durata.rows=Durata.rows.append([between_connections,t_connection_mean])
                    #Durata.table=tabulate(Durata.rows,Durata_h,tablefmt="simple")
                    #write_to_file(Durata.table)
                    #write_to_file("Tempo tra connessioni medio:ms %d" %t_connection_mean)
                    #print("Tempo tra connessioni medio: ms",t_connection_mean
                    #write_to_file("Tempo tra connessioni:ms %d" %between_connections)

            # if the output port is not FLOODING
            # install a new flow rule *for the next packets*
            #if out_port != ofproto.OFPP_FLOOD:
                # install a new flow rule
                    match = parser.OFPMatch(
                        eth_type=0x0800,  # IPv4
                        ip_proto=6,
                        ipv4_src=startCommStruct[len(startCommStruct)-1][2],
                        ipv4_dst=startCommStruct[len(startCommStruct)-1][3],
                        tcp_src=startCommStruct[len(startCommStruct)-1][0],
                        tcp_dst=startCommStruct[len(startCommStruct)-1][1]
                    )
                    self.add_flow(datapath, 10, match, actions)

                    match = parser.OFPMatch(
                        eth_type=0x0800,  # IPv4
                        ip_proto=6,
                        ipv4_src=startCommStruct[len(startCommStruct)-1][3],
                        ipv4_dst=startCommStruct[len(startCommStruct)-1][2],
                        tcp_src=startCommStruct[len(startCommStruct)-1][1],
                        tcp_dst=startCommStruct[len(startCommStruct)-1][0]
                    )
                    self.add_flow(datapath, 10, match, actions)





    def add_flow(self, datapath, priority, match, actions):
        print("nuova regola")
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions)]
        flags=ofproto.OFPFF_SEND_FLOW_REM
        ofmsg = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            flags=flags,
            match=match,
            idle_timeout=3,
            instructions=inst,
        )
        datapath.send_msg(ofmsg)

    
                 
    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def flow_removed_handler(self, ev):
        global t_connection_array
        timeout=3000
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto
        parser = ofproto_v1_3_parser
        fields_json = parser.OFPMatch.to_jsondict(ev.msg.match)["OFPMatch"]["oxm_fields"]
        print("Flow Removed: ")
        if msg.reason == ofp.OFPRR_IDLE_TIMEOUT:
            print("idle timeout")
            temp=int(time.time()*1000) #ms
            #Find the way to know witch rule has been removed
            endCommStruct.append([fields_json[4]["OXMTlv"]["value"], fields_json[5]["OXMTlv"]["value"], fields_json[1]["OXMTlv"]["value"] , fields_json[2]["OXMTlv"]["value"] ,temp,0])
            for start in range(len(startCommStruct)):
                for end in range(len(endCommStruct)):
                    if startCommStruct[start][0] == endCommStruct[end][0] and startCommStruct[start][1] == endCommStruct[end][1] and startCommStruct[start][2] == endCommStruct[end][2] and startCommStruct[start][3] == endCommStruct[end][3]:
                        notPresent = 1
                        for oldConnection in range(len(timeStruct)):
                            if timeStruct[oldConnection][0] == startCommStruct[start][2] and timeStruct[oldConnection][1] == startCommStruct[start][3]:
                                timeStruct[oldConnection][2] = (timeStruct[oldConnection][2] + (endCommStruct[end][4] - startCommStruct[start][4] - 3000))/ 2;
                                timeStruct[oldConnection][3].append(endCommStruct[end][4] - startCommStruct[start][4] - 3000);
                                startCommStruct.pop(start)
                                endCommStruct.pop(end)
                                notPresent = 0
                                end = end + 1
                                start = start + 1
                                break
                        if notPresent == 1:
                            timeStruct.append([startCommStruct[start][2],startCommStruct[start][3], endCommStruct[end][4] - startCommStruct[start][4] - 3000, [endCommStruct[end][4] - startCommStruct[start][4]-3000]])
                        else:
                            break
       
            print(timeStruct)
            #t_connection=temp-int(init_array[-1])-timeout
            #t_connection_array.append(str(t_connection))
            #t = [int(i) for i in t_connection_array]
            #t_connection_mean=sum(t)/len(t)
            #write_to_file("Durata media:ms %d" %t_connection_mean)
            #print("Durata media: ms",t_connection_mean)
            #print("Durata:ms",t_connection)
            #write_to_file("Durata:ms %d" %t_con
