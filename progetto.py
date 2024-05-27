from ryu.ofproto import ofproto_v1_3_parser
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types,tcp,ipv4
import datetime
import time
from ryu.base import app_manager

startCommStruct = []
endCommStruct = []
timeStruct = []
between_connections=[]
first_packet = 0
second_packet = 0

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

        actions = [
            parser.OFPActionOutput(out_port)
        ]
        actions_2 = [
            parser.OFPActionOutput(in_port)
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
            
            if tcp_header.has_flags(tcp.TCP_SYN) and not tcp_header.has_flags(tcp.TCP_ACK):
                temp_init=int(time.time()*1000) #ms tempo di inizio connessione
                
                isAlreadyRegister = 0
                global between_connections
                
                for start in range(len(startCommStruct)):
                    
                    if startCommStruct[start][0] == tcp_header.src_port and startCommStruct[start][1] == tcp_header.dst_port and startCommStruct[start][2] == ip.src and startCommStruct[start][3] == ip.dst:
                        isAlreadyRegister = 1
                
               
                if isAlreadyRegister == 0:        
                    startCommStruct.append([tcp_header.src_port,tcp_header.dst_port,ip.src,ip.dst,temp_init])
                    global first_packet
                    second_packet = first_packet
                    first_packet = temp_init
                    match = parser.OFPMatch(
                        eth_type=0x0800,  # IPv4
                        ip_proto=6, #TCP
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
                    self.add_flow(datapath, 10, match, actions_2)


                if len(between_connections) == 0:
                    between_connections.append([ip.src, ip.dst, 0, 0, temp_init])
                else:
                    time_btw_found = 0
                    for btw_con in range(len(between_connections)):
                        if ip.src == between_connections[btw_con][0] and ip.dst == between_connections[btw_con][1]:
                            if between_connections[btw_con][2] == 0:
                                between_connections[btw_con][2] = temp_init - between_connections[btw_con][4]
                                between_connections[btw_con][3] = temp_init - between_connections[btw_con][4]
                                between_connections[btw_con][4] = temp_init
                            else:
                                between_connections[btw_con][2] = (between_connections[btw_con][2] + temp_init - between_connections[btw_con][4]) / 2 
                                between_connections[btw_con][3] = temp_init - between_connections[btw_con][4]
                                between_connections[btw_con][4] = temp_init
                            
                            print('Tempo tra connessioni di \033[38;5;11m\033[49m'+ str(between_connections[btw_con][0]) + ' --> '+ str(between_connections[btw_con][1]) + '\033[39m\033[49m : \033[38;5;10m\033[49m' + str(between_connections[btw_con][3]) + ' \033[39m\033[49m ms' )
                            print('Tempo medio tra connessioni di \033[38;5;11m\033[49m'+ str(between_connections[btw_con][0]) + ' --> '+ str(between_connections[btw_con][1]) + '\033[39m\033[49m :\033[38;5;10m\033[49m ' + str(between_connections[btw_con][2]) + ' \033[39m\033[49m ms' )
                            time_btw_found = 1
                            break
                    
                    if time_btw_found == 0:
                        between_connections.append([ip.src, ip.dst, 0, 0, temp_init])
                    





    def add_flow(self, datapath, priority, match, actions):
        print("Nuova regola")
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,actions)]
        flags=ofproto.OFPFF_SEND_FLOW_REM
        ofmsg = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            flags=flags,
            match=match,
            idle_timeout=5,
            instructions=inst,
        )
        datapath.send_msg(ofmsg)

    
                 
    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def flow_removed_handler(self, ev):
        global t_connection_array
        timeout=5000
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto
        parser = ofproto_v1_3_parser
        fields_json = parser.OFPMatch.to_jsondict(ev.msg.match)["OFPMatch"]["oxm_fields"]
        if msg.reason == ofp.OFPRR_IDLE_TIMEOUT:
            print("Idle timeout received")
            temp=int(time.time()*1000) #ms
            global endCommStruct
            global second_packet
            global timeStruct
            notPresent = 1
            endCommStruct.append([fields_json[4]["OXMTlv"]["value"], fields_json[5]["OXMTlv"]["value"], fields_json[2]["OXMTlv"]["value"] , fields_json[3]["OXMTlv"]["value"] ,temp,0])
            for start in range(len(startCommStruct)):
                for end in range(len(endCommStruct)):
                        if startCommStruct[start][0] == endCommStruct[end][0] and startCommStruct[start][1] == endCommStruct[end][1] and startCommStruct[start][2] == endCommStruct[end][2] and startCommStruct[start][3] == endCommStruct[end][3]:
                            notPresent = 1
                            for oldConnection in range(len(timeStruct)):
                                if timeStruct[oldConnection][0] == startCommStruct[start][2] and timeStruct[oldConnection][1] == startCommStruct[start][3]:
                                    timeStruct[oldConnection][2] = (timeStruct[oldConnection][2] + (endCommStruct[end][4] - startCommStruct[start][4] - timeout))/ 2;
                                    timeStruct[oldConnection][3].append(endCommStruct[end][4] - startCommStruct[start][4] - timeout);
                                    print('Durata connessione tra \033[38;5;11m\033[49m'+ str(timeStruct[oldConnection][0]) + '\033[39m\033[49m e \033[38;5;11m\033[49m' + str(timeStruct[oldConnection][1]) + '\033[39m\033[49m : \033[38;5;10m\033[49m' + str(timeStruct[oldConnection][3][len(timeStruct[oldConnection][3])-1])+ '\033[39m\033[49m')
                                    print('Durata media connessione tra \033[38;5;11m\033[49m'+ str(timeStruct[oldConnection][0]) + '\033[39m\033[49m e \033[38;5;11m\033[49m' + str(timeStruct[oldConnection][1]) + '\033[39m\033[49m : \033[38;5;10m\033[49m' + str(timeStruct[oldConnection][2])+'\033[39m\033[49m')

                                    startCommStruct.pop(start)
                                    endCommStruct.pop(end)
                                    notPresent = 0
                                    break
                            if notPresent == 1:
                                timeStruct.append([startCommStruct[start][2],startCommStruct[start][3], endCommStruct[end][4] - startCommStruct[start][4] - timeout , [endCommStruct[end][4] - startCommStruct[start][4]-timeout]])
                                if len(timeStruct)!=2:
                                    print('Durata connessione tra \033[38;5;11m\033[49m'+ str(timeStruct[len(timeStruct)-1][0]) + ' \033[39m\033[49m e \033[38;5;11m\033[49m' + str(timeStruct[len(timeStruct)-1][1]) + ' \033[39m\033[49m: \033[38;5;10m\033[49m' + str(timeStruct[len(timeStruct)-1][3][len(timeStruct[len(timeStruct)-1][3])-1]) + '\033[39m\033[49m')
                                    print('Durata media connessione tra \033[38;5;11m\033[49m'+ str(timeStruct[len(timeStruct)-1][0]) + '\033[39m\033[49m e \033[38;5;11m\033[49m' + str(timeStruct[len(timeStruct)-1][1]) + '\033[39m\033[49m : \033[38;5;10m\033[49m' + str(timeStruct[len(timeStruct)-1][2])+ '\033[39m\033[49m')

                            else:
                                break
                 
                if notPresent == 0:
                    break
