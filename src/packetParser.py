from scapy.all import *


def getIpProto(pkt):
    proto_field = pkt[IP].get_field('proto')
    return proto_field.i2s[pkt[IP].proto].upper()

def getDataRow(pkt):
    rtnRow = {"type":"UNKNOWN","time":datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")}

    if pkt.haslayer(Ether):
        rtnRow['dmac'] = pkt[Ether].dst
        rtnRow['smac'] = pkt[Ether].src
    if pkt.haslayer(IP):
        rtnRow['dip'] = pkt[IP].dst
        rtnRow['sip'] = pkt[IP].src
        rtnRow['type'] = getIpProto(pkt)
    if pkt.haslayer(TCP):
        rtnRow['dport'] = pkt[TCP].dport
        rtnRow['sport'] = pkt[TCP].sport
    if pkt.haslayer(UDP):
        rtnRow['dport'] = pkt[UDP].dport
        rtnRow['sport'] = pkt[UDP].sport
    if pkt.haslayer(ARP):
        rtnRow['hwsrc'] = pkt[ARP].hwsrc
        rtnRow['hwdst'] = pkt[ARP].hwdst
        rtnRow['psrc'] = pkt[ARP].psrc
        rtnRow['pdst'] = pkt[ARP].pdst
        rtnRow['type'] = "ARP"
    return rtnRow

