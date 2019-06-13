from src import proutil
import datetime
from scapy.all import *


class Logger():
    
    def __init__(self):
        self.prou = proutil.ProUtil()
        self.logpath = self.prou.getInit()['confing']['LogPath']
        self.logFile = open(self.logpath,'a')
    def writeLog(self,pkt):
        dataRow = self.getDataRow(pkt)
        self.logFile.write(str(dataRow)+"\n")
        self.lofFile.write("payload:\n"+str(pkt)+"\n\n")

    def getIpProto(self,pkt):
        proto_field = pkt[IP].get_field('proto')
        return proto_field.i2s[pkt[IP].proto].upper()


    def getDataRow(self,pkt):
        dmac = ""
        smac = ""
        dip = ""
        sip = ""
        dport = ""
        sport = ""
        ptype = "UNKNOWN"
        hwsrc = ""
        hwdst = ""
        psrc = ""
        pdst = ""
        rtnRow = {}

        if pkt.haslayer(Ether):
            rtnRow['dmac'] = pkt[Ehter].dst
            rtnRow['smac'] = pkt[Ether].src
        if pkt.haslayer(IP):
            rtnRow['dip'] = pkt[IP].dst
            rtnRow['sip'] = pkt[IP].src
            rtnRow['type'] = self.getIpProto(pkt)
        if pkt.haslayer(TCP):
            rtnRow['dport'] = pkt[TCP].dport
            rtnRow['sport'] = pkt[TCP].sport
        if pkt.haslayer(UDP):
            rtnRow['dport'] = pkt[UDP].dport
            rtbRow['sport'] = pkt[UDP].sport
        if pkt.haslayer(ARP):
            rtnRow['hwsrc'] = pkt[ARP].hwsrc
            rtnRow['hwdst'] = pkt[ARP].hwdst
            rtnRow['psrc'] = pkt[ARP].psrc
            rtnRow['pdst'] = pkt[ARP].pdst
            rtnRow['type'] = "ARP"
        return rtnRow
