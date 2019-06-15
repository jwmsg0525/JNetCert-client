from scapy.all import *
import json
import netifaces 
import datetime

from src import reqnet
from src import logger

class ProUtil:
    def __init__(self):
        self.initFile = open('./config/init.json').read()
        self.initData = json.loads(self.initFile)
        
        self.serverIP = self.initData['server']['IP']
        self.serverPort = self.initData['server']['PORT']
        self.logpath = self.initData['config']['LogPath']

        self.reqNet = reqnet.ReqNet(self.serverIP,self.serverPort)
        self.ruleData = self.getRule()

        self.logger = logger.Logger(self.logpath)
        
    def getInit(self):
        return self.initData
    
    def getMode(self):
        return self.ruleData['mode']
    
    def getMyIp(self):
        return netifaces.ifaddresses(self.initData['system']['NetInterFace'])[netifaces.AF_INET][0]['addr']
    
    def getDetMode(self):
        if self.getMode() == 'blacklist':
            return 'Deny'
        return 'Allow'

    def getServerIp(self):
        return self.initData['server']['IP']
    def getServerPort(self):
        return self.initData['server']['PORT']

    def getRule(self):
        return self.reqNet.getRuleJSON()

    def getIpProto(self,pkt):
        proto_field = pkt[IP].get_field('proto')
        return proto_field.i2s[pkt[IP].proto].upper()
        
    def getDataRow(self,pkt):
        rtnRow = {"type":"UNKNOWN","time":datetime.now().strftime("%Y-%m-%dT%H:%M:%S.%fZ%Z")}

        if pkt.haslayer(Ether):
            rtnRow['dmac'] = pkt[Ether].dst
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
            rtnRow['sport'] = pkt[UDP].sport
        if pkt.haslayer(ARP):
            rtnRow['hwsrc'] = pkt[ARP].hwsrc
            rtnRow['hwdst'] = pkt[ARP].hwdst
            rtnRow['psrc'] = pkt[ARP].psrc
            rtnRow['pdst'] = pkt[ARP].pdst
            rtnRow['type'] = "ARP"
        return rtnRow

    def isDetact(self,pkt):
        self.logger.writeLog(pkt)
        self.reqNet.upPacket(pkt)
