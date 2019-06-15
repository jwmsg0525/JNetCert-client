from scapy.all import *
from src import rules 
from src import proutil

class PortFilter:
    def __init__(self,rule):
        self.rule = rule
        self.rule.setLayers()
        self.prou = proutil.ProUtil()
        self.layers = self.rule.getLayers()
        self.detMode = self.prou.getDetMode()
        conf.color_theme = BrightTheme()
    def detact(self,status,pkt):
        if status and self.detMode == 'Deny':
            self.prou.isDetact(pkt)
            return True
        elif status == False and self.detMode == 'Allow':
            self.prou.isDetact(pkt)
            return True
        return False

    def getIpProto(self,pkt):
        proto_field = pkt[IP].get_field('proto')
        return proto_field.i2s[pkt[IP].proto].upper()

    def capture_callback(self,pkt):
        if IP in pkt and self.getIpProto(pkt) in self.layers:
            trueflag = 0
            for IDX in self.rule.searchProtoIDX(self.getIpProto(pkt)):
                if(self.rule.detact(IDX,pkt)):
                    self.detact(True,pkt)
                    return
        self.detact(False,pkt)

    def start_sniff(self):
        sniff(prn=self.capture_callback)
