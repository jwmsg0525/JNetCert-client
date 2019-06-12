from scapy.all import *
from src import rules 
from src import proutil

class PortFilter:
    def __init__(self,rule):
        self.rule = rule
        self.rule.setLayers()
        self.layers = self.rule.getLayers()
        self.detField = proutil.ProUtil().getDetField()
        conf.color_theme = BrightTheme()
    def detact(self,status,pkt):
        if status and self.detField == 'Deny':
            pkt.show()
            return True
        elif status == False and self.detField == 'Allow':
            pkt.show()
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

