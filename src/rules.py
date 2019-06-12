import json
from scapy.all import *
import netifaces 
from src import proutil
class Rule:
    def __init__(self):
        self.prou = proutil.ProUtil()
        self.ruleFile = open(self.prou.getInit()['config']['RulePath']).read()
        self.data = json.loads(self.ruleFile)
        self.myip = self.prou.getMyIp()
        self.detField = self.prou.getDetField()
        self.layers = []
    def setLayers(self):
        for dit in self.data[self.detField]:
            self.layers.append(dit['type'])

    def getLayers(self):
        return self.layers

    def searchProtoIDX(self,protocol):
        if(len(self.layers) == 0):
            self.setLayers()
        return [i for i, e in enumerate(self.getLayers()) if e==protocol]

    def getProto(self,IDX):
        return self.data[self.detField][IDX]

    def detact(self,IDX,pkt):
        rule = self.data[self.detField][IDX]
        if rule['bound']  == 'all':
            if rule['type'] != 'TCP' or rule['type'] != 'UDP':
                return True
            if len(rule['port']) == 0:
                return True
            elif rule['type'] == 'TCP' and(pkt[TCP].sport in rule['port'] or pkt[TCP].dport in rule['port']):
                return True
            elif rule['type'] == 'UDP' and(pkt[UDP].sport in rule['port'] or pkt[UDP].dport in rule['port']):
                return True
        elif rule['bound'] == 'in':
            if str(pkt[IP].dst) == self.myip:
                if rule['type'] != 'TCP' or rule['type'] != 'UDP':
                    return True
                if len(rule['port']) == 0:
                    return True
                elif rule['type'] == 'TCP' and(pkt[TCP].dport in rule['port']):
                    return True
                elif rule['type'] == 'UDP' and(pkt[UDP].dport in rule['port']):
                    return True
        elif rule['bound'] == 'out':
            if str(pkt[IP].src) == self.myip:
                if rule['type'] != 'TCP' or rule['type'] != 'UDP':
                    return True
                if len(rule['port']) == 0:
                    return True
                elif rule['type'] == 'TCP' and(pkt[TCP].dport in rule['port']):
                    return True
                elif rule['type'] == 'UDP' and(pkt[UDP].dport in rule['port']):
                    return True
        return False
