import json
from scapy.all import *
import netifaces 
class ProUtil:
    def __init__(self):
        self.initFile = open('./config/init.json').read()
        self.initData = json.loads(self.initFile)
        self.modeFile = open(self.initData['config']['ModePath']).read()
        self.modeData = json.loads(self.modeFile)
        self.myip = netifaces.ifaddresses(self.initData['system']['NetInterFace'])[netifaces.AF_INET][0]['addr']
    def getInit(self):
        return self.initData
    def getMode(self,modename):
        return self.modeData[modename]
    def getMyIp(self):
        return self.myip
    def getDetField(self):
        if(self.getMode("filter")['mode'] == 'blacklist'):
            return "Deny"
        return "Allow"
