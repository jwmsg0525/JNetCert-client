import requests as req
from src import proutil
from src import packetParser
import json

class ReqNet():
    def __init__(self,serverIP,serverPort):
        self.URL = "http://"+str(serverIP)+":"+str(serverPort)

    def getRuleJSON(self):
        path = "/api/client/get/rule"
        reqUrl = self.URL + path
        res = req.get(reqUrl)
        rulereqtxt = res.text
        rulereqjson = json.loads(rulereqtxt)
        rulejson = rulereqjson['message']
        return rulejson

    def upPacket(self,pkt):
        dataRow = packetParser.getDataRow(pkt)
        path = "/api/client/up/alert"
        reqUrl = self.URL + path
        res = req.post(reqUrl,data=dataRow)
        
