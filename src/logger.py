from src import packetParser
class Logger():
    
    def __init__(self,logpath):
        self.logFile = open(logpath,'a')
    def writeLog(self,pkt):
        dataRow = packetParser.getDataRow(pkt)
        self.logFile.write(str(dataRow)+"\n")
