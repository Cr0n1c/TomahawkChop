import os
import re
import subprocess

class SystemInfo:

    def __init__(self):
        self.filesIgnore = []
        self.cmd = subprocess.check_output('systeminfo')

    def getMemory(self):
        try:
            self.memoryAvailable = int(re.sub(',','',re.findall('Available Physical Memory: (.*?) MB', self.cmd)[0]))
            self.memoryTotal = int(re.sub(',','',re.findall('Total Physical Memory: (.*?) MB', self.cmd)[0]))
        except:
            raise MemoryError
        else:
            if self.memoryAvailable < 512:
                raise MemoryError

    def getDrive(self):
        self.filesIgnore.append(re.findall('Page File Location(s):(.*?)\r\n', self.cmd)[0].strip())
        self.primaryHdd = re.findall('Windows Directory:(.*?)\r\n', self.cmd)[0].split(os.sep)[0])

    def getOS(self):
        self.os = re.findall('OS Version:(.*?)\r\n', self.cmd)[0].strip())
