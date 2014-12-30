
class Analyze:

    def __init__(self, fileClass):
        self.f = fileClass
        self.anomalies = []
        self.analyze()

    def __checkFileName(self):
        if self.f.fileExtention.lower() != 'unk' and self.f.file.type.lower() != self.f.fileExtention.lower():
            self.anomalies.append('PE Header doesn\'t match file extension')
        if self.f.info.originalFileName.lower() not in self.f.fileName.lower():
            self.anomalies.append('Original Filename doesn\'t match on disk name.')

    def analyze(self):
        self.__checkFileName()


