
class Analyze:

    def __init__(self, fileClass):

        self.status = None
        self.anomalies = []
        self.analyze(fileClass)

    def analyze(self, fileClass):
        #if self.__nsrlCompare(fileClass):
        #    return True
        self.fc = fileClass
        self.__checkFileName()

    def __nsrlCompare(self, fc):
        if HASH_DIC.get(fc.hash.sha1) is None:
            return False

        for hash_data in HASH_DIC.get(fc.hash.sha1):
                if fc.hash.md5 == hash_data['md5']:
                    if fc.fileName != hash_data['filename']:
                        self.anomalies.append('File name doesn\'t match known good')
                    self.status = 'Known Good'
                    print 'Found a good one'
                    return True


    def __checkFileName(self):
        if self.fc.fileExtention.lower() != 'unk' and self.fc.file.type.lower() != self.fc.fileExtention.lower():
            self.anomalies.append('PE Header doesn\'t match file extension')
        if self.fc.info.originalFileName.lower() not in self.fc.fileName.lower():
            self.anomalies.append('Original Filename doesn\'t match on disk name.')

def file2Dic(hashFile):
    attribs = {}
    dic = {}

    with open(hashFile, 'r') as fd:
        fLines = fd.readlines()

    for line in fLines:
        data = line.rstrip().split(',')

        if len(data) != 8: #data must be bad
            continue

        key = data[0].strip('"').lower()
        attribs['md5'] = data[1].strip('"').lower()
        attribs['crc32'] = data[2].strip('"')
        attribs['filename'] = data[3].strip('"')
        attribs['filesize'] = data[4].strip('"')
        attribs['productcode'] = data[5].strip('"')
        attribs['opsystemcode'] = data[6].strip('"')
        attribs['specialcode'] = data[7].strip('"')

        if dic.get(key) is not None:
            dic[key].append(attribs)
        else:
            dic[key] = [attribs]

    del fLines #should free up some space
    return dic

print 'Starting HashDB'
HASH_DIC = {}
print 'Finished HashDB'