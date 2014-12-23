import hashlib
import os
import shutil
import sys
import string
import time
import tempfile

import pefile
import pythoncom

import Analysis
import Database

from win32com.shell import shell  # @UnresolvedImport
from win32com import storagecon
from ctypes import windll

def getValue(obj, strVar):
    data = ''
    if isinstance(obj, str):
        data = strVar
    elif isinstance(obj, dict):
        try:
            data = obj[strVar]
        except KeyError:
            data = ''
    else:
        try:
            data = getattr(obj, strVar)
        except AttributeError:
            data = ''

    return data

class Empty:
    pass

class File:

    def __init__(self, file_location, db):
        self.fullLocation = file_location
        self.filePath = os.path.split(self.fullLocation)[0]
        self.fileName= os.path.split(self.fullLocation)[-1]
        self.fileExtention = self.fileName.split('.')[-1]
        self.onDisk = True
        self.file = Empty()
        self.hash = Hash(self.fullLocation)
        self.info = FileProperties(self.fullLocation)
        self.__getFilePEInfo__()
        self.analysis = Analysis.Analyze(self)
        db.add_entry(self)

    def __getFilePEInfo__(self):
        self.file.pe = Empty()
        self.isPE = False
        self.file.pe.fileVersionMS = ''
        self.file.pe.fileVersionLS = ''
        self.file.pe.productVersionMS = ''
        self.file.pe.productVersionLS = ''
        self.file.pe.timeDateStamp = ''
        self.file.type = 'unk'

        try:
            pe = pefile.PE(self.fullLocation)
        except WindowsError: #File doesn't exist
            self.onDisk = False
            pass
        except pefile.PEFormatError: #Not a file we care about!!
            pass
        except UnboundLocalError: #found no info in pe
            self.isPE = True
            pass
        else:
            try:
                self.isPE = True
                self.file.pe.fileVersionMS = getValue(pe.VS_FIXEDFILEINFO, 'FileVersionMS')
                self.file.pe.fileVersionLS = getValue(pe.VS_FIXEDFILEINFO, 'FileVersionLS')
                self.file.pe.productVersionMS = getValue(pe.VS_FIXEDFILEINFO, 'ProductVersionMS')
                self.file.pe.productVersionLS = getValue(pe.VS_FIXEDFILEINFO, 'ProductVersionLS')
                #self.file.pe.timeDateStamp = getValue(pe.IMAGE_FILE_HEADER, 'TimeDateStamp')
                self.file.pe.header = getValue(pe, 'header')
            except:
                pass
            if pe.is_dll():
                self.file.type = 'dll'
            elif pe.is_exe():
                self.file.type = 'exe'
            elif pe.is_sys():
                self.file.type = 'sys'


class FileProperties:

    def __init__(self, file_path):
        self.language = ''
        self.company = ''
        self.fileDescription = ''
        self.fileVersion = ''
        self.fileName = ''
        self.originalFileName = ''
        self.productName = ''
        self.productVersion = ''
        self.copyright = ''

        for name, properties in self.propertySets (file_path):
            if name == 'DocSummaryInformation':
                self.language = getValue(properties, '0x1c')
                self.company = getValue(properties, 'PIDDSI_COMPANY')
            elif name == '{0CEF7D53-FA64-11D1-A203-0000F81FEDEE}':
                self.fileDescription = getValue(properties, '0x3')
                self.fileVersion = getValue(properties, '0x4')
                self.fileName = getValue(properties, '0x5')
                self.originalFileName = getValue(properties, '0x6')
                self.productName = getValue(properties, '0x7')
                self.productVersion = getValue(properties, '0x8')
            elif name == '{64440492-4C8B-11D1-8B70-080036B11A03}':
                self.copyright = getValue(properties, '0xb')

    def propertyDict(self, property_set_storage, fmtid):
        properties = {}
        PROPERTIES = {  pythoncom.FMTID_SummaryInformation : dict (  # @UndefinedVariable
                        (getattr (storagecon, d), d) for d in dir (storagecon) if d.startswith ("PIDSI_")),
                        pythoncom.FMTID_DocSummaryInformation : dict (  # @UndefinedVariable
                        (getattr (storagecon, d), d) for d in dir (storagecon) if d.startswith ("PIDDSI_"))
                      }
        STORAGE_READ = storagecon.STGM_READ | storagecon.STGM_SHARE_EXCLUSIVE

        try:
            property_storage = property_set_storage.Open (fmtid, STORAGE_READ)
        except pythoncom.com_error, error:  # @UndefinedVariable
            if error.strerror == 'STG_E_FILENOTFOUND':
                return {}
            else:
                raise

        for name, property_id, vartype in property_storage:  # @UnusedVariable
            if name is None:
                name = PROPERTIES.get (fmtid, {}).get (property_id, None)
            if name is None:
                name = hex (property_id)
            try:
                for value in property_storage.ReadMultiple ([property_id]):
                    properties[name] = value
            #
            # There are certain values we can't read; they
            # raise type errors from within the pythoncom
            # implementation, thumbnail
            #
            except TypeError:
                properties[name] = None
        return properties

    def propertySets(self, filepath):
        FORMATS = {     pythoncom.FMTID_SummaryInformation : "SummaryInformation",  # @UndefinedVariable
                        pythoncom.FMTID_DocSummaryInformation : "DocSummaryInformation",  # @UndefinedVariable
                        pythoncom.FMTID_UserDefinedProperties : "UserDefinedProperties"  # @UndefinedVariable
                  }

        pidl, flags = shell.SHILCreateFromPath (os.path.abspath (filepath), 0)  # @UnusedVariable
        try:
            property_set_storage = shell.SHGetDesktopFolder ().BindToStorage (pidl, None, pythoncom.IID_IPropertySetStorage)  # @UndefinedVariable

            for fmtid, clsid, flags, ctime, mtime, atime in property_set_storage:  # @UnusedVariable
                yield FORMATS.get (fmtid, unicode (fmtid)), self.propertyDict (property_set_storage, fmtid)

                if fmtid == pythoncom.FMTID_DocSummaryInformation:  # @UndefinedVariable
                    fmtid = pythoncom.FMTID_UserDefinedProperties  # @UndefinedVariable
                    user_defined_properties = self.propertyDict (property_set_storage, fmtid)

                    if user_defined_properties:
                        yield FORMATS.get (fmtid, unicode (fmtid)), user_defined_properties
        except:
            pass

class FileSystem:

    def __init__(self):
        self.files = []
        self.db = Database.Database()

    def __listFiles__(self, startPath):
        dontCheck = ['hiberfil.sys', 'swapfile.sys', 'pagefile.sys']

        dWalk = os.walk(startPath + ':\\')
        for root, dirs, files in dWalk:  # @UnusedVariable
            for f in files:
                try:
                    full_path = root + os.sep + f
                    if os.path.split(full_path)[-1].lower() in dontCheck:
                        continue #files we dont want to check
                    elif os.path.isfile(full_path):
                        '''if not full_path[-3:] in ['dll', 'exe', 'sys']:
                            continue'''
                        self.files.append(File(full_path, self.db))
                except AttributeError:
                    pass

    def getDrives(self):
        drives = []
        bitmask = windll.kernel32.GetLogicalDrives()  # @UndefinedVariable

        for letter in string.uppercase:
            if bitmask & 1:
                drives.append(letter)
            bitmask >>= 1

        return drives

    def dirWalk(self):
        for drive in self.getDrives():
            self.__listFiles__(drive)


class Hash:
    ''' Used to set hashes for files'''

    def __init__(self, file_location):
        self.file = file_location
        self.md5()
        self.sha1()

    def __hasher__(self, hasher):
        try:
            with open(self.file, 'rb') as afile:
                buf = afile.read()
                hasher.update(buf)
        except IOError: #Happens when file is locked
            tf = tempfile.TemporaryFile(mode='r+b', prefix='toma', suffix='.chop')
            try:
                with open(self.file,'rb') as f:
                    shutil.copyfileobj(f,tf)
                tf.seek(0)
                hasher.update(tf.read())
            except IOError:
                pass
            tf.close()
        else:
            return hasher.hexdigest()

    def md5(self):
        self.md5 = self.__hasher__(hashlib.md5())

    def sha1(self):
        self.sha1 = self.__hasher__(hashlib.sha1())


