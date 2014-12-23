import sqlite3 as lite
import os
import sys

class Database:

    def __init__(self, db='default.db'):
        self.db_name = db
        self.__db_check__()

    def __create_db__(self):
        try:
            self.con = lite.connect(self.db_name)
            self.con.text_factory = str
            cur = self.con.cursor()
            cur.executescript("""
                CREATE TABLE Files(OnDiskPath TEXT PRIMARY KEY, MD5 TEXT, SHA1 TEXT, onDisk BOOL, pe_filedescription, pe_fileversion TEXT, pe_filename TEXT,
                pe_originalfilename TEXT, pe_productname TEXT, pe_productversion TEXT, pe_copyright TEXT, pe_language TEXT, pe_company TEXT, pe_type TEXT,
                pe_fileversionMS TEXT, pe_fileversionLS TEXT, pe_productversionMS TEXT, pe_productversionLS TEXT, pe_timedatestamp TEXT, pe_header TEXT);
                """)
            self.con.commit()

        except lite.Error, e:
            if self.con:
                self.con.rollback()

            print 'Error: %s:' %e.args[0]
            sys.exit(1)

    def __db_check__(self):
        if not os.path.exists(self.db_name):
            self.__create_db__()
        else:
            self.con = lite.connect(self.db_name)
            self.con.text_factory = str

    def execute(self, data):
        with self.con:
            cur = self.con.cursor()
            cur.execute("%s") %data

    def add_entry(self, f):
        cur = self.con.cursor()
        if not self.__exist__(f):
            a = [(f.fullLocation, f.hash.md5, f.hash.sha1, f.onDisk, f.info.fileDescription, f.info.fileVersion, f.info.fileName, f.info.originalFileName,
                  f.info.productName, f.info.productVersion, f.info.copyright, f.info.language, f.info.company, f.file.type, f.file.pe.fileVersionMS,
                  f.file.pe.fileVersionLS, f.file.pe.productVersionMS, f.file.pe.productVersionLS, f.file.pe.timeDateStamp, f.file.pe.header)]
            cur.executemany('INSERT INTO Files values(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)', a )
        else:
            pass
        self.con.commit()



    def __exist__(self, f):
        with self.con:
            cur = self.con.cursor()
            self.execute("SELECT * FROM Files WHERE OnDiskPath = ?", f.fullLocation)
            data = cur.fetchone()

        if data is None:
            return False
        else:
            return True


