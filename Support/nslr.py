import sqlite3 as lite
import sys
import csv
from glob import glob

'''
    Take note, this should only be ran to update the NSLR database.  To get this to work with the 4 split files
    I needed 24gig ram.  I found that after creating the db it was bloated out to 22 gigs.  That is why I added
    the vacuum feature.
'''

def createDB():
    con = lite.connect(sqliteFile)
    con.text_factory = str
    with con:
        cur = con.cursor()
        cur.execute("CREATE TABLE IF NOT EXISTS hashTable(SHA1 TEXT, MD5 TEXT, FileName TEXT, OpSystemCode TEXT)")
        cur.execute("CREATE INDEX hashTableIdx ON hashTable(SHA1)")


def csv2Sqlite(csvFile):
    con = lite.connect(sqliteFile)
    con.text_factory = str
    with con:
        cur = con.cursor()
        with open(csvFile, 'rb') as fin:
            dr = csv.DictReader(fin)
            to_db = [(i['SHA-1'], i['MD5'], i['FileName'], i['OpSystemCode']) for i in dr]
            cur.executemany("INSERT INTO hashTable (SHA1, MD5, FileName, OpSystemCode) VALUES (?, ?, ?, ?);", to_db)
    con.close()

def vacuum():
    con = lite.connect(sqliteFile)
    with con:
        con.execute("VACUUM")

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print 'nslr.py sqlite_database csv_file_location'

    sqliteFile = sys.argv[1]
    csvFiles = sys.argv[2]

    createDB()

    for cv in csvFiles:
        csv2Sqlite(cv)

    vacuum()