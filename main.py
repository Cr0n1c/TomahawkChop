import Lib
import time


def fullScan():
    files = Lib.FileSystem()
    files.dirWalk()



if __name__ == '__main__':
    stTime = time.time()
    fullScan()
    spTime = stTime - time.time()
    print 'Total Time Ran: %s' %str(spTime)