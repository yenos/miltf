#!/usr/bin/env python3
import re
import sys
import multiprocessing
import os
import time
import subprocess

# ===== Line processing ===== #
class LineProcessing():
    def process_lines(self, lines):
        #regex       = re.compile("://([^:/]+)")
        rvs = set()
        try:
            s = lines[lines.index("://") + 3:]
            rvs.add(s[:s.find('/')][:s.find(':')])
        except:
            pass
        #res = regex.search(lines)
        #if res is not None:
        #    rvs.add(res.group(1))
        return rvs

# ===== File processing ===== #
class Processing():
    def log2dom(self, fn, session):
        cleanDomTab = set()
        regex       = re.compile("://([^:/]+)")
        with open(fn,'r', encoding="latin-1") as f:
            for line in f:
                res = regex.search(line)
                if res is not None:
                    cleanDomTab.add(res.group(1))
        return cleanDomTab

    def parallel_log2dom(self, fn, session, chunks=100):
        tb          = Toolbox()
        lp          = LineProcessing()
        cleanDomTab = set()
        pool        = multiprocessing.Pool()
        factor      = 1
        lineCpt     = 0
        fsizeMo     = int(os.stat(fn).st_size/1000000)
        nbLines     = tb.estimateLineNumber(fsizeMo)
        print("> Number of Chunks: {0}".format(chunks))
        print("\t> Processing: 0%")
        t           = time.time()
        with open(fn,'r', encoding="latin-1") as f:
            for s in pool.imap_unordered(lp.process_lines, f, chunksize=chunks):
                lineCpt    += 1

                cleanDomTab.update(s)

                if int(factor*nbLines/20) == lineCpt:
                    e           = int(time.time() -t)
                    timeLeft    = int(e*(100-factor*5)/5)
                    print("\t> Processing: {0}% - Estimated time: {1}min ({2}s)".format(factor*5, int(timeLeft/60), int(timeLeft)))
                    factor      += 1
                    t           = time.time()

        return cleanDomTab

# ===== Toolbox ===== #
class Toolbox:
    def estimateLineNumber(self, sizeMo):
        # About 2100 lines per Mo for the type of proxy log file we are use to receive
        return 2100*sizeMo

    def calcNumberChunks(self, nbLine):
        # 666 lignes per chunks, number obtain through a quick&dirty benchmark
        return nbLine/666

    def getTotalRAMAmount(self):
        f   = open("/proc/meminfo","r")
        a   = f.readline()
        return int(int(a.split(":        ")[1].split(" kB")[0])/1000000)

    def checkFolderCounterSwap(self, logPath, logName):
        if not os.path.exists(logPath+"[Takuzin]"+logName):
            os.mkdir(logPath+"[Takuzin]"+logName)

# ===== Big File processing ===== #
class GangBang():
    def counterSwap(self, ramAmount, logPath, logName, logLine):
        tb          = Toolbox()
        tb.checkFolderCounterSwap(logPath, logName)
        #Split
        nbLine      = tb.estimateLineNumber(int(ramAmount)*1000)
        lineCpt     = 0
        lineTotal   = 1
        fileCpt     = 1
        factor      = 1

        with open (logPath+logName.replace("_","."), 'r', encoding="latin-1") as f:
            fn              =logPath+"[Takuzin]"+logName+"/Part-{0}.lst".format(fileCpt)
            counterSwapFile = open(fn, "a", encoding="latin-1")
            estTimeLeft     = int(logLine/50000)

            print("(!) Writing in {0}".format(fn))
            print("\t> Processing: 0% - Estimated minutes left: {0} ({1}s)".format(int(estTimeLeft/60), int(estTimeLeft)))

            t = time.time()
            for line in f:
                lineCpt += 1
                if lineCpt < nbLine:
                    counterSwapFile.write(line)
                elif lineCpt == nbLine:
                    counterSwapFile.write(line)
                    lineCpt     = 0
                    fileCpt     += 1
                    counterSwapFile.close()
                    fn =logPath+"[Takuzin]"+logName+"/Part-{0}.lst".format(fileCpt)
                    print("(!) Writing in {0}".format(fn))
                    counterSwapFile = open(fn, "a", encoding="latin-1")
                lineTotal += 1
                if int(factor*logLine/20) == lineTotal:
                    e = int(time.time() - t)
                    timeLeft = int(e*(100-factor*5)/5)
                    print("\t> Processing: {0}% - Estimated minutes left: {1} ({2}s)".format(factor*5, int(timeLeft/60), int(timeLeft)))
                    factor += 1
                    t = time.time()
            print("\t> Processing: 100%")
            counterSwapFile.close()

        return logPath+"[Takuzin]"+logName+"/"

    def multiple_log2dom(self, folder, restart=False):
        if restart == False:
            fileList    = os.listdir(folder)
            nbFile      = len([x for x in fileList if "lst" in x.split(".")[-1]])
            fileCpt     = 1
            tb          = Toolbox()
            for f in fileList:
                ext     = f.split(".")[-1]
                if ext == "lst":
                    proc            = Processing()
                    d               = set()
                    fn              = folder+f
                    fsizeMo         = int(os.stat(fn).st_size/1000000)
                    nbLines         = tb.estimateLineNumber(fsizeMo)
                    nbChunks        = int(tb.calcNumberChunks(nbLines))
                    estTime         = int(nbLines/58000)
                    print("\n[+] Processing file n°{0}/{1}: {2} ({3}Go) - Estimated time: {4}min".format(fileCpt, nbFile, f, fsizeMo/1000, int(estTime/60)))
                    d = proc.parallel_log2dom(fn, 0, nbChunks)
                    print("\n\t> Processing Done.")
                    with open(folder+f.replace(".lst","_")+"set.bck", "w") as backSet:
                        for line in d:
                            backSet.write(line+"\n")
                    fileCpt += 1
                    os.remove(fn)

        print("\n[+] Merging splitted results files.\n")
        fileList        = os.listdir(folder)
        backFileList    = list()
        for f in fileList:
            if f.split(".")[-1] == "bck":
                backFileList.append(f)

        g   = set()
        i   = 1
        for f in backFileList:
            print("\t> Processing file n°{0}/{1}: {2}".format(i, len(backFileList), f))
            fi  = open(folder+f, "r")
            fileTab = []
            for line in fi:
                fileTab.append(line)
            g.update(fileTab)
            i += 1

        print("\n\t> Creating the set.res result file.")
        with open(folder+"set.res", "w") as f:
            for line in g:
                f.write(line)

        for f in backFileList:
            os.remove(folder+f)



# ===== Entry point ===== #
class Takuzin:
    def avale(self, param):
        tb              = Toolbox()
        proc            = Processing()
        fsize           = os.stat(param).st_size
        fsizeMo         = int(fsize/1000000)
        b               = set()

        nbLines         = tb.estimateLineNumber(fsizeMo)
        nbChunks        = int(tb.calcNumberChunks(nbLines))
        ramAmount       = tb.getTotalRAMAmount()
        ramAllocated    = int((800/100)*ramAmount)
        logPath         = "/".join(param.split("/")[:-1])+"/"
        logName         = param.split("/")[-1].replace(".", "_")

        print("\n[+] Stats:\n-> Estimated nb of lines: {0} \n-> File size: {1} Go\n-> RAM Amount: {2}Go\n-> Allocated RAM: {3}Go".format(nbLines, int(fsizeMo/1000), ramAmount, ramAllocated))

        if fsize < (1<<30):
            b = proc.log2dom(param, 0)
        elif fsize > ((ramAllocated)<<30):
            gb              = GangBang()
            print("\n[+] Log file too big to be stored in RAM. Splitting needed\n")
            counterSwapPath = gb.counterSwap(ramAllocated, logPath, logName, nbLines)
            gb.multiple_log2dom(counterSwapPath)
        else:
            print("\n[+] Log file can be stored in RAM. Processing Log File\n")
            b = proc.parallel_log2dom(param, 0, nbChunks)

        self.crache(b, param)

    def crache(self, s, logPATH):
        if len(s) > 0:
            setFileName     = logPATH.replace(".", "_")+"-set.res"
            with open(setFileName,"w") as f:
                for line in s:
                    f.write(line+"\n")

    def repars(self, fn, restart):
        gb      = GangBang()
        s       = fn.split("/")
        path    = "/".join(s[:-1])+"/[Takuzin]"+s[-1]+"/"
        if restart == "lst":
            print("\n[+] Restarting chunked *.lst files processing")
            gb.multiple_log2dom(path)
        elif restart == "bck":
            print("\n[+] Restarting *.bck files merging")
            gb.multiple_log2dom(path, True)

    def tactac(self, argv):
        param       = argv[1]
        #test = subprocess.check_output(["grep", "-E", "(tunnel|http|ftp)://[^:/]+", param, "-o"])
        #t = str(test).split("\\n")
        #sys.exit()
        try:
            if argv[2].lower() == "rlst":
                self.repars(param, "lst")
            elif argv[2].lower() == "rbck":
                self.repars(param, "bck")
        except IndexError:
            self.avale(param)


if __name__ == '__main__':
    Takuzin     = Takuzin()
    Takuzin.tactac(sys.argv)

