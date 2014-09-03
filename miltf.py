#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Mtgx&Ioc Load&Transform for netForensic

##############################
############# TODO ###########
##############################

# [BUG] Clean the MILTF working base with a whitelist

# [NOK] compareMy* functions : cleaner output
# [NOK] gps_* modules: make 2 in 1
# [NOK] mdie modules: treat it properly, as a xml file
# [NOK] filer: make all ine one

# Supported entities : Domain, sub-domain (mtgx/DNS Name format) and IP

##############################
##### SERIOUS SHIT PART ######
##############################

import argparse
import fnmatch
import os
import sys
import time

# Load scripts from the 'module' folder
from module import mtgx_dom_ip_extract as mdie
from module import ioc_dom_ip_extract as idie
from module import gps_ioc as gpsi
from module import gps_mtgx as gpsm
from module import header
from module import printer
from module import filer
from module import ThreatReconAPIRequest as trar

class Miltf:

    CONFIG_FILE_PATH        = "./store/miltf.cfg"

    IOC_FOLDER_PATH         = None
    MTGX_FOLDER_PATH        = None

    WHITELIST_PATH          = None

    RULES_BASES             = []
    WHITE_BASES             = set()

    CACHE_IN                = False
    CACHE_OUT               = False
    WHITELIST               = False

    ARG_TAB                 = None

    THREAT_RECON_API        = None
    API_ACTIVE              = None

    EXIT_NOT_SUPPORTED      = 99

    def __init__(self):
        self.confLoader()
        self.ARG_TAB  = self.getargs()
        header.header()
        if self.CACHE_OUT:
            self.csv2MILTF()
        else:
            print("\n[+] Loading the IOC File Base")
            t       = time.time()
            iCount  = self.loadIoc()
            e       = time.time() - t
            print("[+] "+str(iCount)+" IOC Rules loaded (in %f s)" % e)
            print("[+] Loading the Casefile File Base")
            t       = time.time()
            mCount  = self.loadMtgx()
            e       = time.time() - t
            print("[+] "+str(mCount)+ " MTGX files loaded (in %f s)" % e)
            print("[+] "+str(len(self.RULES_BASES))+" IPs and domains in MILTF working base")
        if self.WHITELIST:
            self.whiteListing()
        if self.CACHE_IN:
            self.wb2Csv()

# ====================== #
# ====== Argument ====== #
# ====================== #

    def getargs(self):
        desc    = "Mtgx&Ioc Load&Transform for netForensic (MILTF) aim to extract network information from mtgx (Paterva Maltego/Casefile) and IOC files."
        parser  = argparse.ArgumentParser(description=desc)

        # Search Possibilities
        h       = "Return all the element of the working base regarding one of the following tag: IP4, DOM, IOC, MTGX (not case sensitive, default=all)"
        parser.add_argument("-a",   "--all-flag",   help=h)
        h       = "Search a domain in the working base and return the matched string, the type of source file (IOC/MTGX) and the source file PATH"
        parser.add_argument("-d",   "--search-dom", help=h)
        h       = "Search an IPv4 adress in the working base and return the matched string, the type of source file (IOC/MTGX) and the source file PATH"
        parser.add_argument("-i", "--search-ip4",   help=h)

        # Checking Source File
        h       = "Extract IP and domain of a given IOC file, search the elemnts in the working base and return the matched string, the type of source file (IOC/MTGX) and the source file PATH"
        parser.add_argument("--check-ioc",          help=h)
        h       = "Extract IP and domain of a given Mtgx file, search the elemnts in the working base and return the matched string, the type of source file (IOC/MTGX) and the source file PATH"
        parser.add_argument("--check-mtgx",         help=h)
        h       = "Extract the string at each line of the given TXT file, search the elemnts in the working base and return the matched string, the type of source file (IOC/MTGX) and the source file PATH"
        parser.add_argument("--check-txt",          help=h)

        # Quantitative comparaison for Source File
        h       = "Extract IP and Domain of a given IOC File, search the element in the working base and return the number of element that matched at least one, with a numeric indicator."
        parser.add_argument("--comp-ioc",           help=h)
        h       = "Extract IP and Domain of a given Mtgx File, search the element in the working base and return the number of element that matched at least one, with a numeric indicator."
        parser.add_argument("--comp-mtgx",          help=h)
        h       = "Extract the string at each line of the given TXT file, search the element in the working base and return the number of element that matched at least one, with a numeric indicator."
        parser.add_argument("--comp-txt",           help=h)
        h       = "Extract IP and domains of two given files (IOC or MTGX) and return elements that matched at least one. Filenames has to be separate with a '=='"
        parser.add_argument("--comp-twix",          help=h)


        # Saving output
        h       = "Defining output method: create a txt file (txt), return a variable (var) or print in the terminal (term). Default = var. Don't hesitate to redirect the 'term' output into a file"
        parser.add_argument("-o", "--output-type",  help=h)

        # Configure Search
        h       = "Temporary change the configured IOC search PATH with your PATH (currently: "+str(self.IOC_FOLDER_PATH)+")"

        h       = "Temporary change the configured MTGX search PATH with your PATH (currently: "+str(self.MTGX_FOLDER_PATH)+")"

        h       = "Activate the Threat Recon API checking"
        parser.add_argument("--api",                help=h, action="store_true")

        h       = "Load domains and IPs from the given txt file (one per line) and exclude this elements from MILTF working base. BUG: some domains are exclude for an unknow reason, without beeing listed in the whitelist. Still investigated this issue."
        parser.add_argument("-e", "--exclude",      help=h, action="store_true")

        # Caching Source File
        h       = "Save the actual working base into a csv file"
        parser.add_argument("-ci","--cache-in",     help=h, action="store_true")
        h       = "Load data from the -ci argument's csv output to feed the working base, instead of crawling the filesystem."
        parser.add_argument("-co", "--cache_out",   help=h, action="store_true")


        args    = vars(parser.parse_args())

        for key, value in args.items():
            if key == "output_type" and value == None:
                value = "None (Maybe try 'txt' or 'term':))"

            if key == "cache_in" and value == True:
                self.CACHE_IN   = True
            if key == "cache_out" and value == True:
                self.CACHE_OUT  = True
            if key == "exclude" and value == True:
                self.WHITELIST  = True
            if key == "api" and value == True:
                self.API_ACTIVE = True

        return args


    def argLauncher(self, argTab):
        for key, value in argTab.items():
            if key == "all_flag" and value != None:
                self.rulesByFlag(value.lower(), str(argTab["output_type"]))
            if key == "search_dom" and value != None:
                self.searchDomain(value.lower(), "all",  str(argTab["output_type"]))
            if key == "search_ip4" and value != None:
                self.searchIP4(value.lower(), "all",  str(argTab["output_type"]))
            if key == "check_ioc" and value != None:
                self.checkMyIOC(value, "all", str(argTab["output_type"]))
            if key == "check_mtgx" and value != None:
                self.checkMyMtgx(value, "all", str(argTab["output_type"]))
            if key == "comp_ioc" and value != None:
                self.compareMyIOC(value, "all", str(argTab["output_type"]))
            if key == "comp_mtgx" and value != None:
                self.compareMyMtgx(value, "all", str(argTab["output_type"]))
            if key == "check_txt" and value != None:
                self.checkMyTxt(value, "all", str(argTab["output_type"]))
            if key == "comp_txt" and value != None:
                self.compareMyTxt(value, "all", str(argTab["output_type"]))
            if key == "comp_twix" and value != None:
                a = value.split("==")
                self.compareFile2Another(a[0], a[1], "all", str(argTab["output_type"]))

        return 0

# ====================== #
# === Load from Store == #
# ====================== #

    def confLoader(self):
        f = open(self.CONFIG_FILE_PATH, "r")
        confDict = {}

        for line in f:
            if line.count("=") > 0:
                confDict[line.split("=")[0].strip()] = line.split("=")[1].strip()

        self.IOC_FOLDER_PATH    = confDict["IOC_FOLDER_PATH"]
        self.MTGX_FOLDER_PATH   = confDict["MTGX_FOLDER_PATH"]
        self.WHITELIST_PATH     = confDict["WHITELIST_PATH"]

        if confDict["CACHE_IN"] == "True":
            self.CACHE_IN   = True
        else:
            self.CACHE_IN  = False

        if confDict["CACHE_OUT"] == "True":
            self.CACHE_OUT  = True
        else:
            self.CACHE_OUT = False

        if confDict["WHITELIST"] == "True":
            self.WHITELIST  = True
        else:
            self.WHITELIST = False

        if confDict["API_ACTIVE"] == "True":
            self.API_ACTIVE = True
        else:
            self.API_ACTIVE = False

        f.close()

    def wb2Csv(self):
        print("\n[+] Caching the MILTF Working base in csv, according to your will Monsieur.")

        f = open("store/wb.csv", "w+")
        for line in self.RULES_BASES:
            f.write(line[0]+";"+line[1]+";"+line[2]+";"+line[3]+"\n")
        f.close()
        print("[+] That's good! Try the -co argument next time!")
        time.sleep(2)
        print("[+] And do not forget to -ci me from time to time, I like new incoming ;-)\n")
        time.sleep(3)


    def csv2MILTF(self):
        f = None
        try:
            f = open("store/wb.csv", "r")
        except FileNotFoundError:
            exit("[!] No CSV cache! Please -ci me first to see my little -co! Exiting ...\n")
        print("\n[+] Fast loading from CSV cache. Rabbit style! It will not last long!")
        resTab = []
        cpt = 0
        for line in f:
            resTab.append(line.strip().split(";"))
            cpt += 1
        self.RULES_BASES = resTab
        print("[+] Ok, the whole thing is in (%d IPs and domains). Start Working!\n" % cpt)
        f.close()


    def whiteListing(self):
        print("\n[+] Cleaning the MILTF working base with whitelist")
        f           = open(self.WHITELIST_PATH, "r")
        cpt         = 0
        for line in f:
            for idx, rule in enumerate(self.RULES_BASES):
                if (rule[3].endswith("."+line.strip())) or (rule[3] == line.strip()):
                    cpt         += 1
                    del self.RULES_BASES[idx]

        f.close()
        print("[+] Cleaning: Done! (%d rules whitelisted)\n" %cpt)



# ====================== #
# === Find and Load === #
# ====================== #

    def intelFinder(self, ext):
        choice_ioc  = False
        choice_mtgx = False
        if "ioc" in ext and "mtgx" in ext:
            choice_ioc  = True
            choice_mtgx = True
        elif ext == "ioc":
            choice_ioc  = True
        elif ext == "mtgx":
            choice_mtgx = True
        else:
            return self.EXIT_NOT_SUPPORTED

        if(choice_ioc and choice_mtgx):
            pass
        elif(choice_ioc):
            match = gpsi.gps_ioc(self.IOC_FOLDER_PATH)
        elif(choice_mtgx):
            match = gpsm.gps_mtgx(self.MTGX_FOLDER_PATH)

        return match


    def loadIoc(self):
        iocBase     = []
        iocTab      = self.intelFinder("ioc")
        for ioc in iocTab:
            iocBase.append(idie.dispatcher(ioc))
        for chunck in iocBase:
            if len(chunck) > 0:
                for element in chunck:
                    self.RULES_BASES.append(["IOC",element[2],element[1], element[0]])
        return len(iocTab)


    def loadMtgx(self):
        mtgxBase    = []
        mtgxTab     = self.intelFinder("mtgx")
        for mtgx in mtgxTab:
            mtgxBase.append(mdie.dispatcher(mtgx))
        for chunck in mtgxBase:
            if len(chunck) > 0:
                for element in chunck:
                    self.RULES_BASES.append(["MTGX", element[2], element[1], element[0]])
        return len(mtgxTab)

# ======================= #
# ===== Small script ==== #
# ======================= #
    def trarAttribution(self,indicator):
        #Request Attribution information from ThreatRecon Free API
        #Free API limited at 4 req/min
        trar_attribution    = "No or Wrong API key"

        if self.API_ACTIVE == True:
            a = trar.queryTR(indicator,self.THREAT_RECON_API)
            if a == None:
                trar_attribution    = "Unknow indicator"
            elif a[0]["Attribution"] == "" :
                trar_attribution = "No Attribution"
            else:
                trar_attribution = a[0]["Attribution"]

        elif self.API_ACTIVE == False:
            trar_attribution = "API check not activate"

        return trar_attribution


# ======================= #
# ======= Transform ===== #
# ======================= #

    def rulesByFlag(self, condition="all", output="var"):
        resTab  = []

        if condition == "all":
            for line in self.RULES_BASES:
                resTab.append(line)
        elif condition == "ip4":
            for line in self.RULES_BASES:
                if line[1] == "IP4":
                    resTab.append(line)
        elif condition == "dom":
            for line in self.RULES_BASES:
                if line[1] == "DOM":
                    resTab.append(line)
        elif condition == "ioc":
            for line in self.RULES_BASES:
                if line[0] == "IOC":
                    resTab.append(line)
        elif condition == "mtgx":
            for line in self.RULES_BASES:
                if line[0] == "MTGX":
                    resTab.append(line)
        if output == "term":
            printer.rulesByFlag(resTab, condition)
        elif output == "txt":
            filer.rulesByFlag(resTab, condition)
        else:
            return resTab


    def searchDomain(self, domain, condition="all", output="var"):
        domTable    = []
        for rules in self.RULES_BASES:
            if domain.endswith("."+rules[3]) or rules[3].endswith("."+domain) or domain == rules[3]:
                domTable.append([rules[3], rules[0], rules[2]])

        trar_attribution    = self.trarAttribution(domain)

        if output == "term":
            printer.searchDomain(domTable, domain, trar_attribution)
        elif output == "txt":
            filer.searchDomain(domTable, domain, trar_attribution)
        else:
            return domTable


    def searchIP4(self, ip4, condition="all", output="var"):
        ipTable     = []
        for rules in self.RULES_BASES:
            if ip4 in rules[3]:
                ipTable.append([rules[3], rules[0], rules[2]])

        trar_attribution    = self.trarAttribution(ip4)

        if output == "term":
            printer.searchIP4(ipTable, ip4, trar_attribution)
        elif output == "txt":
            filer.searchIP4(ipTable, ip4, trar_attribution)
        else:
            return ipTable


    def checkMyIOC(self, myIocPath, condition="all", output="var"):
        myIocAttributes = idie.dispatcher(myIocPath)
        resTab = []
        for line in myIocAttributes:
            for rules in self.RULES_BASES:
                if myIocPath != rules[2]:
                    if line[0].endswith("."+rules[3]) or rules[3].endswith("."+line[0]) or line[0] == rules[3]:
                        trar_attribution    = self.trarAttribution(line[0])
                        resTab.append([line[0], rules[3], rules[0], rules[2], trar_attribution])

        if output == "term":
            printer.checkMyIOC(resTab, myIocPath)
        elif output == "txt":
            filer.checkMyIOC(resTab, myIocPath)
        else:
            return resTab


    def checkMyMtgx(self, myMtgxPath, condition="all", output="var"):
        myMtgxAttributes    = mdie.dispatcher(myMtgxPath)
        resTab              = []
        for line in myMtgxAttributes:
            for rules in self.RULES_BASES:
                if myMtgxPath != rules[2]:
                    if line[0].endswith("."+rules[3]) or rules[3].endswith("."+line[0]) or line[0] == rules[3]:
                        trar_attribution    = self.trarAttribution(line[0])
                        resTab.append([line[0], rules[3], rules[0], rules[2], trar_attribution])

        if output == "term":
            printer.checkMyMtgx(resTab, myMtgxPath)
        elif output == "txt":
            filer.checkMyMtgx(resTab, myMtgxPath)
        else:
            return resTab


    def compareMyIOC(self, myIocPath, condition="all", output="var"):
        fileMatch   = {}
        resTab      = self.checkMyIOC(myIocPath, condition)
        for line in resTab:
            try:
                fileMatch[line[3]] += 1
            except:
                fileMatch[line[3]] = 1

        if output == "term":
            printer.compareMyIOC(fileMatch, myIocPath)
        elif output == "txt":
            filer.compareMyIOC(fileMatch, myIocPath)
        else:
            return fileMatch


    def compareMyMtgx(self, myMtgxPath, condition="all", output="var"):
        fileMatch   = {}
        resTab      = self.checkMyMtgx(myMtgxPath, condition)
        for line in resTab:
            try:
                fileMatch[line[3]] += 1
            except:
                fileMatch[line[3]] = 1

        if output == "term":
            printer.compareMyMtgx(fileMatch, myMtgxPath)
        elif output == "txt":
            filer.compareMyMtgx(fileMatch, myMtgxPath)
        else:
            return fileMatch


    def checkMyTxt(self, myTxtPath, condition="all", output="var"):
        f           = open(myTxtPath, "r")

        resTab      = []
        cpt = 0
        for line in f:
            cpt += 1
            line = line.strip()
            if len(line) > 0:
                if line[0] not in "#":
                    for rules in self.RULES_BASES:
                        if line.endswith("."+rules[3]) or rules[3].endswith("."+line) or rules[3] == line:
                            trar_attribution = self.trarAttribution(line)
                            resTab.append([line, rules[3], rules[0], rules[2], trar_attribution])
        f.close()
        if output == "term":
            printer.checkMyTxt(resTab, myTxtPath, cpt)
        elif output == "txt":
            filer.checkMyTxt(resTab, myTxtPath)
        else:
            return resTab


    def compareMyTxt(self, myTxtPath, condition="all", output="var"):
        fileMatch   = {}
        resTab      = self.checkMyTxt(myTxtPath, condition)
        for line in resTab:
            try:
                fileMatch[line[3]] += 1
            except:
                fileMatch[line[3]] = 1

        if output == "term":
            printer.compareMyTxt(fileMatch, myTxtPath)
        elif output == "txt":
            filer.compareMyTxt(fileMatch, myTxtPath)
        else:
            return resTab

    def compareFile2Another(self, file1, file2, condition="all", output="var"):

        file1_element   = None
        if file1.endswith("ioc"):
            file1_element = idie.dispatcher(file1)
        elif file1.endswith("mtgx"):
            file1_element = mdie.dispatcher(file1)
        elif file1.endswith("res") or file1.endswith("lst") or file1.endswith("txt"):
            file1_element   = list()
            for line in open(file1, "r"):
                if len(line.strip()) > 0:
                    file1_element.append([line.strip(), file1, "TEXT"])
        else:
            return EXIT_NOT_SUPPORTED

        file2_element   = None
        if file2.endswith("ioc"):
            file2_element = idie.dispatcher(file2)
        elif file2.endswith("mtgx"):
            file2_element = mdie.dispatcher(file2)
        elif file2.endswith("res") or file2.endswith("lst") or file2.endswith("txt"):
            file2_element   = list()
            for line in open(file2, "r"):
                if len(line.strip()) > 0:
                    file2_element.append([line.strip(), file2, "TEXT"])
        else:
            return self.EXIT_NOT_SUPPORTED

        resTab  = []
        for l1 in file1_element:
            for l2 in file2_element:
                if l1[0].endswith("."+l2[0]) or l2[0].endswith("."+l1[0]) or l2[0] == l1[0]:
                    a1 = self.trarAttribution(l1)
                    a2 = self.trarAttribution(l2)
                    resTab.append([l1[0], l2[0], a1, a2])
        if output == "term":
            printer.compareFile2Another(resTab, file1, file2)
        elif output == "txt":
            filer.compareFile2Another(resTab, file1, file2)
        else:
            return resTab


# ================== #
# ==== Launchers === #
# ================== #

    def please_come_in(self):
        fromArgLauncher = self.argLauncher(self.ARG_TAB)



if __name__ == '__main__':
    pamela  = Miltf()
    pamela.please_come_in()
