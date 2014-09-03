import csv
import io
import zipfile
import sys
import xml.etree.ElementTree as etree

def openCasefile(caseFile):
    zf    = zipfile.ZipFile(caseFile)
    fn = None
    for filename in zf.namelist():
        if ".graphml" in filename:
            fn = filename
    graphml = zf.read(fn)
    items_file  = io.TextIOWrapper(io.BytesIO(graphml))
    return items_file

def parseGraphml(items_file):
    catchFlag       = False
    catchType       = None

    clName          = "<?xml version=\"1.1\" encoding=\"UTF-8\" standalone=\"no\"?>"

    ipTable         = []
    domainTable     = []
    subDomainTable  = []

    csv.field_size_limit(sys.maxsize)

    for idx, row in enumerate(csv.DictReader(items_file)):
        if(catchFlag):
            if catchType == "ip":
                ip = row[clName].replace("/","").split("<mtg:Value>")[1]
                #print("[IP] " + ip)
                ipTable.append(ip)
            elif catchType == "dom":
                dom = row[clName].replace("/","").split("<mtg:Value>")[1]
                #print("[DO] " + dom)
                domainTable.append(dom)
            elif catchType == "sub":
                sub = row[clName].replace("/","").split("<mtg:Value>")[1]
                #print("[SD] " + sub)
                subDomainTable.append(sub)

        if "mtg:Property displayName=\"IP Address\"" in row[clName]:
            catchFlag = True
            catchType = "ip"
        elif "mtg:Property displayName=\"Domain Name\"" in row[clName]:
            catchFlag = True
            catchType = "dom"
        elif "mtg:Property displayName=\"DNS Name\"" in row[clName]:
            catchFlag = True
            catchType = "sub"
        else:
            catchFlag = False
    return ipTable, domainTable, subDomainTable

def genResult(ipTable, domTable, subDomTable, inF):
    globalTable     = []

    for ip in ipTable:
        globalTable.append([ip, inF, "IP4"])
    for d in domTable:
        globalTable.append([d, inF, "DOM"])
    for s in subDomTable:
        globalTable.append([s, inF, "DOM"])
    return globalTable

def dispatcher(f):
    graphml = openCasefile(f)
    i, d, s = parseGraphml(graphml)
    return genResult(i, d, s, f)

