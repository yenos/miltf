import xml.etree.ElementTree as etree
import sys

schem = "{http://schemas.mandiant.com/2010/ioc}"
def parseXML(iocRules):
    ipTable = []
    domTable = []

    catchFlag = False

    for el in iocRules.iter(schem+"IndicatorItem"):
        for content in el.iter():
        # DomCatch
            if(catchFlag):
                domTable.append(content.text)

        # IP
            try:
                if content.attrib["type"] == "IP":
                    ipTable.append(content.text)
            except:
                pass
        # DomFlag
            try:
                if content.attrib["search"] == "Network/DNS":
                    catchFlag = True
                else:
                    catchFlag = False
            except:
                catchFlag = False

    return ipTable, domTable

def genResult (ipTable, domTable, inF):
    globalTable     = []

    for ip in ipTable:
        globalTable.append([ip, inF, "IP4"])
    for dom in domTable:
        globalTable.append([dom, inF, "DOM"])
    return globalTable

def dispatcher(f):
    tree = etree.parse(f)
    root = tree.getroot()
    ipt, dot = parseXML(root)
    return genResult(ipt, dot, f)


