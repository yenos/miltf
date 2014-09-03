import operator

def rulesByFlag(tab, t):
    i   = 1
    print("\n[+] Printing Working Base (sort: "+t+")")
    print("> Count:\t"+str(len(tab))+"\n")
    for line in tab:
        print("Element n°"+str(i))
        print("\t> File type: "+str(line[0]))
        print("\t> Element type: "+str(line[1]))
        print("\t> Source PATH: "+str(line[2]))
        print("\t> Element: "+str(line[3])+"\n")
        i += 1

def searchDomain(tab, t, a):
    print("\n[+] Printing search result for: "+t)
    print("> Count:\t"+str(len(tab)))
    sourceList  = {}
    for line in tab:
        try:
            sourceList[line[2]] += 1
        except:
            sourceList[line[2]] = 1
    print("> "+str(len(sourceList))+" source files have triggered:")
    for key in sourceList.keys():
        print("\t- "+key)
    i = 1
    for line in tab:
        print("\nMatch n°"+str(i)+": "+t+" -> "+line[0])
        print("\t> File type: "+str(line[1]))
        print("\t> Element Type: dom")
        print("\t> Source PATH: "+str(line[2]))
        print("\t> Threat Recon Attribution: "+a)
        i += 1

def searchIP4(tab, t, a):
    print("\n[+] Printing search result for: "+t)
    print("> Count:\t"+str(len(tab)))
    sourceList  = {}
    for line in tab:
        try:
            sourceList[line[2]] += 1
        except:
            sourceList[line[2]] = 1
    print("> "+str(len(sourceList))+" source files have triggered:")
    for key in sourceList.keys():
        print("\t- "+key)
    i = 1
    for line in tab:
        print("\nMatch n°"+str(i)+": "+t+" -> "+line[0])
        print("\t> File type: "+str(line[1]))
        print("\t> Element Type: ip4")
        print("\t> Source PATH: "+str(line[2]))
        print("\t> Threat Recon Attribution: "+a)
        i += 1

def checkMyIOC(resTab, t):
    i = 0
    print("\n[+] Printing working base similarities with "+t.split("/")[-1])
    print("> Count:\t"+str(len(resTab)))
    sourceList = {}
    elMatch = {}
    for line in resTab:
        try:
            sourceList[line[3]] += 1
        except:
            sourceList[line[3]] = 1
        try:
            elMatch[line[0]] += 1
        except:
            elMatch[line[3]] = 1
    print("> "+str(len(elMatch))+" elements in your IOC have triggered "+str(len(sourceList))+" source files:")
    for key in sourceList.keys():
        print("\t- "+key)
    i = 1
    for line in resTab:
        print("\nElement n°"+str(i)+": "+line[0])
        print("\t> Matches with: "+line[1])
        print("\t> File Type: "+line[2])
        print("\t> File PATH: "+line[3])
        print("\t> Threat Recon Attribution: "+line[4])
        i += 1

def checkMyMtgx(resTab, t):
    print("\n[+] Printing working base similarities with "+t.split("/")[-1])
    print("> Count:\t"+str(len(resTab)))
    sourceList = {}
    elMatch = {}
    for line in resTab:
        try:
            sourceList[line[3]] += 1
        except:
            sourceList[line[3]] = 1
        try:
            elMatch[line[0]] += 1
        except:
            elMatch[line[3]] = 1
    print("> "+str(len(elMatch))+" elements in your MTGX have triggered "+str(len(sourceList))+" source files:")
    for key in sourceList.keys():
        print("\t- "+key)
    i = 1
    for line in resTab:
        print("\nElement n°"+str(i)+": "+line[0])
        print("\t> Matches with: "+line[1])
        print("\t> File Type: "+line[2])
        print("\t> File PATH: "+line[3])
        print("\t> Threat Recon Attribution: "+line[4])
        i += 1

def compareMyIOC(fileMatch, t):
    print("\n[+] Printing number of similarities between "+t.split("/")[-1]+" and working base files")
    print("> Count:\t"+str(len(fileMatch)))

    i = 1
    for key, value in sorted(fileMatch.items(), key=operator.itemgetter(1), reverse=True):
        print("\n Element n°"+str(i)+": ")
        print("\t> Matched File: "+key)
        print("\t> Number of match: "+str(value))
        i += 1

def compareMyMtgx(fileMatch, t):
    print("\n[+] Printing number of similarities between "+t.split("/")[-1]+" and working base files")
    print("> Count:\t"+str(len(fileMatch)))

    i = 1
    for key, value in sorted(fileMatch.items(), key=operator.itemgetter(1), reverse=True):
        print("\n Element n°"+str(i)+": ")
        print("\t> Matched File: "+key)
        print("\t> Number of match: "+str(value))
        i += 1

def checkMyTxt(resTab, t, cpt):
    print("\n[+] Checking text file similarities")
    print("> Text file:           "+t.split("/")[-1])
    print("> Number of elements:    "+str(cpt))
    print("> "+str(len(resTab))+" similarities found!")

    bufferList = {}

    i = 0
    for sim in resTab:
        bufferList[sim[3]] = sim[2]
    print("> "+str(len(bufferList))+" source files have triggered:")
    for key, value in bufferList.items():
        print("     - ["+value+"] "+key.split("/")[-1])
    for sim in resTab:
        i += 1
        print("\n Similarity n°"+str(i))
        j = 0
        for el in sim:
            if j == 0:
                print("     > Txt Element:              "+el)
            elif j == 1:
                print("     > Working Bases:            "+el)
            elif j == 2:
                print("     > Type of WB Element:       "+el)
            elif j == 3:
                print("     > Source:                   "+el)
            elif j == 4:
                print("     > Threat Recon Attribution: "+el)
            j += 1
    print("\n[+] Checking text file similarities: Done!\n")

def compareMyTxt(fileMatch, t):
    print("\n[+] Printing number of similarities between "+t.split("/")[-1]+" and working base files")
    print("> Count:\t"+str(len(fileMatch)))

    i = 1
    for key, value in sorted(fileMatch.items(), key=operator.itemgetter(1), reverse=True):
        print("\n Element n°"+str(i)+": ")
        print("\t> Matched File: "+key)
        print("\t> Number of match: "+str(value))
        i += 1

def compareFile2Another(resTab,t1, t2):
    print("\n[+] Printing number of similarities between "+t1.split("/")[-1]+" and "+t2.split("/")[-1])    
    print("> Count:\t"+str(len(resTab)))

    i = 1
    for line in resTab:
        print("\n Element n°"+str(i)+": ")
        print("\t> Matched File1 Element:   "+line[0])
        print("\t> File1 Attribution:       "+line[2])
        print("\t> Matched File2 Element:   "+line[1])
        print("\t> File2 Attribution:       "+line[3])
        i += 1


