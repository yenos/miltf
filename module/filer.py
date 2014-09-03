import time

def getDate():
    return time.strftime("%Y%m%d")

def rulesByFlag(tab, t):
    print("\n[+] Creating the output file")
    folder  = "./output/"
    fn      ="[MILTF]WorkingBase_"+str(t)+"_"+getDate()+".txt" 
    f       = open(folder+fn, "w+")
    for line in tab:
        f.write(line[0]+";"+line[1]+";"+line[2]+";"+line[3]+";\n")
    print("{0} Wild "+folder+str(fn)+" appears!")
    print("[+] Creating the ouput file: Done!\n")

def searchDomain(tab, t, a):
    print("[+] Creating the output file")
    fn  = "[MILTF]SearchDomain_"+str(t.replace('.','-'))+"_"+getDate()+".txt" 
    folder  = "./output/"
    f   = open(folder+fn, 'w+')
    for line in tab:
        f.write(line[0]+";"+line[1]+";"+line[2]+";"+a+"\n")
    print("{0} Wild "+folder+str(fn)+" appears!")
    print("[+] Creating the output file: Done!")

def searchIP4(tab, t, a):
    print("[+] Creating the output file")
    fn  = "[MILTF]SearchIP4_"+str(t.replace('.','-'))+"_"+getDate()+".txt"
    folder  = "./output/"
    f   = open(folder+fn, 'w+')
    for line in tab:
        f.write(line[0]+";"+line[1]+";"+line[2]+";"+a+"\n")
    print("{0} Wild "+folder+str(fn)+" appears!")
    print("[+] Creating the output file: Done!")

def checkMyIOC(tab, t):
    print("\n[+] Creating the output file")
    fn  ="[MILTF]CheckIoc_"+str(t.split("/")[-1].replace(".",",")+"_"+getDate()+".txt") 
    folder  = "./output/"
    f   = open(folder+fn, "w+")
    for line in tab:
        f.write(line[0]+";"+line[1]+";"+line[2]+";"+line[3]+";"+line[4]+"\n")
    print("{0} Wild "+folder+str(fn)+" appears!")
    print("[+] Creating the ouput file: Done!\n")

def checkMyMtgx(tab, t):
    print("\n[+] Creating the output file")
    fn  ="[MILTF]CheckMtgx_"+str(t.split("/")[-1].replace(".","_")+"_"+getDate()+".txt") 
    folder  = "./output/"
    f   = open(folder+fn, "w+")
    for line in tab:
        f.write(line[0]+";"+line[1]+";"+line[2]+";"+line[3]+";"+line[4]+"\n")
    print("{0} Wild "+folder+str(fn)+" appears!")
    print("[+] Creating the ouput file: Done!\n")

def compareMyIOC(tab, t):
    print("\n[+] Creating the output file")
    fn  ="[MILTF]CompIoc_"+t.split("/")[-1].replace(".","_")+"_"+str(getDate())+".txt"
    folder  = "./output/"
    f   = open(folder+fn, "w+")
    for key, value in tab.items():
        f.write(key+";"+str(value)+";\n")
    print("{0} Wild "+folder+str(fn)+" appears!")
    print("[+] Creating the ouput file: Done!\n")

def compareMyMtgx(tab, t):
    print("\n[+] Creating the output file")
    fn  ="[MILTF]CompMtgx_"+t.split("/")[-1].replace(".","_")+"_"+str(getDate())+".txt"
    folder  = "./output/"
    f   = open(folder+fn, "w+")
    for key, value in tab.items():
        f.write(key+";"+str(value)+";\n")
    print("{0} Wild "+folder+str(fn)+" appears!")
    print("[+] Creating the ouput file: Done!\n")

def checkMyTxt(tab, t):
    print("\n[+] Creating the output file")
    fn  ="[MILTF]CheckTxt_"+t.split("/")[-1].replace(".","_")+"_"+str(getDate())+".txt"
    folder  = "./output/"
    f   = open(folder+fn, "w+")
    for line in tab:
        f.write(line[0]+";"+line[1]+";"+line[2]+";"+line[3]+line[4]+"\n")
    print("{0} Wild "+folder+str(fn)+" appears!")
    print("[+] Creating the ouput file: Done!\n")

def compareMyTxt(tab, t):
    print("\n[+] Creating the output file")
    fn  ="[MILTF]CompareTxt_"+t.split("/")[-1].replace(".","_")+"_"+str(getDate())+".txt"
    folder  = "./output/"
    f   = open(folder+fn, "w+")
    for key, value in tab.items():
        f.write(key+";"+str(value)+";\n")
    print("{0} Wild "+folder+str(fn)+" appears!")
    print("[+] Creating the ouput file: Done!\n")

def compareFile2Another(tab, t1, t2):
    print("\n[+] Creating the output file")
    fn  ="[MILTF]Compare_"+t1.split("/")[-1].replace(".","_")+"_"+t2.split("/")[-1].replace(".","_")+"_"+str(getDate())+".txt"
    folder  = "./output/"
    f   = open(folder+fn, "w+")
    for line in tab:
        f.write(line[0]+";"+line[1]+";\n")
    print("{0} Wild "+folder+str(fn)+" appears!")
    print("[+] Creating the ouput file: Done!\n")

