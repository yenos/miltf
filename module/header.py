import os

def header():
    os.system(['clear', 'cls'][os.name == 'nt'])
    for line in open("ressource/header.ascii"):
        print(line.strip())
