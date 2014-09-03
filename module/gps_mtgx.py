import os
import fnmatch

def gps_mtgx(searchin):
    match = []
    for root, dirnames, filenames in os.walk(searchin):
        for filename in fnmatch.filter(filenames, "*.mtgx"):
            match.append(os.path.join(root, filename))
    return match
