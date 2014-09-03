import os
import fnmatch

def gps_ioc(searchin):
    match = []
    for root, dirnames, filenames in os.walk(searchin):
        for filename in fnmatch.filter(filenames, '*.ioc'):
            match.append(os.path.join(root, filename))
    return match
