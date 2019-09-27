import sys

def shiftAndKeep(val, shift, keep):
    keepMask = 0
    tempKeep = keep
    while tempKeep > 0:
        keepMask <<= 1
        keepMask += 1
        tempKeep -= 1
    return (val >> shift) & keepMask

def time(timeBytes, highResByte = None):
    seconds = 2 * shiftAndKeep(timeBytes, 0, 5)
    minutes = shiftAndKeep(timeBytes, 5, 6)
    hours = shiftAndKeep(timeBytes, 11, 5)
    
    if highResByte != None:
        milliseconds = highResByte * 10
        if milliseconds >= 1000:
            seconds += 1
            milliseconds -= 1000
        return "%02d:%02d:%02d.%03d" % (hours, minutes, seconds, milliseconds)
    else:
        return "%02d:%02d:%02d" % (hours, minutes, seconds)

def date(dateBytes):
    day = shiftAndKeep(dateBytes, 0, 5)
    month = shiftAndKeep(dateBytes, 5, 4)
    year = shiftAndKeep(dateBytes, 9, 7) + 1980
    
    return "%02d-%02d-%04d" % (day, month, year)

dirCluster = 0
if sys.argv[1] == "r":
    dirCluster = 19
else:
    dirCluster = 33 + int(sys.argv[1]) - 2

file = open("Files/image.dat", "rb")

clusterSize = 512
file.seek(dirCluster * clusterSize)

separator = "----------------------------"

rawData = file.read(32)
intData = int.from_bytes(rawData, byteorder="little")
while intData != 0:
    # Skip if a long name
    attributes = shiftAndKeep(intData, 11 * 8, 1 * 8)
    attrString = ""
    if attributes & 0xF == 0xF:
        rawData = file.read(32)
        intData = int.from_bytes(rawData, byteorder="little")
        continue
    
    print("\n" + separator)
    firstChar = intData & 0xFF
    if firstChar == 0x2E:
        print("Dot entry")
    elif firstChar == 0xE5 or firstChar == 0x05:
        print("Entry erased\n")
        strData = rawData[1:11].decode("ascii")
        print("." + strData[0:6] + "." + strData[7:10])
    else:
        strData = rawData[0:11].decode("ascii")
        print(strData[0:7] + "." + strData[8:11])
    
    # Attributes
    if attributes & 0x01:
        attrString = attrString + "Read only; "
    if attributes & 0x02:
        attrString = attrString + "Hidden; "
    if attributes & 0x04:
        attrString = attrString + "System; "
    if attributes & 0x08:
        attrString = attrString + "Volume label; "
    if attributes & 0x10:
        attrString = attrString + "Subdirectory; "
    if attributes & 0x20:
        attrString = attrString + "Archive; "
    if attributes & 0x40:
        attrString = attrString + "Device; "
    
    if attrString == "":
        print("No special attributes")
    else:
        print("Attributes: " + attrString)
    
    
    # Time
    createHighRes = shiftAndKeep(intData, 13 * 8, 1 * 8)
    createTime = shiftAndKeep(intData, 14 * 8, 2 * 8)
    createDate = shiftAndKeep(intData, 16 * 8, 2 * 8)
    accessDate = shiftAndKeep(intData, 18 * 8, 2 * 8)
    modTime = shiftAndKeep(intData, 22 * 8, 2 * 8)
    modDate = shiftAndKeep(intData, 24 * 8, 2 * 8)
    
    print("Created At: " + time(createTime, createHighRes) + " on " + date(createDate))
    print("Modified At: " + time(modTime) + " on " + date(modDate))
    print("Accessed On: " + date(accessDate))
    
    # Cluster
    fileCluster = shiftAndKeep(intData, 26 * 8, 2 * 8)
    print("First cluster: 0x%03X (%4d)" % (fileCluster, fileCluster))
    
    # File size
    fileSize = shiftAndKeep(intData, 28 * 8, 4 * 8)
    print("Size: %d bytes" % (fileSize))
    
    rawData = file.read(32)
    intData = int.from_bytes(rawData, byteorder="little")

file.close()