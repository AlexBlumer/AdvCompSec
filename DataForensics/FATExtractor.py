

file = open("Files/image.dat", "rb")

file.seek(0x200)

currentCluster = 0
data = file.read(3)
prevData = 0
data = int.from_bytes(data, byteorder="little")
while data != 0:
    dataLo = data & 0xFFF
    dataHi = data >> 12
    prevDataLo = prevData & 0xFF
    prevDataHi = prevData >> 12

    # Seems that the data is generally sequential, so raise a flag if the data doesn't fit
    if prevDataHi + 1 != dataLo or dataLo + 1 != dataHi:
        print("!!! Non-sequential area")
    print("%3d: 0x%03X 0x%03X" % (currentCluster, dataLo, dataHi))
    currentCluster += 2
    prevData = data
    data = file.read(3)
    data = int.from_bytes(data, byteorder="little")
