import sys

start = 291 * 512
fileSize = int(sys.argv[1])

bytesPerRead = 512

readFile = open("Files/image.dat", "rb")
readFile.seek(start)
writeFile = open("out.zip", "wb")

bytesRemaining = fileSize
while bytesRemaining > 0:
    bytesToRead = bytesPerRead if (bytesPerRead < bytesRemaining) else bytesRemaining
    bytes = readFile.read(bytesToRead)
    writeFile.write(bytes)
    bytesRemaining -= bytesToRead

readFile.close()
writeFile.close()
    