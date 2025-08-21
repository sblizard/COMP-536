import os

#generate a long key using good randomness
key = os.urandom(10000)

#use this to keep track of how much of the one time pad we've used
usedBytes = 0

with open("texts.txt", 'r') as file:
    for line in file:

        #empty lines separate the texts in the input
        if not line.strip():
            #print a blank line between ciphertexts in the output
            print("")
            #start over because we're going to be encrypting a new text
            usedBytes=0
            continue
        
        #convert the line to bytes
        bytesLine = bytes(line, 'utf-8')

        #encrypt using OTP
        encryptedLine = bytes(a^b for (a,b) in zip(bytesLine, key[usedBytes:]))
        usedBytes += len(line)

        #print out the encrypted line
        print(encryptedLine.hex())