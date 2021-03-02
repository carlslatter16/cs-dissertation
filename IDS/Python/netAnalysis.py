#!/usr/bin/python3

capThreshold = 3
numThreshold = 2
lenThreshold = 8
domSrcThreshold = 5
abnormalityThreshold = 2

rootDomsDict = {}

capLogPath = 'file.txt'
capLogFile = open(capLogPath,'r')

def main():
    for line in capLogFile:
        subdomain=""
        i=0
        capCount=0
        numCount=0
        abnormalityCount=0
        capThresholdBool = False
        numThresholdBool = False
        domSrcNum = 0

        subdomain=""
        rootDom=""


        for char in line:
            if char != ".":
                subdomain+=char

                if char == "=":
                    base64Bool = True
                if char.isupper() == True:
                    capCount+=1
                    if capCount >= capThreshold: 
                        capThresholdBool = True
                if char.isnumeric() == True:
                    numCount+=1
                    if numCount >= numThreshold:
                        numThresholdBool = True
                i+=1 #iterate indexes
            else:
                break

        print("Subdomain Segment: ", subdomain)

        domRootIndex = i+1

        rootDom = ""

        newDomain = True

        for char in range(domRootIndex, len(line)): #writes after . to file - stores into rootDom
            if(line[char]!="\n"):
                rootDom += line[char]

        for domElementIndex in range(0, len(rootDomsDict.keys())): # for each key
            if rootDom==list(rootDomsDict.keys())[domElementIndex]: # if it matches an existing domain entry
                rootDomsDict[rootDom] += 1
                newDomain = False #avoids initilizing domain to 1

        if newDomain==True:
            rootDomsDict[rootDom] = 1
        
        print("Root Domain Segment: ", rootDom)

        #atm it has issues if it leaves the domain and goes back to it later!

        if len(subdomain) >= lenThreshold:
            print("   Abnormal length of subdomain fragment: ", end='')
            print(len(subdomain), end='')
            abnormalityCount+=1

        if base64Bool==True:
            base64Bool=False
            print("   Possible Base64! ( = Present) ", end='')
            abnormalityCount+=1

        if capThresholdBool==True:
            capThresholdBool = False
            print("   Abnormal occurances of capitals: ", end='')
            print(capCount, end='')
            abnormalityCount+=1

        if numThresholdBool==True:
            numThresholdBool = False
            print("   Abnormal occurances of numbers: ", end='')
            print(numCount, end='')
            abnormalityCount+=1
        

        #need global ab count too!

        if abnormalityCount>=abnormalityThreshold:
            print("\n")
            print("   # THIS IS LIKELY A MALICIOUS UDP DNS PACKET! # ")
            print("\n")
        else:
            print("   # THIS IS LIKELY NOT MALICIOUS DNS # ")
            print("\n")

         #-----------------------------Overall Analysis----------------------------------#

    for element in list(rootDomsDict.keys()): #domain checker
        domSrcNum = rootDomsDict[element]
        if domSrcNum >= domSrcThreshold:
            print("   Abnormal amount of request to the same root domain: ", end='')
            print(element, ": ",  end='')
            print(domSrcNum)
            abnormalityCount+=1


if __name__ == "__main__":
    main()
    