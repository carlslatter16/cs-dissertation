#!/usr/bin/python3

capThreshold = 3
numThreshold = 2
lenThreshold = 8
domSrcThreshold = 5
srcIPThreshold = 10
dstIPThreshold = 10
abnormalityThreshold = 2
caseChangeThreshold=4

rootDomsDict = {}
srcIPDict = {}
dstIPDict = {}

capLogPath = 'file.txt'
capLogFile = open(capLogPath,'r')

def main():
    for line in capLogFile:
        subdomain=""
        i=0
        capCount=0
        caseChangeCount=0
        numCount=0
        abnormalityCount=0
        capThresholdBool = False
        numThresholdBool = False
        caseChangeThresholdBool = False
        domSrcNum = 0
        srcIPNum= 0
        dstIPNum = 0
        subdomain=""
        rootDom=""
        prevCap=""
        srcIP=""
        dstIP=""


        for char in line:
            
            if char != ".":
                subdomain+=char

                if char.isalpha():
                    if (prevCap == "UPPER" and char.islower() == True) or (prevCap == "LOWER" and char.isupper() == True):
                        caseChangeCount += 1
                        if caseChangeCount >= caseChangeThreshold:
                            caseChangeThresholdBool = True
                        
                if char == "=":
                    base64Bool = True
                if char.isupper() == True:
                    capCount+=1
                    prevCap = "UPPER"
                    if capCount >= capThreshold: 
                        capThresholdBool = True
                elif char.islower() == True:
                    prevCap = "LOWER"

                if char.isnumeric() == True:
                    numCount+=1
                    if numCount >= numThreshold:
                        numThresholdBool = True
            else:
                break

        print("Subdomain Segment: ", subdomain)

        domRootIndex = len(subdomain)+1

        newDomain = True


        for char in range(domRootIndex, len(line)): #writes after . to file - stores into rootDom - need to adjust to go to a : and stop
            if(line[char]!=":"):
                rootDom += line[char]
                
            else:
                break

        for domElementIndex in range(0, len(rootDomsDict.keys())): # for each key
            if rootDom==list(rootDomsDict.keys())[domElementIndex]: # if it matches an existing domain entry
                rootDomsDict[rootDom] += 1
                newDomain = False #avoids initilizing domain to 1

        if newDomain==True:
            rootDomsDict[rootDom] = 1
        
        print("Root Domain Segment: ", rootDom)

        #------------------------------------------------------------------------------------------#
        srcIPIndex=len(subdomain)+len(rootDom)+2 #+2 to bypass the delimeters!

        for char in range(srcIPIndex, len(line)): 
            if(line[char]!=":"):
                srcIP += line[char]
            else:
                break
                
        dstIPIndex=len(subdomain)+len(rootDom)+len(srcIP)+3 #+3 to bypass the delimeters!


        for char in range(dstIPIndex, len(line)): 
            if(line[char]!=":"):
                dstIP += line[char]
            else:
                break

        print("Source: ", srcIP)
        print("Destination: ", dstIP)
        #------------------------------------------------------------------------------------------#
        newSrcIP = True
        newDstIP = True

        for srcIPIndex in range(0, len(srcIPDict.keys())): # for each key
            if srcIP==list(srcIPDict.keys())[srcIPIndex]: # if it matches an existing domain entry
                srcIPDict[srcIP] += 1
                newSrcIP = False #avoids initilizing domain to 1

        if newSrcIP==True:
            srcIPDict[srcIP] = 1

        for dstIPIndex in range(0, len(dstIPDict.keys())): # for each key
            if dstIP==list(dstIPDict.keys())[dstIPIndex]: # if it matches an existing domain entry
                dstIPDict[dstIP] += 1
                newDstIP = False #avoids initilizing domain to 1

        if newDstIP==True:
            dstIPDict[dstIP] = 1

        #------------------------------------------------------------------------------------------#
        if len(subdomain) >= lenThreshold:
            print("   Abnormal length of subdomain fragment: ", end='')
            print(len(subdomain), end='')
            abnormalityCount+=1

        if base64Bool==True:
            print("   Possible Base64! ( = Present) ", end='')
            abnormalityCount+=1

        if capThresholdBool==True:
            print("   Abnormal occurances of capitals: ", end='')
            print(capCount, end='')
            abnormalityCount+=1

        if numThresholdBool==True:
            print("   Abnormal occurances of numbers: ", end='')
            print(numCount, end='')
            abnormalityCount+=1
        

        if caseChangeThresholdBool==True:
            print("   Abnormal occurances of case changes: ", end='')
            print(caseChangeCount, end='')
            abnormalityCount+=1

        #need global ab count too!

        if abnormalityCount>=abnormalityThreshold:
            print("\n")
            print("   # THIS IS LIKELY A MALICIOUS UDP DNS PACKET! # ")
            print("\n")
        else:
            print("   # THIS IS LIKELY NOT MALICIOUS DNS # ")
            print("\n")


    print("#------------------------------ OVERALL ANALYSIS -----------------------------------#")

    for element in list(rootDomsDict.keys()): #domain checker
        domSrcNum = rootDomsDict[element]
        if domSrcNum >= domSrcThreshold:
            print("   Abnormal amount of request to the same root domain: ", end='')
            print(element, ": ",  end='')
            print(domSrcNum)

    for element in list(srcIPDict.keys()): #SrcIP checker
        srcIPNum = srcIPDict[element]
        if srcIPNum >= srcIPThreshold:
            print("   Abnormal amount of suspicious traffic from: ", end='')
            print(element, ": ",  end='')
            print(srcIPNum)

    for element in list(dstIPDict.keys()): #DstIP checker 
        dstIPNum = dstIPDict[element]
        if dstIPNum >= dstIPThreshold:
            print("   Abnormal amount of suspicious traffic to: ", end='')
            print(element, ": ",  end='')
            print(dstIPNum)

        #NEED SOME FLAG OF SUSPICOUS TRAFFIC - One of these might be off a tad too, but could be a mistake in the data!

if __name__ == "__main__":
    main()
    