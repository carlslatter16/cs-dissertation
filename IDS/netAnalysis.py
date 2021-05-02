import time #credit - https://docs.python.org/3/library/time.html

#!/usr/bin/python3

#Best Usage: python3 netAnalysis.py > analysis.log

#Parameters that can change the accuracy of detection - Mode also can be used to alter weightings - Future project scope for parameter choice.
capThreshold = 3
numThreshold = 2
lenThreshold = 10
domSrcThreshold = 5
srcIPThreshold = 10
dstIPThreshold = 10
caseChangeThreshold=4
strictMode=True
rootDomsDict = {}
srcIPDict = {}
dstIPDict = {}

#Log created from the capture engine
capLogPath = 'rawCap.log'
capLogFile = open(capLogPath,'r')

def main():
    totalAbnormalities = malCount = totalPackets = 0

    for line in capLogFile:
        #Resetting many variables at a time to the end value
        capThresholdBool = numThresholdBool = base64Bool = caseChangeThresholdBool = False
        abnormalityWeight = abnormalityCount = numCount = caseChangeCount = capCount = domSrcNum = srcIPNum  = dstIPNum = 0
        subdomain = rootDom = prevCap = srcIP = dstIP = unixTime = ""


        for char in line:
            
            if char != ".":
                subdomain+=char

                if char.isalpha():
                    if (prevCap == "UPPER" and char.islower() == True) or (prevCap == "LOWER" and char.isupper() == True):  #logic to sense case changes
                        caseChangeCount += 1
                        if caseChangeCount >= caseChangeThreshold:
                            caseChangeThresholdBool = True
                        
                if char == "=" or char == "/" or char == "+": #base64 chars
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
        
        print("┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅")
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
        unixTimeIndex=len(subdomain)+len(rootDom)+len(srcIP)+len(dstIP)+4 #+3 to bypass the delimeters!
        for char in range(unixTimeIndex, len(line)): 
            if(line[char]!="\n"):
                unixTime += line[char]
            else:
                break

        print("Timestamp :", time.ctime(int(unixTime))) #used a module as there was little reason to reinvent the wheel and it is pretty base to the language use


        #------------------------------------------------------------------------------------------#
        if len(subdomain) >= lenThreshold:
            print("   Abnormal length of subdomain fragment: ", end='')
            print(len(subdomain), end='')
            abnormalityWeight+=3
            abnormalityCount+=1

        if base64Bool==True:
            print("   Possible Base64! ( = or + or / Present) ", end='')
            abnormalityWeight+=5
            abnormalityCount+=1

        if capThresholdBool==True:
            print("   Abnormal occurances of capitals: ", end='')
            print(capCount, end='')
            abnormalityWeight+=2
            abnormalityCount+=1

        if numThresholdBool==True:
            print("   Abnormal occurances of numbers: ", end='')
            print(numCount, end='')
            abnormalityWeight+=3       
            abnormalityCount+=1
        

        if caseChangeThresholdBool==True:
            print("   Abnormal occurances of case changes: ", end='')
            print(caseChangeCount, end='')
            abnormalityWeight+=1
            abnormalityCount+=1
        
        if strictMode==True: #Mode weighting setting
            abnormalityScoreThreshold = 7
        else:
            abnormalityScoreThreshold = 12
 
        if abnormalityWeight>=abnormalityScoreThreshold:
            malCount+=1
            print("\n")
            print("   # THIS IS LIKELY A MALICIOUS UDP DNS PACKET! - Score: ",abnormalityWeight,"#", end='')
            print("\n")
        else:
            print("\n")
            print("   # THIS IS LIKELY NOT A MALICIOUS DNS Packet! - Score: ",abnormalityWeight,"#", end='')
            print("\n")


        totalAbnormalities += abnormalityCount #keep a running total before later reset for next line
        totalPackets +=1

    print("┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅\n")
     

    print("▆▆▆▆▆▆▆▆▆▆▆▆▆▆▆▆▆▆▆▆▆▆▆▆▆▆▆▆▆▃ OVERALL ANALYSIS ▃▆▆▆▆▆▆▆▆▆▆▆▆▆▆▆▆▆▆▆▆▆▆▆▆▆▆▆")
    if(strictMode==True):
        print("▆ Analysis Weighting Mode: STRICT")
    else:
        print("▆ Analysis Weighting Mode: LITE")
    
    print("▆ Timestamp:", time.ctime())  #https://www.programiz.com/python-programming/time
    print("▆ Total packets in capture: ", totalPackets)
    print("▆ Total suspicous packets in capture: ", malCount)
    print("▆ Total abnormalities in capture: ", totalAbnormalities)

    for element in list(rootDomsDict.keys()): #domain checker
        domSrcNum = rootDomsDict[element]
        if domSrcNum >= domSrcThreshold:
            print("▆ WARNING - Excessive requests to the same root domain: --- ", end='')
            print(element, ": ",  end='')
            print(domSrcNum)

    if totalAbnormalities>=totalPackets/4:
        for element in list(srcIPDict.keys()): #SrcIP checker
            srcIPNum = srcIPDict[element]
            if srcIPNum >= srcIPThreshold:
                print("▆ INVESTIGATE - Excessive traffic from: --- ", end='')
                print(element, ": ",  end='')
                print(srcIPNum)

        for element in list(dstIPDict.keys()): #DstIP checker 
            dstIPNum = dstIPDict[element]
            if dstIPNum >= dstIPThreshold:
                print("▆ INVESTIGATE - Excessive traffic to: --- ", end='')
                print(element, ": ",  end='')
                print(dstIPNum)
    

    print("▆▆▆▆▆▆▆▆▆▆▆▆▆▆▆▆▆▆▆▆▆▆▆▆▆▆▆▆▆▆▆▆▆▆▆▆▆▆▆▆▆▆▆▆▆▆▆▆▆▆▆▆▆▆▆▆▆▆▆▆▆▆▆▆▆▆▆▆▆▆▆▆▆\n\n")

if __name__ == "__main__":
    main()
    