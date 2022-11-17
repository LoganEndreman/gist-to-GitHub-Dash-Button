from scapy.all import *
import requests
import time
MAGIC_FORM_URL = 'https://webhook.site/8add6b7b-2898-4270-b285-614d6b3f0583'

def record_nope():
  data = {
    "Timestamp": time.strftime("%Y-%m-%d %H:%M"), 
    "Measurement": 'Try again. Lock not open.'
  }
  requests.post(MAGIC_FORM_URL, data=data)

def record_yes():
  data = {
    "Timestamp": time.strftime("%Y-%m-%d %H:%M"), 
    "Measurement": 'The key is AB.'
  }
  requests.post(MAGIC_FORM_URL, data=data)

def arp_display(pkt):
  timestamp = time.strftime("%Y-%m-%d %H:%M")
  if pkt[ARP].op == 1: #who-has (request)
    if pkt[ARP].psrc == '0.0.0.0': # ARP Probe
      if pkt[ARP].hwsrc == '74:75:48:5f:99:30': # Huggies       
        record_nope()
        time.sleep(10.0)
      elif pkt[ARP].hwsrc == '74:75:48:5f:99:30':
       record_yes() 
      else: 
        print "ARP Probe from unknown device: " + pkt[ARP].hwsrc
        print "Kag tmhq qeombqp!"

print sniff(prn=arp_display, filter="arp", store=0, count=10)
 
