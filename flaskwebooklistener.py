# Libraries
from pprint import pprint
from flask import Flask, json, request, render_template
import sys, os, getopt, json
from flask.sessions import SecureCookieSession
import requests
import meraki
import time
import shutil
import datetime
import credentials
import pdb

Meraki_BaseURL = credentials.MERAKI_BASEURL
Meraki_Headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "X-Cisco-Meraki-API-Key": credentials.MERAKI_API_KEY
    }

#isolation payload to apply firewall rules in the create_isolation_policy function
isolation_payload = json.dumps({
            "name": "Isolation",
            "firewallAndTrafficShaping": {
            "settings": "custom",
            "trafficShapingRules": [],
            "l3FirewallRules": [
                {
                    "comment": "Allow DNS",
                    "policy": "allow",
                    "protocol": "udp",
                    "destPort": "53",
                    "destCidr": "any"
                },
                {
                    "comment": "RFC 1918",
                    "policy": "deny",
                    "protocol": "any",
                    "destPort": "Any",
                    "destCidr": "192.168.0.0/16"
                },
                {
                    "comment": "RFC 1918",
                    "policy": "deny",
                    "protocol": "any",
                    "destPort": "Any",
                    "destCidr": "172.16.0.0/12"
                },
                {
                    "comment": "RFC 1918",
                    "policy": "deny",
                    "protocol": "any",
                    "destPort": "Any",
                    "destCidr": "10.0.0.0/8"
                }
            ],
  }
})

#returns clients that are connected to MX Appliance
def get_clients(serial):
    networkdown = True
    while networkdown == True:
        try:
            response = requests.request('GET', Meraki_BaseURL + "/devices/" + serial + "/clients" , headers=Meraki_Headers , data = {})
            networkdown = False
            return response.json()
        except:
            time.sleep(5)

#returns security events found network within the past 2 minutes
def getclientsecurityevents(network_id, client_id):
    networkdown = True
    while networkdown == True:
        try:
            response = requests.request('GET', Meraki_BaseURL + "/networks/"+ network_id + "/appliance/clients/"+ client_id +"/security/events", headers=Meraki_Headers, data = {})
            networkdown = False
            return response.json()
        except:
            time.sleep(5)


#checks if network is track by mac or track by ip
def get_appliance_settings(network_id):
    networkdown = True
    while networkdown == True:
        try:
            response = requests.request('GET', Meraki_BaseURL + "/networks/" + network_id + "/appliance/settings" , headers=Meraki_Headers , data = {})
            networkdown = False
            return response.json()
        except:
            time.sleep(5)



#create isolation policy
def create_isolation_policy(network_id):
    networkdown = True
    while networkdown == True:
        try:
            response = requests.request('POST', Meraki_BaseURL + "/networks/" + network_id + "/groupPolicies", headers = Meraki_Headers, data = isolation_payload)
            networkdown = False
            return response.json()
        except:
            time.sleep(5)    

#verify isolation policy exists and gets group policy ID on network 
#if policy doesnt exsist creates isolation and returns group policy ID
def verify_isolation_policy(network_id):
    networkdown = True
    while networkdown == True:
        try:
            response = requests.request("GET", Meraki_BaseURL + "/networks/" + network_id + "/groupPolicies", headers = Meraki_Headers, data = {})
            networkdown = False
        except:
            time.sleep(5)   
    response = response.json()
    for policy in response:
        if policy["name"] == "Isolation":
            print("Isolation Policy Verified on network ID " + network_id)
            return policy["groupPolicyId"]
        else:
            print("Isolation Policy Does Not Exist On This Network Creating Policy")
            create_isolation_policy(network_id)
            networkdown = True
            while networkdown == True:
                try:
                    response = requests.request("GET", Meraki_BaseURL + "/networks/" + network_id + "/groupPolicies", headers = Meraki_Headers, data = {})
                    networkdown = False
                except:
                    time.sleep(5)
            response = response.json()
            for policy in response:
                if policy["name"] == "Isolation":
                    return policy["groupPolicyId"]


# Takes group policy ID and Applies Isolation Policy to Client
def apply_isolation(client_list, network_id, group_policy_Id):
    
    settings = get_appliance_settings(network_id)
    if settings["clientTrackingMethod"] == "MAC address":
        
        for client in client_list:
            payload = json.dumps(
                {
                    "mac": client[0]['client_mac'],
                    "devicePolicy": "Group policy",
                    'groupPolicyId':str(group_policy_Id) 
                    })
            response = requests.request('PUT', Meraki_BaseURL + "/networks/" + network_id + "/clients/" + client[0]["client_id"] + "/policy" , headers=Meraki_Headers , data = payload)
            print("isolation applied to client" + client[0]['client_mac'])
        return "Isolation policy applied"
    else:
        return "failed to apply policy"








# Flask App
app = Flask(__name__)
seen_alerts = []
webhook_data = []
# Webhook Receiver Code - Accepts JSON POST from Meraki and
@app.route("/", methods=["POST"])
def get_webhook_json():
    #global webhook_data
    #global seen_alerts
    start_time = time.time()

    # Webhook Receiver
    webhook_data_json = request.json 
    #pprint(webhook_data_json, indent=1)
    webhook_data = json.dumps(webhook_data_json)
    # WebEx Teams can only handle so much text so limit to 1000 chars
    webhook_data = webhook_data[:1000] + '...'

    # Gather Alert Data
    alert_data = []
    alert_type = webhook_data_json['alertType']
    alert_id = webhook_data_json['alertId']
    organization_name = webhook_data_json['organizationName']
    network_name = webhook_data_json['networkName']
    network_id = webhook_data_json['networkId']
    serial_id = webhook_data_json['deviceSerial']
    alert_data.extend([alert_type, alert_id, organization_name, network_name])
    timestamp = webhook_data_json['occurredAt']
    
    
    #Avoid duplicate Alert IDs
    if 1 == 1:
    #if alert_id not in seen_alerts:
        #seen_alerts.append(alert_id)

        # Find client for malware alert
        #WEBHOOK ALERT TO NOTIFY CLIENT DOWNLOADED MALWARE
        print("Webhook Received Begining Isolation")
        group_policy = verify_isolation_policy(network_id= network_id)  
        if alert_type == "Power supply went down": #!!!!!!!!!test solution to be changd to "Malware Downloaded!!!!!!!!"
            print('webhook recieved isolation has started')
            Net_Clients = get_clients(serial = "Q3FA-RY3M-KUVT") #!!!!!!serial to equal serial_id!!!!!!!!!!!
            client_list = []
            
            #for loop
            for client in Net_Clients: 
                client_list.append(client["id"]) 
            #pprint(client_list)
            security_alerts = []
            for id in client_list:
                security_alerts.append(getclientsecurityevents(network_id= network_id, client_id = id))
            #pprint(security_alerts)    
            malware_clients =[]
            for alert in security_alerts:
                if alert == []:
                    pass
                else:
                    for x in alert:
                        try:
                            if x == 'errors':
                                pass
                            elif x['blocked'] == False: #!!!!!!!!!downloaded to replace blocked!!!!!!!!!!
                                malware_clients.append(x["clientMac"])

                        except:
                            pass
            client_list = []            
            for client in Net_Clients:
                if client["mac"] in malware_clients:
                    client_list.append([ {"client_id": client["id"],"client_mac": client["mac"]} ])
                else:
                    pass

            
            apprun = apply_isolation(client_list = client_list, network_id = network_id, group_policy_Id = group_policy)
             #once client is identified apply isolation policy
            #Isolation ploicy must be verified to exist on the network otherwise it will be created#Isolation Policy Can now be applied



    return "WebHook POST Received"




def main(argv):
    try:
        opts, args = getopt.getopt(argv, "hs:", ["secret="])
    except getopt.GetoptError:
        print("receiver.py -s <secret>")
        sys.exit(2)
    for opt, arg in opts:
        if opt == "-h":
            print("receiver.py -s <secret>")
            sys.exit()
        elif opt in ("-s", "--secret"):
            secret = arg

    print("secret: " + secret)



if __name__ == "__main__":
    seen_alerts = []
    main(sys.argv[1:])
    app.run(host="0.0.0.0", port=5000, debug=True)

