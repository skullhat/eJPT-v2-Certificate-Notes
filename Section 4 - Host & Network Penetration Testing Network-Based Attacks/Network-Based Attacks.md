## How To Use [Wireshark](https://www.wireshark.org/docs/)

``` bash
wireshark
```

## [Tshark](https://tshark.dev/) 


``` bash
tshark -h | more
trshark -D
#  checking the available interface for TShark

tshark -i eth0
# specify the interface

tshark -i eth0 -c 10
# If we want we can limit the capture limit to few packets using the -c

tshark -c 500 -w mycapture.pcap
# to save the capture to a file, say mycapture.pcap


tshark -r mycapture.pcap
# To read the above file


tshark -i eth0 -c 10 host google.com
#Specifying a Target Host
# _**Note:** We can also use the IP address of the host instead of the hostname

tshark -i eth0 src host google.com
#To filter out the incoming traffic


tshark -i eth0 dst host google.com
# to filter out outgoing traffic

tshark -r p2/packet_dumps/packet_dump-$file_id -z io,phs,$filter | grep radiotap
# &
tshark -r file.pcap -R <filter> | wc -l
# get number of packets displayed

tshark -qz io,stat,30,"COUNT(frame) frame"

tshark -r file.pcap  -T fields -e frame.protocols
# list of protocols

-Y 'http'
tshark -r HTTP_traffic.pcap -Y 'ip.src==192.168.252.128 && ip.dst==52.32.74.91'

tshark -r HTTP_traffic.pcap -Y 'http.request.method==GET'

tshark -r HTTP_traffic.pcap -Y 'http.request.method==GET' -Tfields -e frame.tine -e ip.src -e http.reqest.full_uri | more

tshark -r HITP_traffic.pcap -Y 'http contains password'

tshark -r HTTP_traffic.pcap -Y 'http.request.method==GET && http.host==www.nytimes.com' -Tfields -e ip.dst

tshark -r HTTP_traffic.pcap -Y 'ip contains amazon.in && ip.src==192.168.252.128' -Tfields -e ip.src -e http.cookie

tshark -r HTTP_traffic.pcap -Y 'ip.src==192.168.252.128 && http' -Tfields -e http.user_agent
```


## ARP Poisoning

Address Resolution Protocol (ARP) is a protocol that enables network communications to reach a specific device on the network. ARP translates Internet Protocol (IP) addresses to a Media Access Control (MAC) address, and vice versa. Most commonly, devices use ARP to contact the router or gateway that enables them to connect to the Internet.

An ARP spoofing, also known as ARP poisoning, is a [Man in the Middle](https://www.imperva.com/learn/application-security/man-in-the-middle-attack-mitm/) (MitM) attack that allows attackers to intercept communication between network devices. The attack works as follows:

1.  The attacker must have access to the network. They scan the network to determine the IP addresses of at least two devices⁠—let’s say these are a workstation and a router. 
2.  The attacker uses a spoofing tool, such as Arpspoof or Driftnet, to send out forged ARP responses. 
3.  The forged responses advertise that the correct MAC address for both IP addresses, belonging to the router and workstation, is the attacker’s MAC address. This fools both router and workstation to connect to the attacker’s machine, instead of to each other.
4.  The two devices update their ARP cache entries and from that point onwards, communicate with the attacker instead of directly with each other.
5.  The attacker is now secretly in the middle of all communications.

```bash
arpspoof -i eth1 -t 10.100.13.37 -r 10.100.13.36
telnet 10.100.13.36

```

## [WiFi Analysis](https://tbhaxor.com/wifi-traffic-analysis-in-wireshark/)

```bash
# What is the name of the Open (No Security) SSID present in the packet dump?
wlan.fc.type == 0x0 && wlan.fc.type_subtype == 0x8 && wlan.fixed.capabilities.privacy == 0

# The SSID 'Home_Network' is operating on which channel?
wlan.ssid == "Home_Network"

# Which security mechanism is configured for SSID 'LazyArtists'? Your options are: OPEN, WPA-PSK, WPA2-PSK.

# Is WiFi Protected Setup (WPS) enabled on SSID 'Amazon Wood'? State Yes or No

wlan.ssid contains "Amazon Wood"
# -> Yes


# What is the total count of packets which were either transmitted or received by the device with MAC e8:de:27:16:87:18?

# The display filter you can use in this case (without quoting the MAC address value) is

wlan.ta == e8:de:27:16:87:18 || wlan.ra == e8:de:27:16:87:18

# What is the MAC address of the station which exchanged data packets with SSID 'SecurityTube_Open'?
wlan.fc.type_subtype == 0x20 && wlan.ra == e8:de:27:16:87:18

#  From the last question, we know that a station was connected to SSID 'SecurityTube_Open'. Provide TSF timestamp of the association response sent from the access point to this station.
wlan.ta == e8:de:27:16:87:18 && wlan.ra == 5c:51:88:31:a0:3b && wlan.fc.type_subtype == 0x1


# The BSSID 00:0d:67:3d:4a:49 is operating in which country? Provide the standard two character country code e.g. US, UK.

# -> IN (India)

# How many clients tried to connect with SSID ‘Ruther_SSID’? Consider all connection attempts and not only the successful connections.
wlan.ssid == "Ruther_SSID" && wlan.fc.type_subtype == 0x0

# -> 3

# Is it possible to launch a passphrase cracking attack on SSID ‘Amazon’? State Yes or No.

wlan.bssid == 3c:1e:04:2a:08:4f && eapol
# -> yes

# What is the name of the SSID which is using WPA/WPA2-Enterprise security scheme?
wlan.fc.type_subtype == 0x08 && wlan.rsn.akms.type == 1

#-> Example


# A device tried to connect to the SSID mentioned in Q1. What is the MAC address of that device?
wlan.fc.type_subtype == 0x0 && wlan.ssid == "Example"

# 00:25:86:e7:c4:d8

# A device tried to connect to the SSID mentioned in Q1. Was the connection attempt successful? State Yes or No.
 (wlan.fc.type_subtype == 0x0 || wlan.fc.type_subtype == 0x1 || wlan.fc.type_subtype == 0xb) && wlan.ssid == "Example"
# -> No

# What kind of EAP (Extended Authentication Protocol) is used by the SSID? Provide answer in form of abbreviation.
wlan.ta == 1c:7e:e5:97:79:b1 && eap && !(eap.type == 0x1)
#PEAP

# A deauthentication broadcast message was transmitted by the BSSID 1c:7e:e5:97:79:b1. Provide the time in UTC in DD/MM/YYYY HH:MM:SS format.
wlan.sa == 1c:7e:e5:97:79:b1 && wlan.fc.type_subtype == 0xc

# -> 14/03/2018 12:16:49
```




> 	💡 If you use the `==` operator to filter the SSID in wireshark, it will not show any packets because it is performing strict equality. The SSID name in the pcap file has a trailing whitespace. Therefore, you are supposed to use `**wlan.ssid contains "Amazon Wood"**` filter.