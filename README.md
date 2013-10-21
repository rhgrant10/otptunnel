OTPTunnel
=========

OTPTunnel is privacy software, written in Python, that creates an encrypted network tunnel between two hosts. It works by creating a TAP interface; packets read in from the TAP interface are stream XOR'ed using a 'one time pad' as the XOR key and transmitted as udp datagrams across a network.

#Installing

`pip install pynetlinux`

`git clone https://github.com/rpgraham84/otptunnel`

#How To Use
The idea is that two users would exchange a very large truly random keyfile before using OTPTunnel. Ideally, one would use a hardware random number generator based on some natural phenomenon like cosmic noise or radioactive decay. However, any file (yes, even a file full of zeros) can be used. The trouble with that of course being that any byte XOR 0 is the same byte.

The users then each take the same key to their respective endpoints on the network. For now, there can only be two participants. This will be changed soon so that the server can host multiple keyfiles and effectively serve as a router of a VPN. The server can be initiated as so:

`./otptunnel -S -K keyfile -A 1.2.3.4`

Where 1.2.3.4 is the client participant's ip. I know it's weird to have to specify this on the server but I will be changing this in the near future.

The client would then connect:

`./otptunnel -K keyfile -A 5.6.7.8 --tap-addr 10.8.0.2`

Where 5.6.7.8 is the server's ip. From this point forward, the two hosts can interact with one another via their TAP interfaces. If either the server or client has any services bound to their TAP IP address, or 0.0.0.0, they will be visible to the other party via that user's TAP. 

For instance, in many common Linux distros, OpenSSHD by default, binds to 0.0.0.0. Therefore, if the server were running sshd bound to 0.0.0.0, the client could connect at 10.8.0.1 (the default server TAP IP) port 22. 

#How It Works
The packets will be picked off the TAP at OSI layer 2 and have their 16-byte md5 sum appended to them. The original packet plus 16-byte checksum are XOR'ed with that participant's keyfile bytes. Basically, the server gets the even bytes, the client gets the odd bytes. Then, a  6-byte hex string representing the offset is appended to the packet so that the recipient knows where to seek to in the keyfile to begin decoding the packet. Finally, the packet is encapsulated with Ethernet, IP, and UDP headers and sent out on the wire over UDP port 12000.

#Note From The Author

Please feel free to modify this source to your liking and submit a pull-request! I've tried to maintain good PEP8 formatting throughout the code and comment wherever possible so that anyone can understand it. One key motivation for me in doing this project is to bring cryptography back down to an easily digestable and highly customizable system for experimenters, students and hobbyists from

#TODO: (as of 10/21/2013)

* Make web interface for monitoring state information, modifying configuration, adding new keys, etc.
* Make OTPTunnel pip installable. Make debian-style init script for launching otptunnel as daemon.
