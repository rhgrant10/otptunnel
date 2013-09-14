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

#TODO: (as of 9/13/2013)

##Immediate

*  Fix server init code so that a remote ip doesn't have to be specified server-side but can be inferred from successfully reading a control packet.
*  Give server `OTPTunnel` a `clients` object to track keyfiles and offsets for clients that it accepts.
*  Make OTP object aware of the last decode offset used during every `OTP.decode()` call. This way, the recipient of a packet can reject it if it has a lower offset than the most recent one used.
*  Introduce packet padding. At the beginning of every `OTP.encode()` call, the first byte at `OTP._current_encode_seek` is used as a random number 0-255 that will be the number of random bytes of padding prepended to the packet. The prepended bytes are taken from /dev/urandom so as to not waste keyfile. This is to defend against plaintext correlation based on every encrypted packet being predictably longer than it's plaintext counterpart.
*  Introduce a "burning mode" which will write a pseudo-random byte (different bytes for each user) for every read into the keyfile. This way, even if the users attempt to use the same keyfile again, it wont work. Packets will we dropped because the client and server will have different bytes in their keyfiles where they've already used that portion of the key.
* Introduce a configurable keybyte_zero counter that allows for a certain number of zeros to be allowed in a row from the keyfile. For instance, one might set the max_keybyte_zero counter at 3, and then no more than 3 zeroes would ever be pulled from the keyfile in immediate succession to help prevent leakage. During the `encode()` or `decode()` call, if the last 3 keybytes were zero, otptunnel will loop over the keyfile bytes (at regular stepping), until a non-zero byte is found and that will be the keybyte used in the XOR. 
*  Design a config file. Make OTPTunnel read this file instead of having to specify a million flags.
*  Offer users an ability to track and save session state in a state file.
* Implement option to manually specify initial encoding seek offset value.
* Introduce multiple clients per server.
* Make server act as router, hand out IP addresses for VPN clients.
* Introduce "control packets" as mechanism for servers and clients to exchange messages regarding establishing a new client connection to the server and for the server to hand out a TAP IP address to clients. Control packets always have an outermost offset of 0xFFFFFFFFFFFF -- the highest offset allowed in 6 bytes, the next 6 bytes are the actual offset into some (perhaps unknown) keyfile. 
* Make server use a directory of keys instead of a single keyfile. When a new packet comes in, if it is a control packet, the server tries to decrypt the packet from the starting offset of every key in it's keyfile directory. 
* Make web interface for monitoring state information, modifying configuration, adding new keys, etc.
* Make OTPTunnel pip installable. Make debian-style init script for launching otptunnel as daemon.