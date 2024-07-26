# Server for https://github.com/juhis-o/thingy91-accel/


## Overview
Server receives CBOR/heatshrink compressed acceleration values from client and prints them to cbor.csv file.
Details about communication between client and server can be found from my theses.

Shortly, server receives 9 NON-CONFIRMABLE packets from client and 1 CONFIRMABLE packet. 
Server responds to this CONFIRMABLE packet CREATED response, if all 10 packets has arrived to server. 

If not, server responds client with BAD REQUEST. This message contains bitfield, which indicates what messages has arrived to server.

Transaction between client and server

![Client/Server Transaction](https://i.imgur.com/ZKnHzLG.png)

BAD REQUEST bitfield

![Bitfield](https://i.imgur.com/whWBc2m.png)

### Building and Running
********************
Dependencies:

https://github.com/PJK/libcbor

https://github.com/obgm/libcoap

Compile and install according to instructions.

Port 5684 needs to be opened in your router to work with thing91-accel project.

### Compiling
1. ```sh
   git clone https://github.com/juhis-o/thingy-91_accel-server.git
   ```
2. ```sh
   cd thingy-91_accel-server
   ```
3. ```sh
   cmake ./
   ```
4. Modify line 237 to match your local IP address.

5. Make
   ```sh
   make
   ```
5. Run
   ```sh
   ./server
   ```
