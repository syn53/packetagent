
# PacketAgent
### Covert packet transmission - Embed messages or files in UDP/TCP/ICMP headers

![PacketAgent logo](./imgs/logo2.png)

## Background

Packet-agent is designed to transmit a secret message or file via TCP/UDP/ICMP, by concealing encrypted data within the protocol header, while transmitting the packet with no visible data on the network.

Packet-agent will transmit innocuous looking packets with no data, while encupsulating your message within a series of headers.

## Uses

* Whistleblowing

While working for ___[insert evil company/government here]___ you need to send a top-secret file to a trusted destination, while avoiding the eyes of the network sysadmin, packet-sniffers, deep-packet inspection and traffic sensors on the local network.

* IOT device

An important IOT device requires a network connection to send a status to a remote host, however the firewall on the WAN is restrictive, deep-packet inspection is active and blocking normal traffic.

* Education

After having a major nose-bleed researching with the latest Javascript framework and going mad after the last code-review for your teams .net/PHP application, you yearn to get your hands dirty creating raw TCP/UDP packets, messing with IP protocols, and having fun with low-level networking.

# Methods

## Source-port UDP

Embed a message by using the UDP source-port to encapsulate data with 2-bytes per connection.

### Example

#### Running the Server

Messages displayed to STDOUT

```
$ go run packetagent-server.go -privkey ./mykey.pem

Listening on port :8053  (UDP)

```

#### Export to a directory

Messages received are exported to the specified directory, saved by the MD5 sum of the receiving data.


```
$ go run packetagent-server.go -privkey ./mykey.pem -export ./data/

Listening on port :8053  (UDP)

127.0.0.1 => Writing to ./data/90d7e87ab11a7cc3257e0057c4e5cb8a

```

#### Server Usage

```
  -export string
    	Export to a specified directory (./data)
  -port string
    	Listen on specified port (UDP) (default ":8053")
  -privkey string
    	Decrypt data using private RSA key (optional)
  -verbose
    	Flag for verbose output
```

#### Client - Send a message

Ceaser, famously used an elementary ___encryption___ format to relay messages - "Attack at dawn" is one such famous message sent.

```
$ go run packetagent-client.go -message "Attack at dawn" -pubkey mykey.pub

Transmitting message =>  Attack at dawn

Dialing ☎️ => 127.0.0.1:8053

 122 / 204 [========>------------------------]  59.80% 1s
 204 / 204 [=================================] 100.00% 0s
```

#### Client - Send a file

Files can be sent, recommended filesize <32kb.

```
$ go run packetagent-client.go -file ~/Desktop/secret.pdf -pubkey mykey.pub
Sending file =>  ~/Desktop/secret.pdf ( 4226 ) bytes on disk.

Dialing ☎️ => 127.0.0.1 : 8053

 1111 / 3958 [========>----------------------]  28.07% 4s
 3958 / 3958 [===============================] 100.00% 6s

```

#### Client usage

```
  -broadcast
    	Broadcast to subnet (UDP only)
  -file string
    	Send a file (<32kb recommended)
  -message string
    	Message to transmit (default "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
  -port int
    	Connect on specified port (UDP) (default 8053)
  -pubkey string
    	Public RSA key to encrypt data (optional)
  -server string
    	Connect to specified server (localhost) (default "127.0.0.1")
  -sleep int
    	Pause for X milliseconds between packets (1ms) (default 1)
  -source string
    	Source IP address
  -verbose
    	Flag for verbose output
```

### tcpdump

To test, capture all UDP packets on localhost - Note the data length is 0, headers are only transmitted with our message encrypted using the specified public/private-key.

```
$ tcpdump -i lo0 udp

20:53:44.708462 IP localhost.35331 > localhost.senomix02: UDP, length 0
20:53:44.709647 IP localhost.21268 > localhost.senomix02: UDP, length 0
20:53:44.711355 IP localhost.36172 > localhost.senomix02: UDP, length 0
20:53:44.712985 IP localhost.12937 > localhost.senomix02: UDP, length 0
20:53:44.714733 IP localhost.41653 > localhost.senomix02: UDP, length 0
...

204 packets captured
204 packets received by filter
```

### How it works

### Benefits

### Cons


## Source address

Coming soon. Send packets with a forged source addresses, while concelling a message within the source address.

## TCP ID header

Coming soon. Embedding data within the TCP ID header.

## ICMP 

Coming soon. Embedding data within the ICMP header.

# Encryption

Optionally messages can be encrypted using a specified RSA public key. Since the purpose of PacketAgent is to prevent data sent over the network and prevent the server from sending data back to the client, TLS is not used, rather PacketAgent will encrypt messages by:

1) The client will generate a Shared-key (AES-256), encrypting this using the specified RSA public-key

2) The message payload is encrypted using the Shared-key generated

3) The server receives the message and decrypts the Shared-key using the specified RSA key, and the remaining payload is decrypted from the shared-key.

```
[AES-256 Shared Key encrypted using RSA public-key][Payload encrypted with Shared-key]
```

# Credits

* Logo ANSI art made by Green Hornet (1996)
* Inspiration for encapulating messages via the TCP ID header from Craig H. Rowland (covert.c)


```
                  | |            _                                  _
 ____  _____  ____| |  _ _____ _| |_ _____ _____  ____ _____ ____ _| |_
|  _ \(____ |/ ___) |_/ ) ___ (_   _|_____|____ |/ _  | ___ |  _ (_   _)
| |_| / ___ ( (___|  _ (| ____| | |_      / ___ ( (_| | ____| | | || |_
|  __/\_____|\____)_| \_)_____)  \__)     \_____|\___ |_____)_| |_| \__)
|_|                                             (_____|

```


# 🕵 
