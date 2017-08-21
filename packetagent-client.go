/*
                  | |            _                                  _
 ____  _____  ____| |  _ _____ _| |_ _____ _____  ____ _____ ____ _| |_
|  _ \(____ |/ ___) |_/ ) ___ (_   _|_____|____ |/ _  | ___ |  _ (_   _)
| |_| / ___ ( (___|  _ (| ____| | |_      / ___ ( (_| | ____| | | || |_
|  __/\_____|\____)_| \_)_____)  \__)     \_____|\___ |_____)_| |_| \__)
|_|                                             (_____|

packet-agent 🕵 : client.go
license: LGPLv3
author: Ben Duncan @ben_colo
more: https://packet-agent.com/

FILE_ID.DIZ

*/

package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/syn53/packetagent"
	pb "gopkg.in/cheggaaa/pb.v1"
	// Should be optional really ...
)

/*
TODO:

- Add per IP message support
- SSL support
	- base64AES-256-KEY(encrypted by RSA public key)+}base64payload}}(EOF)
	- if crypto fails, try plaintext

- Port ranges
x - Fit 2 bytes in, vs 1
- Function to find free ports
- TCP or UDP
- How to detect these, filter via tcpdump and the like.
- Send dummy data to cloak
x - Progress bar support
- Look at godep support

Support other transport methods:

- IP headers
- Spoofed packets ( destination IP )
- ICMP payloads
- Dest port ( e.g between $range + (1 to 66) to represent Base64
- Two ports, e.g 80 and 443 as binary for dst connect, no data
- ipv6 support, lots more padding
- Combination of TCP + UDP packets

- UDP DEST PORT! SRC IS IRRELEVANT VIA A NAT! :)

*/

func main() {

	// CLI Flags
	message := flag.String("message", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=", "Message to transmit")
	verbose := flag.Bool("verbose", false, "Flag for verbose output")

	dstport := flag.Int("port", 8053, "Connect on specified port (UDP)")
	server := flag.String("server", "127.0.0.1", "Connect to specified server (localhost)")
	file := flag.String("file", "", "Send a file (<32kb recommended)")

	sleep := flag.Int("sleep", 1, "Pause for X milliseconds between packets (1ms)")

	broadcast := flag.Bool("broadcast", false, "Broadcast to subnet (UDP only)")

	source := flag.String("source", "", "Source IP address")

	publickey := flag.String("pubkey", "", "Public RSA key to encrypt data (optional)")

	flag.Parse()

	var str string

	// Read the file to send
	if *file != "" {

		data, err := ioutil.ReadFile(*file)
		if err != nil {
			log.Fatalf("Cannot read specified file: %s", err)
		}

		dataLen := len(data)

		str = string(data)

		fmt.Println("Sending file =>", *file, "(", len(data), ") bytes on disk. (", len(str), ") bytes base64 encoded")

		if dataLen > 1024*32 {
			fmt.Println("WARNING: File specified is larger then 32kb, this is not recommended.")
		}

	} else {

		str = *message
		fmt.Println("Transmitting message => ", *message)

	}

	// Create a map between characters
	ctl := pkagent.CtlStrings{}
	ctl = pkagent.CtlStringsToMap(ctl)

	if *broadcast == true {
		*server = "255.255.255.255"
	}

	RemoteAddr := net.UDPAddr{IP: net.ParseIP(*server), Port: *dstport}

	fmt.Println("\nDialing ☎️ =>", RemoteAddr.IP, ":", RemoteAddr.Port, "\n")

	// Public key specified? Encrypt a AES shared-key using the rcpt public RSA key
	// After this, encrypt the payload using the AES cipher
	// Format:
	// }base64-AES-256-KEY(signed by RSA public key)}(AES encrypted payload, base64}}(EOF)

	var ports []int

	if *publickey != "" {
		pub_parsed, err := pkagent.LoadRSApublicKey(*publickey)

		if err != nil {
			log.Fatal(err)
		}

		label := []byte("")
		hash := sha256.New()

		if *verbose == true {
			fmt.Println("Encrypting message")
		}

		// Encrypt the AES shared key
		aesKey := pkagent.GenKey()

		aesSharedKey, err := rsa.EncryptOAEP(hash, rand.Reader, pub_parsed, aesKey, label)

		if err != nil {
			fmt.Println("Failed to encrypt AES shared key", err)
		}

		if *verbose == true {
			fmt.Println("Encrypting complete")
		}

		// Next, encrypt the payload using the AES key

		aesPayLoad, err := pkagent.Encrypt(aesKey, str)

		if err != nil {
			fmt.Println(err)
		}

		if *verbose == true {
			fmt.Println("SharedKey length =", len(aesSharedKey))
			fmt.Println(string(aesSharedKey))

			fmt.Println("Payload")

			fmt.Println(aesPayLoad)
		}

		// base64-AES-256-KEY(signed by RSA public key)+{(AES encrypted payload, base64}}(EOF)

		// Encode the AES shared key using the RSA public key
		ports = pkagent.SrcportToASCII(string(aesSharedKey), ctl.Data, true)

		// Next, the payload AES encrypted
		ports = append(ports, pkagent.SrcportToASCII(aesPayLoad, ctl.Data, false)...)

	} else {

		ports = pkagent.SrcportToASCII(str, ctl.Data, false)

	}

	count := len(ports)
	bar := pb.StartNew(count)

	for _, value := range ports {
		bar.Increment()

		var s []string

		if *source != "" {
			s = []string{string(*source) + ":", strconv.Itoa(value)}

		} else {
			s = []string{":", strconv.Itoa(value)}

		}

		LocalAddr, err := net.ResolveUDPAddr("udp", strings.Join(s, ""))

		if err != nil {
			log.Fatal("Could not create network socket:", err)
		}

		if *verbose == true {
			fmt.Println("Opening connection on port", s)
		}

		// Attempt to dial 5 times max ( src part may already be in use )
		var attempt int

		for {

			conn, err := net.DialUDP("udp", LocalAddr, &RemoteAddr)

			if err != nil {
				fmt.Println("Could not dial network socket:", err)
				attempt++

				if attempt == 5 {
					log.Fatal("Could not dial network socket after 5 attempts:", err)
					time.Sleep(time.Second * 1)

				}

				continue
			}

			// TODO: Random data, or null for data payload

			//var i int

			msg := string("")

			buf := []byte(msg)
			_, err = conn.Write(buf)
			if err != nil {
				fmt.Println(msg, err)
			}

			// Sleep for the specified time between packets
			sleep2 := time.Duration(*sleep)
			snooze := time.Millisecond * sleep2
			time.Sleep(snooze)

			// Close the connection
			// TODO: Add TCP support
			conn.Close()
			break

		}

	}

	bar.Finish()
	bar.FinishPrint("\nComplete - 🕵 PacketAgent at your service")

}
