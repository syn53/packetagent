/*
                  | |            _                                  _
 ____  _____  ____| |  _ _____ _| |_ _____ _____  ____ _____ ____ _| |_
|  _ \(____ |/ ___) |_/ ) ___ (_   _|_____|____ |/ _  | ___ |  _ (_   _)
| |_| / ___ ( (___|  _ (| ____| | |_      / ___ ( (_| | ____| | | || |_
|  __/\_____|\____)_| \_)_____)  \__)     \_____|\___ |_____)_| |_| \__)
|_|                                             (_____|

packet-agent: server.go
license: Apache 2.0
author: Ben Duncan @ben_colo
more: https://packet-agent.com/

*/

package main

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"

	"github.com/syn53/packetagent"
)

func main() {

	// watch traffic
	// sudo tcpdump -ni utun2 ip and udp and port 53

	port := flag.String("port", ":8053", "Listen on specified port (UDP)")
	verbose := flag.Bool("verbose", false, "Flag for verbose output")
	export := flag.String("export", "", "Export to a specified directory (./data)")

	privkey := flag.String("privkey", "", "Decrypt data using private RSA key (optional) ")

	flag.Parse()

	fmt.Println("Listening on port", *port, " (UDP)")

	ctl := pkagent.CtlStrings{}
	ctl = pkagent.CtlStringsToMap(ctl)

	ServerAddr, err := net.ResolveUDPAddr("udp", *port)

	ln, err := net.ListenUDP("udp", ServerAddr)

	if err != nil {
		log.Fatal("Could not start server:", err)
		// handle error
	}

	buf := make([]byte, 1024)
	data := []string{}

	// Used to store the client payload, per IP
	clientDataIP := make(map[string]string)

	// Used to store the shared AES key
	clientDataIPKey := make(map[string]string)

	for {
		n, addr, err := ln.ReadFromUDP(buf)

		clientData := pkagent.SrcportsToString(addr.Port, ctl.Data)

		ipv4 := addr.IP

		if *verbose == true {
			fmt.Println("\bReceived from", addr.IP, ":", addr.Port, n, "=>", clientData)
		}

		if err != nil {
			fmt.Println("Error:", err)
		}

		// EOF of the shared AES key ( encrypted by the specified public key )
		if clientData == "+{" {

			totalStr := string(clientDataIP[string(ipv4)]) //strings.Join(data, "")

			str, err := base64.StdEncoding.DecodeString(totalStr)

			if err != nil {
				fmt.Println("Cannot decode AES shared secret:", err)
			}

			clientDataIPKey[string(ipv4)] = string(str)

			//clientDataIPKey[string(ipv4)], err = base64.StdEncoding.DecodeString(clientDataIP[string(ipv4)])

			clientDataIP[string(ipv4)] = "" // Clear the buffer, for the AES payload

			if *verbose == true {
				fmt.Println("ShardAESKey Recv", totalStr)
			}

		} else if clientData == "{{" {

			//c := strings.Join(clientDataIP[string(ipv4)], "")
			totalStr := string(clientDataIP[string(ipv4)]) //strings.Join(data, "")

			str, err := base64.StdEncoding.DecodeString(totalStr)

			if *verbose == true {
				fmt.Println("ShardAESPayload Recv")
			}

			// If a private key specified?
			if *privkey != "" {

				priv_parsed, _ := pkagent.LoadRSAprivateKey(*privkey)

				label := []byte("")
				hash := sha256.New()

				var sharedAESkey []byte

				sharedAESkey, err = rsa.DecryptOAEP(hash, rand.Reader, priv_parsed, []byte(clientDataIPKey[string(ipv4)]), label)

				if err != nil {
					fmt.Println("Cannot decrypt shared AES key:", err)
				}

				// We have our key. Not decrypt the payload sent
				str, err = pkagent.Decrypt(sharedAESkey, string(str))

				if err != nil {
					fmt.Println("Cannot decrypt payload:", err)
				}

			}

			if err == nil {

				// Write data to output file
				if *export != "" {

					hasher := md5.New()
					hasher.Write([]byte(str))
					file := hex.EncodeToString(hasher.Sum(nil))

					filename := *export + "/" + file

					fmt.Println(ipv4, "=> Writing to", filename)

					if err := ioutil.WriteFile(filename, str, 0600); err != nil {
						fmt.Println("write output:", err)
					}

				} else {
					fmt.Println(ipv4, "=>", string(str))

				}

			} else {
				fmt.Println("\aError decoding string - Maformed data?", err)
			}

			data = []string{}
			// Reset once message received
			clientDataIP[string(ipv4)] = ""

		} else {

			clientDataIP[string(ipv4)] = clientDataIP[string(ipv4)] + clientData

			data = append(data, clientData)
		}

	}

	defer ln.Close()

}
