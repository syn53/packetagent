package pkagent

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"strconv"
	"strings"
	"time"
)

// CtlStrings Map containing characters
type CtlStrings struct {
	Data map[int]string
}

// CtlStringsToMap Create a map of the base64 characters
func CtlStringsToMap(ctl CtlStrings) CtlStrings {

	strs := []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/={")

	//ctlStrings = make(map[int]string)
	ctl.Data = make(map[int]string)

	// Port numbers, map > 10
	for i := 10; i < len(strs)+10; i++ {
		ctl.Data[i] = string(strs[i-10])
	}

	return ctl

	/*
		strs := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/={"

		//ctlStrings = make(map[int]string)
		ctl.Data = make(map[int]string)

		for _, rune := range strs {
			newstr := (int(rune) - 43)
			ctl.Data[newstr] = string(rune)
		}

		return ctl
	*/

	// ctl

}

// SrcportsToStringDecode Convert a collection of source ports to a string, base64 decoded
func SrcportsToStringDecode(ports []int, m map[int]string) (src []byte) {

	str := []string{}

	for _, s := range ports {
		a, b := srcportFromASCII(s)

		if m[a] != "" {
			str = append(str, m[a])
		}

		if m[b] != "" {
			str = append(str, m[b])

		}

	}

	totalStr := strings.Join(str, "")

	src, _ = base64.StdEncoding.DecodeString(totalStr)

	//fmt.Println(string(src))

	return src

}

// SrcportsToString Convert a single source ports to a string
func SrcportsToString(port int, m map[int]string) (src string) {

	str := []string{}

	a, b := srcportFromASCII(port)

	if m[a] != "" {
		str = append(str, m[a])
	}

	if m[b] != "" {
		str = append(str, m[b])

	}

	totalStr := strings.Join(str, "")

	return totalStr

}

// Generte a random source-port
func randomSrcPort(min, max int) int {
	rand.Seed(time.Now().UnixNano())
	return rand.Intn(max-min) + min
}

// Check if a source-port is already in use
func checkportUse(port int) (chk bool) {

	// The Internet Assigned Numbers Authority (IANA) suggests the range 49152 to 65535 (215+214 to 216−1) for dynamic or private ports.
	if port > 65535 || port < 100 {
		return true
	}

	return false
}

// Convert a string, into a series of ports to identify the message
/*
	65535
	01122
	60033
	71100

	UDP
	random-pkt1-pkt2

	Find a free source-port between:

	10000
	20000
	30000
	40000
	50000

	if pkt1 < 55 and pkt2 < 35, use:
	60000, e.g
	65535

	TODO: if pkt1 or pkt2 == 00, transmit a single packet, else if > 0, two packets exist.

*/

// SrcportToASCII convert ports to a string
func SrcportToASCII(src string, m map[int]string, encrypt bool) (ports []int) {

	// Convert to Base64 and append EOF
	src = base64.StdEncoding.EncodeToString([]byte(src))

	// AES shared key is sent
	if encrypt == true {
		src = src + "+{"

	} else {
		src = src + "{{"
	}

	length := len(src)

	for i := 0; i < length; i++ {

		//a, b := srcportFromASCII()

		b := i + 1

		if b < length {

			first := strRange(string(src[i]), m)
			second := strRange(string(src[i+1]), m)

			//fmt.Println("FIRST => ", first)
			//fmt.Println("SECOND => ", second)

			port := 0
			random := 0
			chk := 0

			for {

				random = randomSrcPort(1, 6)

				// 5 failures, ditch the second byte, make it random
				/*
					if chk > 5 {
						//fmt.Println("Check > 5")
						//first = 99
						//random = random * 10
						chk = 0
					}
				*/

				// We need padding
				//if chk == 0 {
				if first < 10 {
					//fmt.Println("First needs padding", first, random)

					//if first < 10 && second < 10 {
					//	random = random * 100
					//} else {
					random = random * 10
					//}
				}

				if second < 10 {
					//fmt.Println("Second needs padding", first, random)
					first = first * 10
				}

				//}

				port, _ = strconv.Atoi(fmt.Sprintf("%d%d%d", random, first, second))

				//fmt.Println("\tPort => ", port, random, first, second)
				if !checkportUse(port) {
					ports = append(ports, port)
					i = i + 1 // 2 strings included
					chk = 0
					break
				} else {
					//fmt.Println("Port", port, "already used, finding another random port", i)
					chk++
				}

			}

			//fmt.Println(i, "=>", string(src[i]), "=>", "port =>", port, random, first, second)

			//a, b := srcportFromASCII(port)
			//fmt.Println("Decoded =>", m[a], m[b])

		} else {
			fmt.Println(i, "=>", string(src[i]), "=>", "range =>", strRange(string(src[i]), m))

		}

	}

	return ports

}

func strRange(s string, m map[int]string) int {

	for key, value := range m {
		if string(value) == s {
			return key
		}
	}

	return 0

}

func srcportFromASCII(src int) (a, b int) {

	// We can do this better
	each := strings.Split(strconv.Itoa(src), "")

	length := len(each)

	for i := 0; i < length; i++ {

		//fmt.Println(i, each[i])

	}

	if length > 4 {
		//fmt.Println("First bytes: ", each[3], each[4])
		//fmt.Println("Second bytes: ", each[1], each[2])
		a, _ := strconv.Atoi(each[1] + each[2])
		b, _ := strconv.Atoi(each[3] + each[4])
		return a, b
	} else if length > 2 {
		//fmt.Println("Only bytes: ", each[2], each[3])
		a, _ := strconv.Atoi(each[2] + each[3])
		return a, 0
	} else if length > 1 {
		//fmt.Println("Only bytes: ", each[0], each[1])
		a, _ := strconv.Atoi(each[0] + each[1])
		//fmt.Println("Skipping port")
		return a, 0
	} else {
		//fmt.Println("Skipping port")
	}

	return 0, 0
}

// Load a speicifed public key for encryption
func LoadRSAprivateKey(pathname string) (*rsa.PrivateKey, error) {

	data, err := ioutil.ReadFile(pathname)

	if err != nil {
		log.Fatal("Could not load", pathname, ":", err)
	}

	//block, _ := pem.Decode([]byte(privPEM))
	block, _ := pem.Decode(data)

	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the key")
	}

	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return priv, nil
}

func LoadRSApublicKey(pathname string) (*rsa.PublicKey, error) {

	data, err := ioutil.ReadFile(pathname)

	if err != nil {
		log.Fatal("Could not load", pathname, ":", err)
	}

	block, _ := pem.Decode(data)

	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	switch pub := pub.(type) {
	case *rsa.PublicKey:
		return pub, nil
	default:
		break // fall through
	}
	return nil, errors.New("Key type is not RSA")
}
