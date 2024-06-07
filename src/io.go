package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// ---

func ReadFile(pcapFileName string) ([]gopacket.Layer, error) {
	handle, err := pcap.OpenOffline(pcapFileName)
	if err != nil {
		return nil, err
	}
	defer handle.Close()

	ret := make([]gopacket.Layer, 0)
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		if dnsPacket := packet.Layer(layers.LayerTypeDNS); dnsPacket != nil {
			ret = append(ret, dnsPacket)
		}
	}

	return ret, nil
}

// ---

type OutputJson struct {
	Packet string `json:"packet"`
	Key    string `json:"key"`
	Nonce  string `json:"nonce"`

	// Note that the word "couter" indicates suffix for PreCounterBlock (J0)
	// which is 0x00000001 for 12-byte nonce (IV).
	// See NIST SP 800-38D, section 7.1.
	Counter string `json:"counter"`
}

func WriteFile(packet gopacket.Layer, fileName string) error {
	output := new(OutputJson)
	output.Packet = hex.EncodeToString(packet.LayerContents())
	if !checkIodineSignature1(packet.LayerContents()) {
		fmt.Fprintln(os.Stderr, "1", fileName, packet.LayerContents())
	}
	if !checkIodineSignature2(packet.LayerContents()) {
		fmt.Fprintln(os.Stderr, "2", fileName, packet.LayerContents())
	}
	if !checkIodineSignature3(packet.LayerContents()) {
		fmt.Fprintln(os.Stderr, "3", fileName, packet.LayerContents())
	}
	output.Key = KEY
	output.Nonce = NONCE
	output.Counter = PRE_COUNTER_SUFFIX

	dat, err := json.Marshal(output)
	if err != nil {
		return err
	}

	if err := os.WriteFile(fileName, dat, 0644); err != nil {
		return err
	}

	return nil
}

func checkIodineSignature1(mainSlice []byte) bool {
	sigBytes := []byte{0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}
	sigOffset := 2
	mainLen, sigLen := len(mainSlice), len(sigBytes)

	if sigLen == 0 || sigLen > mainLen {
		return false
	}

	if bytes.Compare(mainSlice[sigOffset:sigOffset+sigLen], sigBytes) == 0 {
		return true
	}
	return false
}

func checkIodineSignature2(mainSlice []byte) bool {
	sigBytes := []byte{0x45, 0x10}
	sigOffset := 13
	mainLen, sigLen := len(mainSlice), len(sigBytes)

	if sigLen == 0 || sigLen > mainLen {
		return false
	}

	if bytes.Compare(mainSlice[sigOffset:sigOffset+sigLen], sigBytes) == 0 {
		return true
	}
	return false
}

func checkIodineSignature3(mainSlice []byte) bool {
	sigBytes := []byte{0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00}
	// sigOffset := nil // Arbirarily offset
	mainLen, sigLen := len(mainSlice), len(sigBytes)

	if sigLen == 0 || sigLen > mainLen {
		return false
	}

	for i := 0; i <= mainLen-sigLen; i++ {
		if bytes.Compare(mainSlice[i:i+sigLen], sigBytes) == 0 {
			return true
		}
	}
	return false
}
