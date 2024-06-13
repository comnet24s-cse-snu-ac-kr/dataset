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

  sigs := make([]*SnortSignature, 0)
  sigs = append(sigs, &SnortSignature{content: []byte{0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}, offset: 2})
  sigs = append(sigs, &SnortSignature{content: []byte{0x45, 0x10}, offset: 13})
  sigs = append(sigs, &SnortSignature{content: []byte{0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00}, offset: -1})

  for i, sig := range sigs {
    if sig.check(packet.LayerContents()) {
      fmt.Fprintln(os.Stderr, "Detected:", i, fileName, packet.LayerContents())
    }
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

type SnortSignature struct {
  content []byte
  offset  int
}

func (s *SnortSignature) check(mainSlice []byte) bool {
	mainLen, sigLen := len(mainSlice), len(s.content)

	if sigLen == 0 || sigLen > mainLen {
		return false
	}

  if s.offset == -1 {
    for i := 0; i <= mainLen-sigLen; i++ {
      if bytes.Compare(mainSlice[i:i+sigLen], s.content) == 0 {
        return true
      }
    }
  } else {
    if bytes.Compare(mainSlice[s.offset:s.offset+sigLen], s.content) == 0 {
      return true
    }
  }

	return false
}
