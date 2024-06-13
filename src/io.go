package main

import (
	"encoding/hex"
	"encoding/json"
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
}

func WriteFile(packet gopacket.Layer, fileName string) error {
	output := new(OutputJson)
	output.Packet = hex.EncodeToString(packet.LayerContents())

	dat, err := json.Marshal(output)
	if err != nil {
		return err
	}

	if err := os.WriteFile(fileName, dat, 0644); err != nil {
		return err
	}

	return nil
}
