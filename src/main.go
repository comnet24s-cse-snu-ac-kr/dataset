package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/google/gopacket/layers"
  "github.com/schollz/progressbar/v3"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Printf("Usage: %s <pcap file>\n", os.Args[0])
    return
	}
  pcapFileName := os.Args[1]
  pcapFileNameWithNoExtension := strings.TrimSuffix(pcapFileName, ".pcap")

  pcaps, err := ReadFile(pcapFileName)
  if err != nil {
    fmt.Println("error:", err)
  }

  bar := progressbar.NewOptions(len(pcaps),
    progressbar.OptionSetWidth(30),
    progressbar.OptionShowCount(),
    progressbar.OptionSetPredictTime(false),
    progressbar.OptionShowDescriptionAtLineEnd(),
    progressbar.OptionShowElapsedTimeOnFinish(),
    progressbar.OptionSetDescription(fmt.Sprintf("%s", pcapFileName)),
  )

  for i, pcap := range pcaps {
    var packetType string
    if pcap.(*layers.DNS).QR == true /*DNS Response */ {
      packetType = "response"
    } else {
      packetType = "query"
    }
    if err := WriteFile(pcap, fmt.Sprintf("%s-%s-%05d.json", pcapFileNameWithNoExtension, packetType, i)); err != nil {
      fmt.Println("error:", err)
      return
    }
    bar.Add(1)
  }
}
