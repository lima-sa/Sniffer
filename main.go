package main

import (
	"fmt"
	"log"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func main() {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatalf("Ошибка получения списка устройств: %v", err)
	}

	if len(devices) == 0 {
		log.Fatal("Не найдено ни одного сетевого интерфейса.")
	}

	fmt.Println("Запуск сниффера на всех интерфейсах:")
	for _, device := range devices {
		fmt.Printf("- %s (%s)\n", device.Name, device.Description)
		go sniffDevice(device.Name)
	}

	select {}
}

func sniffDevice(deviceName string) {
	snapshotLen := int32(65536)
	promiscuous := true
	timeout := 30 * time.Second

	handle, err := pcap.OpenLive(deviceName, snapshotLen, promiscuous, timeout)
	if err != nil {
		log.Printf("[Ошибка] Не удалось открыть интерфейс %s: %v", deviceName, err)
		return
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for packet := range packetSource.Packets() {
		printPacketInfo(deviceName, packet)
	}
}

func printPacketInfo(deviceName string, packet gopacket.Packet) {

	timestamp := packet.Metadata().Timestamp.Format("15:04:05.000")
	length := packet.Metadata().Length

	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		ipLayer = packet.Layer(layers.LayerTypeIPv6)
	}

	if ipLayer != nil {
		switch ip := ipLayer.(type) {
		case *layers.IPv4:
			fmt.Printf("[%s] [%s] IPv4 %s -> %s | Протокол: %s | %d байт\n",
				deviceName, timestamp, ip.SrcIP, ip.DstIP, ip.Protocol, length)
		case *layers.IPv6:
			fmt.Printf("[%s] [%s] IPv6 %s -> %s | Протокол: %s | %d байт\n",
				deviceName, timestamp, ip.SrcIP, ip.DstIP, ip.NextHeader, length)
		}
	} else {
		if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
			arp, _ := arpLayer.(*layers.ARP)
			fmt.Printf("[%s] [%s] ARP %v -> %v | %d байт\n",
				deviceName, timestamp, arp.SourceProtAddress, arp.DstProtAddress, length)
		} else {
			fmt.Printf("[%s] [%s] Не-IP пакет | %d байт\n",
				deviceName, timestamp, length)
		}
	}
}
