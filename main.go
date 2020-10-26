package main

import (
	"flag"
	"log"
	"net"
	"os"
	"time"

	"github.com/agalue/onms-flow-replay/parser"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

func main() {
	log.SetOutput(os.Stdout)
	srcAddr := "127.0.0.1"
	hostname, _ := os.Hostname()
	if ipaddrs, err := net.LookupIP(hostname); err != nil {
		srcAddr = ipaddrs[0].String()
	}
	flowParser := &parser.FlowParser{}
	pcapFile := flag.String("pcap", "", "Path to the pcap file with Netflow 9 packets")
	flag.StringVar(&flowParser.SourceAddress, "ip", srcAddr, "Flow Exporter IP Address")
	flag.IntVar(&flowParser.SourcePort, "port", 8877, "Flow Exporter Port")
	flag.StringVar(&flowParser.ForeignSource, "foreignSource", "Test", "Flow Exporter Foreign Source")
	flag.StringVar(&flowParser.ForeignID, "foreignId", hostname, "Flow Exporter Foreign ID")
	flag.IntVar(&flowParser.NodeID, "nodeId", 1, "Flow Exporter Node ID")
	flag.StringVar(&flowParser.MinionID, "minion", hostname, "OpenNMS Minion ID")
	flag.StringVar(&flowParser.MinionLocation, "location", "Mock", "OpenNMS Minion Location")
	flag.StringVar(&flowParser.KafkaServer, "kafka", srcAddr+":9092", "Kafka Bootstrap Server")
	flag.StringVar(&flowParser.KafkaTopic, "topic", "OpenNMS.Sink.Telemetry-Netflow-9", "Kafka Topic for Flows Sink API or Flow Document")
	flag.BoolVar(&flowParser.UseSink, "useSink", true, "true for Sink API, or false for Flow Document (Nephron Source)")

	flag.Parse()

	flowParser.Start()
	defer flowParser.Stop()

	handleRead, err := pcap.OpenOffline(*pcapFile)
	if err != nil {
		log.Fatalf("PCAP error while reading %s: %v", *pcapFile, err)
	}
	defer handleRead.Close()

	var lastTS time.Time
	var lastSend time.Time
	packetSource := gopacket.NewPacketSource(handleRead, handleRead.LinkType())
	for packet := range packetSource.Packets() {
		intervalInCapture := packet.Metadata().Timestamp.Sub(lastTS)
		elapsedTime := time.Since(lastSend)
		if (intervalInCapture > elapsedTime) && !lastSend.IsZero() {
			time.Sleep(intervalInCapture - elapsedTime)
		}
		lastSend = time.Now()
		flowParser.Process(packet)
		lastTS = packet.Metadata().Timestamp
	}
}
