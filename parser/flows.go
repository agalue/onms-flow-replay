package parser

import (
	"encoding/json"
	"log"
	"net"
	"strconv"
	"time"

	"github.com/ThreeDotsLabs/watermill"
	"github.com/ThreeDotsLabs/watermill-kafka/v2/pkg/kafka"
	"github.com/ThreeDotsLabs/watermill/message"
	"github.com/google/gopacket"

	"github.com/agalue/onms-flow-replay/protobuf/flowdocument"
	"github.com/agalue/onms-flow-replay/protobuf/netflow"
	"github.com/agalue/onms-flow-replay/protobuf/sink"
	"github.com/agalue/onms-flow-replay/protobuf/telemetry"
	"google.golang.org/protobuf/proto"

	decoder "github.com/cloudflare/goflow/v3/decoders"
	goflowMsg "github.com/cloudflare/goflow/v3/pb"
	goflow "github.com/cloudflare/goflow/v3/utils"

	"github.com/golang/protobuf/ptypes/wrappers"
)

// FlowParser represents a flow parser
type FlowParser struct {
	MinionID       string
	MinionLocation string
	SourceAddress  string
	SourcePort     int

	NodeID        int
	ForeignSource string
	ForeignID     string

	KafkaTopic  string
	KafkaServer string
	UseSink     bool

	offset    uint64
	processor decoder.Processor
	publisher *kafka.Publisher
}

// Publish implementation of the goflow's Transport interface to parse flow messages
// This is not intended to be used directly
func (p *FlowParser) Publish(msgs []*goflowMsg.FlowMessage) {
	messages := make([][]byte, len(msgs))
	for idx, m := range msgs {
		text, _ := json.Marshal(m)
		log.Printf("Original Flow: %s", string(text))
		if p.offset == 0 {
			p.offset = uint64(time.Now().Unix()) - m.TimeFlowStart
			log.Printf("Detected an offset of %d seconds", p.offset)
		}
		var buffer []byte
		if p.UseSink {
			f := p.convertToFlowMessage(m)
			text, _ = json.Marshal(f)
			log.Printf("ONMS Flow Message, Timestamp: %s, First Switched %s, Last Switched %s: %s",
				time.Unix(int64(f.Timestamp/1000), 0).String(),
				time.Unix(int64(f.FirstSwitched.Value/1000), 0).String(),
				time.Unix(int64(f.LastSwitched.Value/1000), 0).String(),
				string(text))
			buffer, _ = proto.Marshal(f)
		} else {
			d := p.convertToFlowDocument(m)
			text, _ = json.Marshal(d)
			log.Printf("ONMS Flow Document, Timestamp: %s, First Switched %s, Last Switched %s: %s",
				time.Unix(int64(d.Timestamp/1000), 0).String(),
				time.Unix(int64(d.FirstSwitched.Value/1000), 0).String(),
				time.Unix(int64(d.LastSwitched.Value/1000), 0).String(),
				string(text))
			buffer, _ = proto.Marshal(d)
		}
		messages[idx] = buffer
	}
	if p.UseSink {
		data := p.wrapMessageToTelemetry(messages)
		p.sendBytes(data)
	} else {
		for _, m := range messages {
			if err := p.publisher.Publish(p.KafkaTopic, message.NewMessage(watermill.NewUUID(), m)); err != nil {
				log.Printf("Cannot send message: %v", err)
			}
		}
	}
}

// Start initializes the flow parser and the Kafka producer
// Panics if Kafka is unreachable.
func (p *FlowParser) Start() {
	var err error
	p.publisher, err = kafka.NewPublisher(
		kafka.PublisherConfig{
			Brokers:   []string{p.KafkaServer},
			Marshaler: kafka.DefaultMarshaler{},
		},
		watermill.NewStdLogger(false, false),
	)
	if err != nil {
		log.Fatalf("Cannot connect to Kafka through %s: %v", p.KafkaServer, err)
	}

	netflow := goflow.StateNetFlow{Transport: p}
	netflow.InitTemplates()
	decoderParams := decoder.DecoderParams{
		DecoderFunc:   netflow.DecodeFlow,
		DoneCallback:  goflow.DefaultAccountCallback,
		ErrorCallback: new(goflow.DefaultErrorCallback).Callback,
	}
	p.processor = decoder.CreateProcessor(1, decoderParams, "Netflow-9")
	p.processor.Start()
}

// Stop shutsdown the flow processor
func (p *FlowParser) Stop() {
	p.processor.Stop()
}

// Process parses the flow data from the raw packet and send it to Kafka
func (p *FlowParser) Process(packet gopacket.Packet) {
	baseMessage := goflow.BaseMessage{
		Src:     net.ParseIP(p.SourceAddress),
		Port:    p.SourcePort,
		Payload: packet.TransportLayer().LayerPayload(),
	}
	p.processor.ProcessMessage(baseMessage)
}

func (p *FlowParser) convertToFlowMessage(flowmsg *goflowMsg.FlowMessage) *netflow.FlowMessage {
	srcAddress := net.IP(flowmsg.SrcAddr).String()
	dstAddress := net.IP(flowmsg.DstAddr).String()
	nextHopeAddress := net.IP(flowmsg.NextHop).String()
	var version netflow.NetflowVersion
	switch flowmsg.Type {
	case goflowMsg.FlowMessage_NETFLOW_V5:
		version = netflow.NetflowVersion_V5
	case goflowMsg.FlowMessage_NETFLOW_V9:
		version = netflow.NetflowVersion_V9
	case goflowMsg.FlowMessage_IPFIX:
		version = netflow.NetflowVersion_IPFIX
	}
	msg := &netflow.FlowMessage{
		NetflowVersion:    version,
		Direction:         netflow.Direction(flowmsg.FlowDirection),
		Timestamp:         flowmsg.TimeReceived * 1000,
		DeltaSwitched:     &wrappers.UInt64Value{Value: (flowmsg.TimeFlowStart + p.offset) * 1000},
		FirstSwitched:     &wrappers.UInt64Value{Value: (flowmsg.TimeFlowStart + p.offset) * 1000},
		LastSwitched:      &wrappers.UInt64Value{Value: (flowmsg.TimeFlowEnd + p.offset) * 1000},
		SrcAddress:        srcAddress,
		SrcPort:           &wrappers.UInt32Value{Value: flowmsg.SrcPort},
		SrcAs:             &wrappers.UInt64Value{Value: uint64(flowmsg.SrcAS)},
		SrcMaskLen:        &wrappers.UInt32Value{Value: flowmsg.SrcNet},
		DstAddress:        dstAddress,
		DstPort:           &wrappers.UInt32Value{Value: flowmsg.DstPort},
		DstAs:             &wrappers.UInt64Value{Value: uint64(flowmsg.DstAS)},
		DstMaskLen:        &wrappers.UInt32Value{Value: flowmsg.DstNet},
		NextHopAddress:    nextHopeAddress,
		InputSnmpIfindex:  &wrappers.UInt32Value{Value: flowmsg.InIf},
		OutputSnmpIfindex: &wrappers.UInt32Value{Value: flowmsg.OutIf},
		TcpFlags:          &wrappers.UInt32Value{Value: flowmsg.TCPFlags},
		Protocol:          &wrappers.UInt32Value{Value: flowmsg.Proto},
		IpProtocolVersion: &wrappers.UInt32Value{Value: flowmsg.Etype},
		Tos:               &wrappers.UInt32Value{Value: flowmsg.IPTos},
		FlowSeqNum:        &wrappers.UInt64Value{Value: uint64(flowmsg.SequenceNum)},
		SamplingInterval:  &wrappers.DoubleValue{Value: float64(flowmsg.SamplingRate)},
		NumBytes:          &wrappers.UInt64Value{Value: flowmsg.Bytes},
		NumPackets:        &wrappers.UInt64Value{Value: flowmsg.Packets},
		Vlan:              &wrappers.UInt32Value{Value: flowmsg.VlanId},
	}
	return msg
}

func (p *FlowParser) convertToFlowDocument(flowmsg *goflowMsg.FlowMessage) *flowdocument.FlowDocument {
	srcAddress := net.IP(flowmsg.SrcAddr).String()
	dstAddress := net.IP(flowmsg.DstAddr).String()
	nextHopeAddress := net.IP(flowmsg.NextHop).String()
	var version flowdocument.NetflowVersion
	switch flowmsg.Type {
	case goflowMsg.FlowMessage_NETFLOW_V5:
		version = flowdocument.NetflowVersion_V5
	case goflowMsg.FlowMessage_NETFLOW_V9:
		version = flowdocument.NetflowVersion_V9
	case goflowMsg.FlowMessage_IPFIX:
		version = flowdocument.NetflowVersion_IPFIX
	}
	msg := &flowdocument.FlowDocument{
		NetflowVersion:    version,
		Direction:         flowdocument.Direction(flowmsg.FlowDirection),
		Timestamp:         flowmsg.TimeReceived * 1000,
		DeltaSwitched:     &wrappers.UInt64Value{Value: (flowmsg.TimeFlowStart + p.offset) * 1000},
		FirstSwitched:     &wrappers.UInt64Value{Value: (flowmsg.TimeFlowStart + p.offset) * 1000},
		LastSwitched:      &wrappers.UInt64Value{Value: (flowmsg.TimeFlowEnd + p.offset) * 1000},
		SrcAddress:        srcAddress,
		SrcPort:           &wrappers.UInt32Value{Value: flowmsg.SrcPort},
		SrcAs:             &wrappers.UInt64Value{Value: uint64(flowmsg.SrcAS)},
		SrcMaskLen:        &wrappers.UInt32Value{Value: flowmsg.SrcNet},
		DstAddress:        dstAddress,
		DstPort:           &wrappers.UInt32Value{Value: flowmsg.DstPort},
		DstAs:             &wrappers.UInt64Value{Value: uint64(flowmsg.DstAS)},
		DstMaskLen:        &wrappers.UInt32Value{Value: flowmsg.DstNet},
		NextHopAddress:    nextHopeAddress,
		InputSnmpIfindex:  &wrappers.UInt32Value{Value: flowmsg.InIf},
		OutputSnmpIfindex: &wrappers.UInt32Value{Value: flowmsg.OutIf},
		TcpFlags:          &wrappers.UInt32Value{Value: flowmsg.TCPFlags},
		Protocol:          &wrappers.UInt32Value{Value: flowmsg.Proto},
		IpProtocolVersion: &wrappers.UInt32Value{Value: flowmsg.Etype},
		Tos:               &wrappers.UInt32Value{Value: flowmsg.IPTos},
		FlowSeqNum:        &wrappers.UInt64Value{Value: uint64(flowmsg.SequenceNum)},
		SamplingInterval:  &wrappers.DoubleValue{Value: float64(flowmsg.SamplingRate)},
		NumBytes:          &wrappers.UInt64Value{Value: flowmsg.Bytes},
		NumPackets:        &wrappers.UInt64Value{Value: flowmsg.Packets},
		Vlan:              strconv.Itoa(int(flowmsg.VlanId)),
		ExporterNode: &flowdocument.NodeInfo{
			ForeignSource: p.ForeignSource,
			ForeginId:     p.ForeignID,
			NodeId:        uint32(p.NodeID),
		},
	}
	return msg
}

func (p *FlowParser) wrapMessageToTelemetry(data [][]byte) []byte {
	now := uint64(time.Now().UnixNano() / int64(time.Millisecond))
	port := uint32(p.SourcePort)
	logMsg := &telemetry.TelemetryMessageLog{
		SystemId:      &p.MinionID,
		Location:      &p.MinionLocation,
		SourceAddress: &p.SourceAddress,
		SourcePort:    &port,
		Message:       make([]*telemetry.TelemetryMessage, len(data)),
	}
	for i := 0; i < len(data); i++ {
		logMsg.Message[i] = &telemetry.TelemetryMessage{
			Timestamp: &now,
			Bytes:     data[i],
		}
	}
	bytes, err := proto.Marshal(logMsg)
	if err != nil {
		log.Printf("Cannot serialize telemetry message: %v", err)
		return nil
	}
	return bytes
}

func (p *FlowParser) sendBytes(bytes []byte) {
	id := watermill.NewUUID()
	var current, total int32 = 1, 1
	msg := &sink.SinkMessage{
		MessageId:          &id,
		CurrentChunkNumber: &current,
		TotalChunks:        &total,
		Content:            bytes,
	}
	bytes, err := proto.Marshal(msg)
	if err != nil {
		log.Printf("Cannot serialize sink message: %v", err)
		return
	}
	log.Printf("Sending Sink Message of %d bytes to %s (broker: %s, location: %s)", len(bytes), p.KafkaTopic, p.KafkaServer, p.MinionLocation)
	err = p.publisher.Publish(p.KafkaTopic, message.NewMessage(id, bytes))
	if err != nil {
		log.Printf("Cannot send sink message: %v", err)
	}
}
