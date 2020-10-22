// Liquid Ping - Version 1.0 Beta 1

// Copyright (c) 2020, Liquid Telecommunications
// All rights reserved.
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
// * Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
// * Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer
//   in the documentation and/or other materials provided with the distribution.
// * Neither the name of the <organization> nor the names of its contributors may be used to endorse or promote products derived from
//   this software without specific prior written permission.
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// LIQUID TELECOMMUNICATIONS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
// NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
// ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"io/ioutil"
	"math"
	"math/rand"
	"net"
	"os"
	"runtime"
	"strings"
	"time"
	"unsafe"
)

// Various header offsets and codes
const (
	DefaultPingCount     = 10
	DefaultPayloadLength = 8
	V4EchoRequestType    = uint8(8)
	V6EchoRequestType    = uint8(128)
	HdrSize              = uint8(8)
	TimestampSize        = uint8(16)
	BodyOffset           = uint8(4)
	IdSequenceSize       = uint8(4)
	DataOffset           = uint8(24)
	TimestampOffset      = 8
	TrackerOffset        = 16
	ChecksumOffset       = 2
	HeaderTotalSize      = 28
)

// Constants used for our dynamic poller notifications
const (
	UpdatedRepetitions    = uint8(2)
	UpdatedPacketInterval = uint8(3)
	UpdatedFrequency      = uint8(4)
	UpdatedProtocol       = uint8(5)
	UpdatedCount          = uint8(6)
	UpdatedTimeout        = uint8(7)
	UpdatedPayloadSize    = uint8(8)
)

// InPkt is what we parse returned packets into
type InPkt struct {
	Buffer   []byte
	RecvTime time.Time
	TTL      int
	RecvSize int
	Dest     *net.IPAddr
	Poller   *Poller
}

// GetRTTMillisecond returns the RTT of the packet in a float64 format
func (in *InPkt) GetRTTMillisecond() float64 {
	return float64(in.RecvTime.Sub(BytesToTime(in.Buffer[TimestampOffset:]))*time.Millisecond) / 1000000000000
}

// Poller is the main structure containing the poller for each destination
type Poller struct {
	Dest            *net.IPAddr
	PacketInterval  time.Duration
	Timeout         time.Duration
	Count           int
	PayloadSize     int
	UdpTracker      uint64
	Source          string
	OutChannel      chan interface{}
	ControlChan     chan uint8
	IsIPv4          bool
	UseUDP          bool
	UseICMP         bool
	UdpConn         net.PacketConn
	PollRepetitions int
	PollFrequency   time.Duration
	GenericPacket   PacketICMP
	Conn            icmp.PacketConn
	RecvPackets     []*InPkt
	Running         bool
	ErrStatus       error
	network         string
}

// NewPoller instantiates a new poller instance with a bunch of default options
func NewPoller(Dest string, Source string, Frequency int, Out chan interface{}) (*Poller, error) {
	var err error
	res := new(Poller)
	if res.Dest, err = net.ResolveIPAddr("ip", Dest); err != nil {
		res = nil
		return nil, fmt.Errorf("invalid destination address specified")
	}
	// Check if this is an IPv4 address that we've parsed - if its not - and its valid - assume its a valid
	// IPv6 address
	if *(*uint64)(unsafe.Pointer(&res.Dest.IP[0])) == 0 &&
		*(*uint16)(unsafe.Pointer(&res.Dest.IP[8])) == 0 &&
		*(*uint16)(unsafe.Pointer(&res.Dest.IP[10])) == 0xFFFF {
		res.IsIPv4 = true
		if runtime.GOOS == "windows" {
			res.network = "ip4:icmp"
		} else {
			res.network = "udp4"

		}
	} else {
		res.IsIPv4 = false
		if runtime.GOOS == "windows" {
			res.network = "ip6:icmp"
		} else {
			res.network = "udp6"
		}
	}
	res.PacketInterval = 1 * time.Second
	res.Timeout = 1 * time.Second
	res.Count = DefaultPingCount
	res.PayloadSize = DefaultPayloadLength
	res.UdpTracker = uint64(rand.Intn(math.MaxInt16))
	res.Source = "0.0.0.0"
	res.OutChannel = Out
	res.UseUDP = true
	res.UseICMP = false
	res.RecvPackets = make([]*InPkt, res.Count)
	for i := range res.RecvPackets {
		res.RecvPackets[i] = &InPkt{Buffer: make([]byte, 9200), Dest: res.Dest, Poller: res}
	}
	res.GenericPacket = res.constructEchoRequest(res.PayloadSize)
	res.GenericPacket.SetID(uint16(rand.Intn(math.MaxInt16)))
	res.GenericPacket.SetTracker(res.UdpTracker)
	res.Source = Source
	res.PollFrequency = time.Duration(Frequency) * time.Second
	return res, nil
}

// notifyChan exists for doing dynamic poller changes - this is currently not implemented
func (p *Poller) notifyChan(ControlCode uint8) {
	if p.Running {
		p.ControlChan <- ControlCode
	}
}

// SetPacketInterval sets the interval between packets - not currently implemented, we send packets the moment we get replies
func (p *Poller) SetPacketInterval(interval int) {
	p.PacketInterval = time.Duration(interval) * time.Second
	p.notifyChan(UpdatedPacketInterval)
}

// SetTimeout sets the overall timeout on a polling run - needs further implementation
func (p *Poller) SetTimeout(timeout int) {
	p.Timeout = time.Duration(timeout) * time.Second
	p.notifyChan(UpdatedTimeout)
}

// SetCount sets the number of packets per polling iteration
func (p *Poller) SetCount(count int) {
	if count > p.Count {
		for i := 0; i < count-p.Count; i++ {
			p.RecvPackets = append(p.RecvPackets, &InPkt{Buffer: make([]byte, 9200)})
		}
	} else if count < p.Count {
		for i := 0; i < p.Count-count; i++ {
			p.RecvPackets[0] = nil
			p.RecvPackets = p.RecvPackets[1:]
		}
	}
	p.notifyChan(UpdatedCount)
}

// SetICMP sets up to use privileged mode
func (p *Poller) SetICMP() {
	p.UseICMP = true
	p.UseUDP = false
	if p.IsIPv4 {
		p.network = "ip:icmp"
	} else {
		p.network = "ip6:ipv6-icmp"
	}
	p.notifyChan(UpdatedProtocol)
}

// SetUDP sets up to use "UDP" mode - this is still ICMP, its just a very different way of creating the socket
func (p *Poller) SetUDP() {
	p.UseUDP = true
	p.UseICMP = false
	if p.IsIPv4 {
		p.network = "udp4"
	} else {
		p.network = "udp6"
	}
	p.notifyChan(UpdatedProtocol)
}

// SetRepetitions sets the number of poll cycles
func (p *Poller) SetRepetitions(repetitions int) {
	p.PollRepetitions = repetitions
	p.notifyChan(UpdatedRepetitions)
}

// SetFrequency sets the frequency of poll cycles - this is effectively a delay between each poll cycle
func (p *Poller) SetFrequency(frequency int) {
	p.PollFrequency = time.Duration(frequency) * time.Second
	p.notifyChan(UpdatedFrequency)
}

// SetPayloadSize sets the payload size of each packet
func (p *Poller) SetPayloadSize(pSize int) {
	p.PayloadSize = pSize
	p.GenericPacket = nil
	p.GenericPacket = p.constructEchoRequest(pSize)
	p.notifyChan(UpdatedPayloadSize)
}

func (p *Poller) listen() error {
	var err error
	if p.UseUDP {
		if p.UdpConn, err = net.ListenPacket("udp", p.Source); err != nil {
			return err
		}
		return nil
	}
	return fmt.Errorf("currently set in ICMP Mode, only UDP is supported at present")
}

// constructEchoRequest constructs a default ping packet that can be manipulated, dataLen is the payload size
// after header size
func (p *Poller) constructEchoRequest(dataLen int) PacketICMP {
	packet := PacketICMP(make([]byte, int(HdrSize+IdSequenceSize+TimestampSize)+dataLen))
	if p.IsIPv4 {
		packet.SetType(V4EchoRequestType)
	} else {
		packet.SetType(V6EchoRequestType)
	}
	packet.SetDataBytes(0xFF)
	return packet
}

// Run runs the poller in question
func (p *Poller) Run(ErrorChan chan *Poller, QueueChan chan bool) {
	var err error
	var conn *icmp.PacketConn
	var completed = 0

	p.Running = false
	for {
		QueueChan <- true
		if conn, err = icmp.ListenPacket(p.network, p.Source); err != nil {
			p.ErrStatus = err
			ErrorChan <- p
			return
		}
		if runtime.GOOS != "windows" {
			if p.IsIPv4 {
				_ = conn.IPv4PacketConn().SetControlMessage(ipv4.FlagTTL, true)
			} else {
				_ = conn.IPv6PacketConn().SetControlMessage(ipv6.FlagHopLimit, true)
			}
		}
		rChan, sChan := make(chan bool), make(chan bool)
		go p.ReceivePackets(conn, rChan, sChan)
		if SendErr := p.SendPacket(conn, rChan, sChan); SendErr != nil {
			ErrorChan <- &Poller{Dest: p.Dest, ErrStatus: SendErr, Running: false}
		}
		p.OutChannel <- p.RecvPackets
		close(rChan)
		close(sChan)
		_ = conn.Close()
		<-QueueChan
		if p.PollRepetitions > 0 {
			completed++
			if completed > p.PollRepetitions {
				ErrorChan <- &Poller{ErrStatus: nil, Running: false}
				return
			}
		}
		<-time.After(p.PollFrequency)
	}
}

// ReceivePackets is used to receive the reply packets - this is typically started as a go routing
func (p *Poller) ReceivePackets(conn *icmp.PacketConn, RecvChan chan bool, SendChan chan bool) {
	var err error
	Offset := 0
	for {
		select {
		case ok := <-SendChan:
			if !ok {
				return
			}
			if connErr := conn.SetReadDeadline(time.Now().Add(time.Duration(3) * time.Second)); connErr != nil {
				fmt.Printf("Error setting read deadline\n")
			}
			if p.IsIPv4 {
				var cm *ipv4.ControlMessage
				p.RecvPackets[Offset].RecvSize, cm, _, err = conn.IPv4PacketConn().ReadFrom(p.RecvPackets[Offset].Buffer)
				if cm != nil {
					p.RecvPackets[Offset].TTL = cm.TTL
				}
			} else {
				var cm *ipv6.ControlMessage
				p.RecvPackets[Offset].RecvSize, cm, _, err = conn.IPv6PacketConn().ReadFrom(p.RecvPackets[Offset].Buffer)
				if cm != nil {
					p.RecvPackets[Offset].TTL = cm.HopLimit
				}
			}
			if err != nil {
				if netErr, ok := err.(*net.OpError); ok {
					if netErr.Timeout() {
						p.RecvPackets[Offset].Buffer = make([]byte, 0)
						Offset++
						RecvChan <- true
						continue
					}
				} else {
					fmt.Printf("Got some other error: %v\n", err)
					_ = conn.Close()
					RecvChan <- false
				}
			} else {
				p.RecvPackets[Offset].RecvTime = time.Now()
				p.RecvPackets[Offset].Buffer = p.RecvPackets[Offset].Buffer[:p.RecvPackets[Offset].RecvSize]
				Offset++
				RecvChan <- true
			}
		}
		if Offset == p.Count {
			break
		}
	}
}

// SendPacket is the packet sender - this should be started normally so that it blocks until end of poller cycle
func (p *Poller) SendPacket(conn *icmp.PacketConn, RecvChan chan bool, SendChan chan bool) error {
	Count := uint16(0)
	var dst net.Addr = p.Dest
	if runtime.GOOS != "windows" {
		dst = &net.UDPAddr{IP: p.Dest.IP, Zone: p.Dest.Zone}
	}
	for {
		p.GenericPacket.SetSeq(Count)
		p.GenericPacket.SetTimestamp(time.Now())
		p.GenericPacket.SetChecksum()
		if _, err := conn.WriteTo(p.GenericPacket, dst); err != nil {
			SendChan <- false
			return err
		}
		SendChan <- true
		if ok := <-RecvChan; !ok {
			return fmt.Errorf("receiver signalled an error")
		}
		Count++
		if Count == uint16(p.Count) {
			break
		}
	}
	return nil
}

// IsBigEndian is a helper function to test the endianness of the host system
func IsBigEndian() bool {
	var x = 0x0100
	if (*(*byte)(unsafe.Pointer(&x))) == 0x01 {
		return true
	}
	return false
}

// SwapUint64 reverses the byte order of a unsigned 64 bit integer
func SwapUint64(x uint64) uint64 {
	return 0 |
		((x & 0xFF) << 56) |
		((x & 0xFF00) << 40) |
		((x & 0xFF0000) << 24) |
		((x & 0xFF000000) << 8) |
		((x & 0xFF00000000) >> 8) |
		((x & 0xFF0000000000) >> 24) |
		((x & 0xFF000000000000) >> 40) |
		((x & 0xFF00000000000000) >> 56)
}

// SwapUint16 reverses the byte order for an unsigned 16 bit integer
func SwapUint16(x uint16) uint16 {
	return x<<8 | x>>8
}

// PacketICMP type is used for storing and manipulating packets at byte level
type PacketICMP []byte

// SetDataBytes sets the value of padding bytes
func (icp *PacketICMP) SetDataBytes(val uint8) {
	if len(*icp)-1 > int(DataOffset) {
		for x := int(DataOffset); x < len(*icp); x++ {
			(*icp)[x] = val
		}
	}
}

// BytesToTime converts the byte slice provided to a time.Time
func BytesToTime(b []byte) time.Time {
	nano := *(*int64)(unsafe.Pointer(&b[0]))
	return time.Unix(nano/1000000000, nano%1000000000)
}

// SetTimestamp sets the timestamp in the ICMP packet
func (icp *PacketICMP) SetTimestamp(t time.Time) {
	nanoseconds := t.UnixNano()
	nanoBytes := (*[8]byte)(unsafe.Pointer(&nanoseconds))[:]
	copy((*icp)[TimestampOffset:], nanoBytes)
}

// SetChecksum sets the checksum in the ICMP packet
func (icp *PacketICMP) SetChecksum() {
	ZeroBytes := []byte{0, 0}
	coverage := len(*icp) - 1
	s := uint32(0)
	copy((*icp)[ChecksumOffset:], ZeroBytes)
	for i := 0; i < coverage; i += 2 {
		s += uint32((*icp)[i+1])<<8 | uint32((*icp)[i])
	}
	if coverage&1 == 0 {
		s += uint32((*icp)[coverage])
	}
	s = s>>16 + s&0xFFFF
	s = s + s>>16
	checksum := ^uint16(s)
	(*icp)[ChecksumOffset] ^= byte(checksum)
	(*icp)[ChecksumOffset+1] ^= byte(checksum >> 8)
}

// SetTracker sets the tracking portion of the packet
func (icp *PacketICMP) SetTracker(tracker uint64) {
	if IsBigEndian() {
		copy((*icp)[TrackerOffset:], (*[8]byte)(unsafe.Pointer(&tracker))[:])
	} else {
		t := SwapUint64(tracker)
		copy((*icp)[TrackerOffset:], (*[8]byte)(unsafe.Pointer(&t))[:])
	}
}

// SetType sets the ICMP type
func (icp *PacketICMP) SetType(typ uint8) {
	(*icp)[0] = typ
}

// SetID sets the flow ID of the ICMP packet
func (icp *PacketICMP) SetID(id uint16) {
	var id16 uint16
	if IsBigEndian() {
		copy((*icp)[BodyOffset:], (*[2]byte)(unsafe.Pointer(&id))[:])
	} else {
		id16 = SwapUint16(id)
		copy((*icp)[BodyOffset:], (*[2]byte)(unsafe.Pointer(&id16))[:])
	}
}

// SetSeq sets the sequence number of the ICMP packet
func (icp *PacketICMP) SetSeq(seq uint16) {
	var id16 uint16
	if IsBigEndian() {
		copy((*icp)[BodyOffset+2:], (*[2]byte)(unsafe.Pointer(&seq))[:])
	} else {
		id16 = SwapUint16(seq)
		copy((*icp)[BodyOffset+2:], (*[2]byte)(unsafe.Pointer(&id16))[:])
	}
}

// CollateStats calculates packet loss, and minimum, average, maximum of ping runs
// This will print results to console unless an outbound channel is specified
// via the variadic argument, in which case stats are returned via the channel.
func CollateStats(in chan interface{}, jsonOutput, jsonPretty bool, out ...chan string) {
	type jsonStruct struct {
		DeviceIP string  `json:"Destination"`
		Min      float64 `json:"Minimum"`
		Avg      float64 `json:"Average"`
		Max      float64 `json:"Maximum"`
		Dev      float64 `json:"Deviation"`
		Loss     float64 `json:"PacketLoss"`
	}
	var jOut *jsonStruct

	for {
		select {
		case data := <-in:
			pCount := float64(len(data.([]*InPkt)))
			var Avg, Min, Max float64 = 0, 0xFFFF, 0
			var respCount = float64(0)
			for _, p := range data.([]*InPkt) {
				if len(p.Buffer) < 16 {
					continue
				} else {
					Last := p.GetRTTMillisecond()
					if Last < Min {
						Min = Last
					}
					if Last > Max {
						Max = Last
					}
					Avg += Last
					respCount++
				}
			}
			if respCount != 0 {
				Percentage := 100 - (respCount/pCount)*100
				Avg = Avg / respCount
				if len(out) > 0 {
					out[0] <- fmt.Sprintf("[%s] [%d byte payload size] [%.2f%% packet loss] [%.2f Min %.2f Average %.2f Max %.2f Jitter]\n",
						data.([]*InPkt)[0].Dest, len(data.([]*InPkt)[0].Buffer)-HeaderTotalSize,
						Percentage, Min, Avg, Max, Max-Min)
				} else if jsonOutput {
					jOut = &jsonStruct{
						DeviceIP: data.([]*InPkt)[0].Dest.String(),
						Min:      Min,
						Avg:      Avg,
						Max:      Max,
						Dev:      Max - Min,
						Loss:     Percentage,
					}
					if jsonPretty {
						if jString, err := json.MarshalIndent(jOut, "", "\t"); err == nil {
							fmt.Printf("%s\n", string(jString))
						}
					} else {
						if jString, err := json.Marshal(jOut); err == nil {
							fmt.Printf("%s\n", string(jString))
						}
					}
				} else {
					fmt.Printf("[%s] [%d byte payload size] [%.2f%% packet loss] [%.2f Min %.2f Average %.2f Max %.2f Jitter]\n",
						data.([]*InPkt)[0].Dest, len(data.([]*InPkt)[0].Buffer)-HeaderTotalSize,
						Percentage, Min, Avg, Max, Max-Min)
				}
			} else {
				if len(out) > 0 {
					out[0] <- fmt.Sprintf("[%s] [100%% packet loss]\n", data.([]*InPkt)[0].Dest)
				} else {
					fmt.Printf("[%s] [100%% packet loss]\n", data.([]*InPkt)[0].Dest)
				}
			}
		}
	}
}

// CompiledFor is used for command line compilation of limited usage compiles - to use this compile with:
// go build -ldflags="-X main.CompiledFor=xxxxx"
func main() {
	var destinations []string
	var err error
	var RunningPollers = 0

	sourceIP := flag.String("source", "0.0.0.0", "Source of pings")
	destFile := flag.String("destination-file", "", "Destination file containing destination IP addresses")
	destination := flag.String("destination", "", "Single host destination")
	repetitions := flag.Int("repetitions", 10, "Number of poll cycles")
	repFrequency := flag.Int("frequency", 120, "Delay in seconds between polling cycles")
	dataSize := flag.Int("payload-size", 0, "ICMP Payload size")
	packetRep := flag.Int("packet-reps", 10, "Number of packets per repetition")
	maxConcurrent := flag.Int("max-concurrent", 1000, "Maximum concurrent polling sessions")
	jsonOutput := flag.Bool("json-output", false, "Print output in json format")
	jsonPretty := flag.Bool("json-pretty", false, "Print output in json format with pretty print")

	flag.Parse()

	if destinations, err = validateFlags(
		sourceIP, destFile, destination, repetitions, repFrequency, dataSize, packetRep, maxConcurrent); err != nil {
		fmt.Printf("Invalid usage: %v\n", err)
		fmt.Printf("Usage:\n")
		flag.PrintDefaults()
		return
	}

	StatChan := make(chan interface{})
	go CollateStats(StatChan, *jsonOutput, *jsonPretty)
	ErrChan := make(chan *Poller)
	QueueChan := make(chan bool, *maxConcurrent)
	Pollers := make([]*Poller, len(destinations))
	for i, ip := range destinations {
		if Pollers[i], err = NewPoller(ip, *sourceIP, *repFrequency, StatChan); err == nil {
			if *repetitions > 0 {
				Pollers[i].SetRepetitions(*repetitions)
			}
			Pollers[i].SetPayloadSize(*dataSize)
			Pollers[i].SetCount(*packetRep)
			Pollers[i].SetFrequency(*repFrequency)
			Pollers[i].Source = *sourceIP
			go Pollers[i].Run(ErrChan, QueueChan)
			RunningPollers++
		} else {
			fmt.Printf("[%d] Error: %v\n", i, err)
		}
	}
	for {
		select {
		case x := <-ErrChan:
			if x.ErrStatus != nil {
				fmt.Printf("Poller for %s exited due to error: %v\n", x.Dest, x.ErrStatus)
			}
			RunningPollers--
			if RunningPollers == 0 {
				fmt.Printf("Completed all polling runs, exiting\n")
				return
			}
		case <-time.After(1 * time.Second):
			break
		}
	}
}

func validateFlags(sip, df, d *string, rep, repF, ds, prep, mc *int) ([]string, error) {
	var res = make([]string, 0)
	// Validate the source IP
	if net.ParseIP(*sip) == nil {
		return nil, fmt.Errorf("invalid source ip specified")
	}
	if *prep < 0 || *prep > 100 {
		return nil, fmt.Errorf("packet repetitions per polling run should be between 0 and 100")
	}
	if *ds < 0 || *ds > 9000 {
		return nil, fmt.Errorf("data size should be between 0 and 9000 [specifying larger than MTU will result in failures]")
	}
	if *rep < 1 {
		return nil, fmt.Errorf("repetitions should be 1 or greater")
	}
	if *repF < 30 {
		return nil, fmt.Errorf("repetition frequency needs to be 30 or larger")
	}
	if *mc < 1 {
		return nil, fmt.Errorf("maximum concurrency must be at least 1")
	}

	// Validate destination file or destination host
	if len(*df) == 0 && len(*d) == 0 {
		return nil, fmt.Errorf("no destinations specified")
	} else if len(*df) > 0 {
		if f, err := os.Open(*df); err != nil {
			return nil, fmt.Errorf("failed to open destinations file [%s]: %v", *df, err)
		} else {
			data, _ := ioutil.ReadAll(f)
			ips := strings.Split(string(data), "\n")
			for _, ip := range ips {
				if ipa := net.ParseIP(strings.TrimSpace(ip)); ipa != nil {
					res = append(res, ip)
				}
			}
			if len(res) != 0 {
				return res, nil
			}
		}
	} else if ipa := net.ParseIP(strings.TrimSpace(*d)); ipa != nil {
		return []string{*d}, nil
	}
	return nil, fmt.Errorf("no valid ip addresses in destination file")
}
