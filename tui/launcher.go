package tui

import (
	"strconv"
	"strings"

	"ProgWI/attack"

	"github.com/google/gopacket"

	"github.com/rivo/tview"
	"github.com/gdamore/tcell/v2"
)

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

	// create a new page to show the attack
	result := tview.NewTextView().
		SetText("Test the victim by sending one packet - Press q to go back to the main page").
		SetChangedFunc(func() {
			App.Draw()
		})
	SetCommonBoxAttributes(result.Box, "Test Attack")

	new_window := CreateNewWindow(result, "test")
	Pages.AddAndSwitchToPage("test", new_window, true)

	// send the commands on another thread to avoid blocking the main one
	go executeTestAttack(result, command_channel, ack_channel)
}

/**
* Send the commands to the other threads to actually start the attack
*
* Also update the TextView to tell the user what is happening
*/
func executeTestAttack(result *tview.TextView, command_channel chan bool, ack_channel chan gopacket.Packet) {
	// send a command to start the attack
	command_channel <- true
	result.SetText(result.GetText(true) + "\n\nSent one packet, waiting for the ACK...\n\nIf no ACK is received, the victim may be not vulnerable or the ACK was lost (try again)")

	// get the packet back
	<-ack_channel
	result.SetText(result.GetText(true) + "\n\nACK received, the victim is vulnerable\n\nPress q to go back to the main page and try other attacks")

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

	// launch the attack, the sniffer and the commander on separate threads
	go attack.StartAttack(victim_mac, command_channel)
	go attack.CaptureACKs(ack_channel, command_channel)
	go attack.ContinuousAttack(command_channel, done_channel, wait_time)

	sending_screen := tview.NewTextView().
		SetText("Transmitting 1 packet each " + strconv.Itoa(wait_time)  + "ms - Press q to go back to the main page")
	SetCommonBoxAttributes(sending_screen.Box, "DoS/Battery Attack")

	new_window := CreateNewWindow(sending_screen, "dosbat")

	// when the 'q' key is pressed, stop the attack and go back to the main page
	new_window.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		switch event.Rune() {
		case 'q':
			stopAttackAndGoBack(command_channel, done_channel, "dosbat")
		default:
			return event
		}

		return nil
	})

	Pages.AddAndSwitchToPage("dosbat", new_window, true)
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

	// launch the attack, the sniffer and the commander on separate threads
	go attack.StartAttack(victim_mac, command_channel)
	go attack.CaptureACKs(ack_channel, command_channel)
	go attack.ContinuousAttack(command_channel, done_channel, wait_time)

	display_string := "Transmitting 1 packet each " + strconv.Itoa(wait_time)  + "ms - Press q to go back to the main page\n\n"
	display_string += "These are the Received Signal Strength Indicator [dBm] of the last 5 packets\n\n"
	display_string += "They can be used to localize the victim, since they become higher (they're negative numbers) the closer the attacker is to the victim\n\n"

	rssi_screen := tview.NewTextView().
		SetText(display_string).
		SetChangedFunc(func() {
			App.Draw()
		})
	SetCommonBoxAttributes(rssi_screen.Box, "Localization Attack")

	// get ACKs from the ack channel and display them on the screen
	go updateTextViewWithRSSI(rssi_screen, display_string, ack_channel, done_channel)

	new_window := CreateNewWindow(rssi_screen, "local")

	// when the 'q' key is pressed, stop the attack and go back to the main page
	new_window.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		switch event.Rune() {
		case 'q':
			stopAttackAndGoBack(command_channel, done_channel, "local")
		default:
			return event
		}

		return nil
	})

	Pages.AddAndSwitchToPage("local", new_window, true)
}

/**
* Stop a continuous attack and go back to the main page
*/
func stopAttackAndGoBack(command_channel chan bool, done_channel chan bool, page_name string) {
	done_channel <- true
	Pages.RemovePage(page_name)
	if Pages.GetPageCount() == 0 {
		App.Stop()
	}
}

/**
* Get the captured ACKs from the channel and put the last 15 RSSIs on the TextView
*/
func updateTextViewWithRSSI(rssi_screen *tview.TextView, display_string string, ack_channel chan gopacket.Packet, done_channel chan bool) {
	var RSSIs []string

	for {
		select {
		// stop if the attack is done
		case <- done_channel:
			return
		default:
			ack := <-ack_channel
			RSSIs = append([]string{attack.GetRSSI(ack) + " dBm"}, RSSIs...)
			if (len(RSSIs) > 15) {
				RSSIs = RSSIs[:len(RSSIs) - 1]
			}

			rssi_screen.SetText(display_string + strings.Join(RSSIs, "\n"))
		}
	}
}
