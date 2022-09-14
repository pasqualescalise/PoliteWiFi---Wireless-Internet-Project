package tui

import (
	"strconv"
	"strings"
	"unicode"
	"net"

	"github.com/rivo/tview"
	"github.com/gdamore/tcell/v2"
)

const (
	MAIN_WIDTH = 240
	MAIN_HEIGHT = 55
)

var (
	App  *tview.Application
	Pages *tview.Pages

	// main grid
	grid *tview.Grid

	// contains all objects on the screen, used to move between them
	loop_elements []tview.Primitive
	index = 0

	mac_field *tview.InputField
	wait_field *tview.InputField

	// set by the InputFields
	victim_mac []byte
	wait_time = 800
)

/**
* Create the TUI application
*/
func CreateNewApplication() {
	App = tview.NewApplication()

	main_grid := createMainGrid()
	SetCommonBoxAttributes(main_grid.Box, "Polite WIFI")

	main_window := CreateNewWindow(main_grid, "main")

	Pages = tview.NewPages().AddPage("main", main_window, true, true)

	// start the application
	if err := App.SetRoot(Pages, true).Run(); err != nil {
		panic(err)
	}
}

/**
* Create the grid of the main page, with the InputFields and the Buttons
**/
func createMainGrid() *tview.Grid {
	grid = tview.NewGrid()
	grid.SetRows(1/11, 2/11, 2/11, 1/11, 4/11, 1/11).SetColumns(1/13, 3/13, 1/13, 3/13, 1/13, 3/13, 1/13)

	createInputFields()
	createButtons()

	// move between the elements of the main grid using TAB
	grid.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Key() == tcell.KeyTab {
			index++;
			if index > len(loop_elements) - 1 {
				index = 0
			}
			setFocusOnMainGrid(index)
			return nil
		} else {
			return event
		}
	})

	return grid
}

/**
* Create the two InputFields, one for the MAC of the victim, the other for
* the waiting time between each packet
*/
func createInputFields() {
	// InputField for the MAC address
	mac_field = tview.NewInputField().SetLabel("MAC of the victim: ").
		SetAcceptanceFunc(inputFieldMACAddress) // only accept valid MAC chars

	// if the Enter key is pressed and the MAC is valid, go on with the attacks
	mac_field.SetDoneFunc(func(key tcell.Key) {
			if (!getMACFromField()) {
				return
			}

			setFocusOnMainGrid(1)
		})

	// InputField for the (optional) waiting time
	wait_field = tview.NewInputField().SetLabel("Wait time of packets [ms] (optional, default 1 packet every 800ms): ").
		SetAcceptanceFunc(tview.InputFieldInteger) // only accept integers

	// if the Enter key is pressed, go on with the attacks
	wait_field.SetDoneFunc(func(key tcell.Key) {
			setFocusOnMainGrid(2)
		})

	// add the InputFields to the grid
	grid.AddItem(mac_field, 1, 1, 1, 5, 0, 0, true)
	grid.AddItem(wait_field, 2, 1, 1, 5, 0, 0, true)

	loop_elements = append(loop_elements, mac_field)
	loop_elements = append(loop_elements, wait_field)
}

/**
* Create the three InputFields, one for each type of attack
*
* Procede with the attack only if the MAC inserted in the InputField is valid
*/
func createButtons() {
	// create button for the Test Attack
	test_button := tview.NewButton("Test Attack").SetSelectedFunc(func() {
		if getMACFromField() {
			LaunchTestAttack(victim_mac)
			index = 0
		}
	})

	// create button for the Dos/Battery Attack
	dosbat_button := tview.NewButton("DoS/Battery Attack").SetSelectedFunc(func() {
		if getMACFromField() {
			LaunchDoSBatAttack(victim_mac, getWaitTimeFromField())
			index = 0
		}
	})

	// create button for the Localization Attack
	local_button := tview.NewButton("Localization Attack").SetSelectedFunc(func() {
		if getMACFromField() {
			LaunchLocalizationAttack(victim_mac, getWaitTimeFromField())
			index = 0
		}
	})

	// add the Buttons to the grid
	grid.AddItem(test_button, 4, 1, 1, 1, 0, 0, true)
	grid.AddItem(dosbat_button, 4, 3, 1, 1, 0, 0, true)
	grid.AddItem(local_button, 4, 5, 1, 1, 0, 0, true)

	loop_elements = append(loop_elements, test_button)
	loop_elements = append(loop_elements, dosbat_button)
	loop_elements = append(loop_elements, local_button)
}

/**
* Parse the MAC that is currently in the InputField and return false if
* it's invalid
*/
func getMACFromField() bool {
	var err error
	victim_mac, err = net.ParseMAC(mac_field.GetText())
	if (err != nil) {
		mac_field.SetText("")
		setFocusOnMainGrid(0)
		return false
	}

	return true
}

/**
* Get the wait time that is currently in the InputField and return it, setting
* it to 1 if it's too small
*/
func getWaitTimeFromField() int {
	wait_time, _ = strconv.Atoi(wait_field.GetText())
	if wait_field.GetText() == "" {
		return 800
	} else if wait_time < 1 {
		return 1
	}

	return wait_time
}

/**
* Move the focus on the grid to the specified element
*/
func setFocusOnMainGrid(i int) {
	index = i;
	App.SetFocus(loop_elements[i])
}

/**
* Create a new window centering the Primitive
**/
func CreateNewWindow(primitive tview.Primitive, page_name string) *tview.Grid {
	new_window := tview.NewGrid()

	// go back pressing q -> can be overridden by the single component
	new_window.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		switch event.Rune() {
		case 'q':
			Pages.RemovePage(page_name)
			if Pages.GetPageCount() == 0 {
				App.Stop()
			}
		default:
			return event
		}

		return nil
	})

	return new_window.SetColumns(0, MAIN_WIDTH, 0).
		SetRows(0, MAIN_HEIGHT, 0).
		AddItem(primitive, 1, 1, 1, 1, 0, 0, true)
}

/**
* Create borders around the Box and add the title
**/
func SetCommonBoxAttributes(box *tview.Box, title string) {
	box.SetBorder(true).
		SetTitle(strings.ToUpper(title)).
		SetBorderPadding(2, 2, 4, 4)
}

/**
* Allow only MAC characters (exadecimal integers + colon)
*/
func inputFieldMACAddress(text string, ch rune) bool {
	return ch == ':' || ch == 'a' || ch == 'b' || ch == 'c' || ch == 'd' || ch == 'e' || ch == 'f' || unicode.IsDigit(ch)
}
