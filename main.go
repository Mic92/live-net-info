package main

import (
	"bytes"
	"fmt"
	"math"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
	lg "github.com/charmbracelet/lipgloss"
)

type model struct {
	err         error
	pingResults []pingResult
	mtuResults  []mtuResult
	gatewayResults []gatewayResult
	dnsResults dnsResult
	table       table.Model
	pingRow     *table.Row
	mtuRow      *table.Row
	gatewayRow  *table.Row
	dnsRow      *table.Row
	interfaceRow  *table.Row
}

type pingResult struct {
	address     net.IP
	millisconds float64
	err         error
}

func pingError(address net.IP, err error) pingResult {
	return pingResult{
		address:     address,
		millisconds: 0,
		err:         err,
	}
}

func runPing(address net.IP, delay time.Duration) tea.Cmd {
	return func() tea.Msg {
		time.Sleep(delay)
		c := exec.Command("ping", "-c1", address.String())
		var stderr bytes.Buffer
		var stdout bytes.Buffer
		c.Stderr = &stderr
		c.Stdout = &stdout

		err := c.Run()
		if err != nil {
			return pingError(address, fmt.Errorf("ping failed: %v (%s)", err, strings.TrimSpace(stderr.String())))
		}
		re := regexp.MustCompile(`(?m:^rtt min/avg/max/mdev = ([0-9.]+)/([0-9.]+)/([0-9.]+)/([0-9.]+) ms$)`)
		match := re.FindSubmatch(stdout.Bytes())
		if match == nil {
			return pingError(address, fmt.Errorf("unable to parse ping output: %s", stdout))
		}
		avgRtt, err := strconv.ParseFloat(string(match[2]), 64)
		if err != nil {
			return pingError(address, fmt.Errorf("unable to parse average ping time: %s", match[2]))
		}
		return pingResult{
			address:     address,
			millisconds: avgRtt,
			err:         nil,
		}
	}
}

type mtuResult struct {
	address net.IP
	mtu     uint16
	err     error
}

func isIpv6(address net.IP) bool {
	return address.To4() == nil
}
func ipFamilyIndex(address net.IP) uint {
	if isIpv6(address) {
		return 1
	}
	return 2
}

func runMtuProbe(address net.IP, delay time.Duration) tea.Cmd {
	var overhead uint16
	if isIpv6(address) {
		overhead = 48 // ipv6
	} else {
		overhead = 28 // ipv4
	}
	const minMTU = uint16(1100)
	const maxMTU = uint16(9000)
	lowerBound := minMTU
	upperBound := maxMTU
	packetSize := minMTU
	pingProbe := func() uint16 {
		for {
			args := []string{"-c1", "-s", strconv.Itoa(int(packetSize)), "-M", "do", address.String()}

			c := exec.Command("ping", args...)

			err := c.Run()
			if err == nil { // packet was sent
				if packetSize == maxMTU {
					return packetSize
				}
				lowerBound = packetSize
				packetSize = (packetSize + upperBound) / 2
				if packetSize == upperBound-1 || packetSize == upperBound {
					return upperBound
				}
			} else {
				if packetSize == minMTU {
					return 0
				}
				upperBound = packetSize
				packetSize = (packetSize + lowerBound) / 2
				if packetSize == lowerBound-1 || packetSize == lowerBound {
					return lowerBound
				}
			}
		}
	}

	return func() tea.Msg {
		time.Sleep(delay)
		packetSize := pingProbe()
		if packetSize != 0 {
			packetSize += overhead
		}
		return mtuResult{
			address: address,
			mtu:     packetSize,
		}
	}
}

func (m model) Init() tea.Cmd {
	batches := []tea.Cmd{
		updateDefaultGateway(true, 0),
		updateDefaultGateway(false, 0),
		updateDnsServers(0),
	}
	for _, result := range m.pingResults {
		batches = append(batches, runPing(result.address, 0))
		f := runMtuProbe(result.address, 0)
		batches = append(batches, f)
	}
	return tea.Batch(batches...)
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q":
			return m, tea.Quit
		}
	case pingResult:
		for i, r := range m.pingResults {
			if r.address.Equal(msg.address) {
				m.pingResults[i] = msg
				break
			}
		}
		return m, runPing(msg.address, time.Second)
	case mtuResult:
		for i, r := range m.mtuResults {
			if r.address.Equal(msg.address) {
				m.mtuResults[i] = msg
				break
			}
		}
		return m, runMtuProbe(msg.address, time.Second*5)
	case gatewayResult:
		for i, r := range m.gatewayResults {
			if r.ipv6 == msg.ipv6 {
				m.gatewayResults[i] = msg
				break
			}
		}
		return m, updateDefaultGateway(msg.ipv6, time.Second*5)
	case dnsResult:
		m.dnsResults = msg
		return m, updateDnsServers(time.Second*5)
	}
	var cmd tea.Cmd
	m.table, cmd = m.table.Update(msg)
	return m, cmd
}

// Get default gateway using the iproute2 command
func getDefaultGateway(ipv6 bool) (net.IP, string, error) {
	var args []string
	if ipv6 {
		args = append(args, "-6")
	}
	args = append(args, "route", "show", "default")
	out, err := exec.Command("ip", args...).Output()
	if err != nil {
		return nil, "", fmt.Errorf("error getting default gateway: %v", err)
	}
	if len(out) == 0 {
		return nil, "-", nil
	}
	fields := strings.Fields(string(out))
	if len(fields) < 5 {
		return nil, "", fmt.Errorf("error parsing default gateway from: %s", string(out))
	}
	gateway := net.ParseIP(fields[2])
	if gateway == nil {
		return nil, "", fmt.Errorf("error parsing default gateway from: %s", string(out))
	}
	return gateway, fields[4], nil
}

// Parses the current active DNS server from resolvectl
func getDnsServers() ([]net.IP, error) {
	out, err := exec.Command("resolvectl", "dns").Output()
	if err != nil {
		return nil, fmt.Errorf("error getting DNS server from resolvectl: %v", err)
	}
	var dnsServers []net.IP
	// Link 3 (wlp170s0): 192.168.1.1 fdea:dd07:18a9::1
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		fields := strings.SplitN(line, ":", 2)
		if len(fields) < 2 {
			continue
		}
		for _, field := range strings.Fields(fields[1]) {
			dnsServers = append(dnsServers, net.ParseIP(field))
		}
	}
	return dnsServers, nil
}

type gatewayResult struct {
	address net.IP
	interfaceName string
	err     error
	ipv6    bool
}

type dnsResult struct {
	addresses []net.IP
	err       error
}


func updateDefaultGateway(ipv6 bool, delay time.Duration) tea.Cmd {
	return func() tea.Msg {
		time.Sleep(delay)
		address, interfaceName, err := getDefaultGateway(ipv6)
		if err != nil {
			return gatewayResult{
				address: nil,
				interfaceName: "",
				err: err,
				ipv6: ipv6,
			}
		}
		return gatewayResult{
			address:  address,
			interfaceName: interfaceName,
			err: nil,
			ipv6: ipv6,
		}
	}
}

func updateDnsServers(delay time.Duration) tea.Cmd {
	return func() tea.Msg {
		time.Sleep(delay)
		addresses, err := getDnsServers()
		return dnsResult{
			addresses: addresses,
			err: err,
		}
	}
}

func renderPingResult(result *pingResult) string {
	if result.err == nil {
		if math.IsInf(result.millisconds, 1) {
			return "unknown"
		} else {
			return fmt.Sprintf("%0.2f ms", result.millisconds)
		}
	} else {
		return result.err.Error()
	}
}

func renderMtuResult(result *mtuResult) string {
	if result.err == nil {
		if result.mtu == 0 {
			return "unknown"
		} else {
			return fmt.Sprintf("%d Bytes", result.mtu)
		}
	} else {
		return result.err.Error()
	}
}

func renderGatewayResult(result *gatewayResult) string {
	if result.err == nil {
		if result.address == nil {
			return "-"
		} else {
			return result.address.String()
		}
	} else {
		return result.err.Error()
	}
}

var baseStyle = lg.NewStyle().
	BorderStyle(lg.NormalBorder()).
	BorderForeground(lg.Color("240"))

func (m model) View() string {
	if m.err != nil {
		return "Error: " + m.err.Error() + "\n"
	}

	for _, result := range m.pingResults {
		(*m.pingRow)[ipFamilyIndex(result.address)] = renderPingResult(&result)
	}
	for _, result := range m.mtuResults {
		(*m.mtuRow)[ipFamilyIndex(result.address)] = renderMtuResult(&result)
	}
	for _, result := range m.gatewayResults {
		(*m.gatewayRow)[ipFamilyIndex(result.address)] = renderGatewayResult(&result)
		(*m.interfaceRow)[ipFamilyIndex(result.address)] = result.interfaceName
	}
	dnsServers := make([][]string, 2)
	if m.dnsResults.err != nil {
		(*m.dnsRow)[1] = m.dnsResults.err.Error()
	} else {
		for _, result := range m.dnsResults.addresses {
			idx := ipFamilyIndex(result) - 1
			dnsServers[idx] = append(dnsServers[idx], result.String())
		}
		for i, servers := range dnsServers {
			(*m.dnsRow)[i + 1] = strings.Join(servers, ", ")
		}
	}

	m.table.UpdateViewport()

	return baseStyle.Render(m.table.View()) + "\n"
}

func pingAddresses(addresses ...net.IP) []pingResult {
	addressMap := make([]pingResult, len(addresses))
	for i := range addresses {
		addressMap[i] = pingResult{
			address:     addresses[i],
			millisconds: math.Inf(1),
			err:         nil,
		}
	}
	return addressMap
}
func mtuAddresses(addresses ...net.IP) []mtuResult {
	addressMap := make([]mtuResult, len(addresses))
	for i := range addresses {
		addressMap[i] = mtuResult{
			address: addresses[i],
			mtu:     0,
			err:     nil,
		}
	}
	return addressMap
}

func main() {
	googleDNSv4 := net.ParseIP("8.8.8.8")
	googleDNSv6 := net.ParseIP("2001:4860:4860::8888")

	// if NETCHECK_DEBUG is set, log to file
	if os.Getenv("NETCHECK_DEBUG") != "" {
		f, err := tea.LogToFile("netcheck.log", "netcheck")
		if err != nil {
			fmt.Printf("cannot open log: %v", err)
			os.Exit(1)
		}
		defer f.Close()
	}

	columns := []table.Column{
		{Title: "", Width: 10},
		{Title: "Ipv6", Width: 25},
		{Title: "Ipv4", Width: 25},
	}

	rows := []table.Row{
		{"Ping", "-", "-"},
		{"MTU", "unknown", "unknown"},
		{"Gateway", "-", "-"},
		{"DNS", "-", "-"},
		{"Interface", "-", "-"},
	}
	pingRow := &rows[0]
	mtuRow := &rows[1]
	gatewayRow := &rows[2]
	dnsRow := &rows[3]
	interfaceRow := &rows[4]

	t := table.New(
		table.WithColumns(columns),
		table.WithRows(rows),
		table.WithFocused(true),
		table.WithHeight(7),
	)

	s := table.DefaultStyles()
	t.SetStyles(s)

	m := model{
		pingResults: pingAddresses(googleDNSv4, googleDNSv6),
		mtuResults:  mtuAddresses(googleDNSv4, googleDNSv6),
		gatewayResults: []gatewayResult{
			{
				address: nil,
				interfaceName: "-",
				err: nil,
				ipv6: true,
			},
			{
				address: nil,
				interfaceName: "-",
				err: nil,
				ipv6: false,
			},
		},
		dnsResults: dnsResult{},
		table:       t,
		pingRow:     pingRow,
		mtuRow:      mtuRow,
		gatewayRow:  gatewayRow,
		dnsRow:      dnsRow,
		interfaceRow: interfaceRow,
	}

	if _, err := tea.NewProgram(m).Run(); err != nil {
		fmt.Println("Error running program:", err)
		os.Exit(1)
	}
}
