package main

import (
	"bufio"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"
)

// Status gives the status of "open, closed, filtered"
type Status struct {
	Name  xml.Name `xml:"state" json:"name,omitempty"`
	State string   `xml:"state,attr"`
}

// Service is the name of the service. Ex: "ssh, rdp, etc."
type Service struct {
	Name string `xml:"name,attr" json:"name"`
}

// Port has all of the information about the port in question
type Port struct {
	Name     xml.Name `xml:"port" json:"name,omitempty"`
	Protocol string   `xml:"protocol,attr" json:"protocol"`
	Port     uint32   `xml:"portid,attr" json:"port"`
	Status   Status   `xml:"state" json:"status"`
	Service  Service  `xml:"service,omitempty" json:"service"`
}

// Ports is the array of ports
type Ports struct {
	Name  xml.Name `xml:"ports" json:"name,omitempty"`
	Ports []Port   `xml:"port"`
}

// Address has the address of the server. This is only used when multiple hosts
// are scanned at the same time
type Address struct {
	Name    xml.Name `xml:"address" json:",omitempty"`
	Address string   `xml:"addr,attr"`
}

// Host holds the information about the port including what address it has and
// the information about the ports
type Host struct {
	Name    xml.Name `xml:"host" json:"name,omitempty"`
	Address Address  `xml:"address" json:"address"`
	Ports   Ports    `xml:"ports" json:"ports"`
}

// Nmap is the root object that holds all data
type Nmap struct {
	Name xml.Name `xml:"nmaprun" json:",omitempty"`
	Host []Host   `xml:"host"`
}

// rootNmap is a global object that has the information about the scans
var rootNmap = make(map[string]Host, 0)

// SaveFile is the location of where the temporary file is saved
const SaveFile = "/tmp/rootNmap"

// runScan runs the nmap scan and converts the output into the Host object
func runScan(hosts ...string) ([]Host, error) {
	var hostsOut Nmap

	args := []string{"-oX", "-", "-p-"}
	args = append(args, hosts...)
	output, err := exec.Command("nmap", args...).Output()
	if err != nil {
		return hostsOut.Host, err
	}

	if err := xml.Unmarshal(output, &hostsOut); err != nil {
		return hostsOut.Host, err
	}

	return hostsOut.Host, nil
}

// writeNmap writes the rootNmap object to the SaveFile
func writeNmap() error {
	output, err := json.Marshal(rootNmap)
	if err != nil {
		return err
	}
	if err := ioutil.WriteFile(SaveFile, output, 0755); err != nil {
		return err
	}
	return nil
}

// addHost takes in host addresses as strings, scans them, puts them in the
// global rootNmap object and writes them to the save file
func addHost(newHosts ...string) error {
	hosts, err := runScan(newHosts...)
	if err != nil {
		return err
	}
	for _, h := range hosts {
		rootNmap[h.Address.Address] = h
	}

	if err := writeNmap(); err != nil {
		return err
	}

	return nil
}

// parseScan is a helper function for the createInterface that parses and
// executes commands.
func parseScan(tokens []string) error {
	commands := []string{"list", "show", "quit", "scan"}
	if tokens[0] == "list" {
		if len(tokens) == 1 {
			fmt.Println("usage: list [ip]")
			return nil
		}
		for _, host := range rootNmap {
			if host.Address.Address == tokens[1] {
				for _, port := range host.Ports.Ports {
					p := fmt.Sprint(port.Port) + "/"
					proto := port.Protocol
					status := port.Status.State
					service := port.Service.Name
					fmt.Println(p+proto, status, service)
				}
				return nil
			}
		}
	} else if tokens[0] == "show" {
		for _, host := range rootNmap {
			fmt.Println(host.Address.Address)
		}
		return nil
	} else if tokens[0] == "quit" || tokens[0] == "q" {
		os.Exit(0)
	} else if tokens[0] == "scan" {
		// Rescan hosts
		if len(tokens) == 1 {
			oldHosts := make([]string, 0)
			for _, host := range rootNmap {
				oldHosts = append(oldHosts, host.Address.Address)
			}
			if err := addHost(oldHosts...); err != nil {
				return err
			}

			// Scan new hosts
		} else {
			if err := addHost(tokens[1:]...); err != nil {
				return err
			}
		}
	} else if tokens[0] == "help" {
		fmt.Println("Available commands: ")
		for _, h := range commands {
			fmt.Println(h)
		}
	} else {
		fmt.Println("Error: command ", tokens[0], "not found")

	}

	return nil
}

// createInterface creates the interface shell for interacting with the
// application
func createInterface() error {
	for {
		fmt.Print("> ")
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			text := scanner.Text()
			tokens := strings.Split(text, " ")
			if err := parseScan(tokens); err != nil {
				return err
			}
			fmt.Print("> ")
		}
		if err := scanner.Err(); err != nil {
			return err
		}
	}
}

func init() {
	// Read save file and replace the rootNmap object if it exists
	file, err := ioutil.ReadFile(SaveFile)
	// If there is no error, use contents to create initial structure
	if err == nil {
		if err := json.Unmarshal(file, &rootNmap); err != nil {
			fmt.Println(file)
		}
	}
}

func main() {
	if len(os.Args) > 1 {
		if err := addHost(os.Args[1:]...); err != nil {
			fmt.Println("Error adding hosts:", err)
		}
	}

	if err := createInterface(); err != nil {
		fmt.Println(err)
	}
}
