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

type Status struct {
	Name  xml.Name `xml:"state" json:"name,omitempty"`
	State string   `xml:"state,attr"`
}

type Service struct {
	Name string `xml:"name,attr" json:"name"`
}

type Port struct {
	Name     xml.Name `xml:"port" json:"name,omitempty"`
	Protocol string   `xml:"protocol,attr" json:"protocol"`
	Port     uint32   `xml:"portid,attr" json:"port"`
	Status   Status   `xml:"state" json:"status"`
	Service  Service  `xml:"service,omitempty" json:"service"`
}

type Ports struct {
	Name  xml.Name `xml:"ports" json:"name,omitempty"`
	Ports []Port   `xml:"port"`
}

type Address struct {
	Name    xml.Name `xml:"address" json:",omitempty"`
	Address string   `xml:"addr,attr"`
}

type Host struct {
	Name    xml.Name `xml:"host" json:"name,omitempty"`
	Address Address  `xml:"address" json:"address"`
	Ports   Ports    `xml:"ports" json:"ports"`
}

type Nmap struct {
	Name xml.Name `xml:"nmaprun" json:",omitempty"`
	Host []Host   `xml:"host"`
}

var rootNmap = make(map[string]Host, 0)

const SaveFile = "/tmp/rootNmap"

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

func createScan() error {
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

	if err := createScan(); err != nil {
		fmt.Println(err)
	}
}
