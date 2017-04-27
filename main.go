package main

import (
	"bufio"
	"encoding/xml"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

type Status struct {
	Name  xml.Name `xml:"state"`
	State string   `xml:"state,attr"`
}

type Service struct {
	Name        xml.Name `xml:service`
	ServiceName string   `xml:name,attr`
}

type Port struct {
	Name     xml.Name `xml:"port"`
	Protocol string   `xml:"protocol,attr"`
	Port     uint32   `xml:"portid,attr"`
	Status   Status   `xml:"state"`
	Service  Service  `xml:"service"`
}

type Ports struct {
	Name  xml.Name `xml:"ports"`
	Ports []Port   `xml:"port"`
}

type Address struct {
	Name    xml.Name `xml:"address"`
	Address string   `xml:"addr,attr"`
}

type Host struct {
	Name    xml.Name `xml:"host"`
	Address Address  `xml:"address"`
	Ports   Ports    `xml:"ports"`
}

type Nmap struct {
	Name xml.Name `xml:"nmaprun"`
	Host []Host   `xml:"host"`
}

var rootNmap = make(map[string]Host, 0)

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

func addHost(newHosts ...string) error {
	hosts, err := runScan(newHosts...)
	if err != nil {
		return err
	}
	for _, h := range hosts {
		rootNmap[h.Address.Address] = h
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
					fmt.Println(fmt.Sprint(port.Port)+"/"+port.Protocol, port.Status.State, port.Service.ServiceName)
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

func main() {
	if len(os.Args) < 1 {
		fmt.Println("usage: ./main")
		os.Exit(0)
	}

	if err := addHost(os.Args[1:]...); err != nil {
		fmt.Println("Error adding hosts:", err)
	}

	if err := createScan(); err != nil {
		fmt.Println(err)
	}
}
