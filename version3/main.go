package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	LogLevel     string
	JSONOutput   bool
	SockstatPath string
	Sockstat6Path string
}

type SocketStats struct {
	SocketsUsed int `json:"sockets_used"`
	TCP         struct {
		InUse           int `json:"in_use"`
		Orphan          int `json:"orphan"`
		TimeWait        int `json:"time_wait"`
		Allocated       int `json:"allocated"`
		Memory          int `json:"memory"` // in memory pages (usually 4KB)
		HashEntries     int `json:"hash_entries"`
		RehashEntries   int `json:"rehash_entries"`
	} `json:"tcp"`
	UDP struct {
		InUse  int `json:"in_use"`
		Memory int `json:"memory"` // in memory pages (usually 4KB)
	} `json:"udp"`
	UDPLite struct {
		InUse int `json:"in_use"`
	} `json:"udp_lite"`
	RAW struct {
		InUse int `json:"in_use"`
	} `json:"raw"`
	FRAG struct {
		InUse  int `json:"in_use"`
		Memory int `json:"memory"` // in memory pages (usually 4KB)
	} `json:"frag"`
	IPv6 struct {
		TCPInUse    int `json:"tcp_in_use"`
		UDPInUse    int `json:"udp_in_use"`
		UDPLiteInUse int `json:"udplite_in_use"`
		RAWInUse    int `json:"raw_in_use"`
		FRAGInUse   int `json:"frag_in_use"`
	} `json:"ipv6"`
}

var logLevels = map[string]int{"DEBUG": 0, "INFO": 1, "WARNING": 2, "ERROR": 3}

func main() {
	config := parseFlags()
	
	if err := validateConfig(config); err != nil {
		log.Fatalf("Configuration error: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	stats, err := getSocketStats(ctx, config)
	if err != nil {
		log.Fatalf("Failed to get socket statistics: %v", err)
	}

	displayStats(stats, config)
}

func parseFlags() Config {
	var config Config
	
	flag.StringVar(&config.LogLevel, "log-level", "INFO", "Log level (DEBUG, INFO, WARNING, ERROR)")
	flag.BoolVar(&config.JSONOutput, "json", false, "Output in JSON format")
	flag.StringVar(&config.SockstatPath, "sockstat-path", "/proc/net/sockstat", "Path to sockstat file")
	flag.StringVar(&config.Sockstat6Path, "sockstat6-path", "/proc/net/sockstat6", "Path to sockstat6 file")
	help := flag.Bool("help", false, "Show help")
	flag.Parse()

	if *help {
		showHelp()
		os.Exit(0)
	}

	return config
}

func validateConfig(config Config) error {
	if _, exists := logLevels[config.LogLevel]; !exists {
		return fmt.Errorf("invalid log level: %s. Valid levels: DEBUG, INFO, WARNING, ERROR", config.LogLevel)
	}
	return nil
}

func checkFileAccess(path string) error {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("'%s' not found. Ensure you are running on a Linux system", path)
		}
		return fmt.Errorf("cannot open '%s': %v", path, err)
	}
	f.Close()
	return nil
}

func logMessage(config Config, level, message string) {
	msgLevel, ok := logLevels[level]
	if !ok {
		msgLevel = logLevels["INFO"]
	}

	confLevel := logLevels[config.LogLevel]
	if msgLevel < confLevel {
		return
	}

	timestamp := time.Now().Format("2006-01-02 15:04:05")
	line := fmt.Sprintf("%s - %s - %s", timestamp, level, message)

	if config.JSONOutput || level == "ERROR" {
		fmt.Fprintln(os.Stderr, line)
	} else {
		fmt.Println(line)
	}
}

func showHelp() {
	fmt.Printf(`Usage: %s [OPTIONS]

Options:
  --json                    Output socket summary in JSON format
  --log-level LEVEL         Set log level (DEBUG, INFO, WARNING, ERROR)
  --sockstat-path PATH      Path to sockstat file (default: /proc/net/sockstat)
  --sockstat6-path PATH     Path to sockstat6 file (default: /proc/net/sockstat6)
  --help                    Display this help message

Examples:
  %s --json
  %s --log-level DEBUG
  %s --sockstat-path /custom/path/sockstat
`, os.Args[0], os.Args[0], os.Args[0], os.Args[0])
}

func getSocketStats(ctx context.Context, config Config) (*SocketStats, error) {
	startTime := time.Now()
	logMessage(config, "INFO", "Reading socket statistics...")

	stats := &SocketStats{}
	resultChan := make(chan error, 2)
	
	go func() {
		if err := checkFileAccess(config.SockstatPath); err != nil {
			resultChan <- err
			return
		}
		if err := parseSockstatFile(config.SockstatPath, stats, false, config); err != nil {
			resultChan <- err
			return
		}
		resultChan <- nil
	}()

	go func() {
		if err := checkFileAccess(config.Sockstat6Path); err == nil {
			if err := parseSockstatFile(config.Sockstat6Path, stats, true, config); err != nil {
				logMessage(config, "WARNING", fmt.Sprintf("Failed to parse IPv6 stats: %v", err))
			}
		}
		resultChan <- nil
	}()

	for i := 0; i < 2; i++ {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case err := <-resultChan:
			if err != nil {
				return nil, err
			}
		}
	}

	elapsed := time.Since(startTime).Seconds()
	logMessage(config, "INFO", fmt.Sprintf("Success! Retrieved socket summary in %.4fs.", elapsed))

	return stats, nil
}

func parseSockstatFile(path string, stats *SocketStats, isIPv6 bool, config Config) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("failed to open %s: %v", path, err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if isIPv6 {
			parseLineIPv6(line, stats)
		} else {
			parseLine(line, stats, config)
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading %s: %v", path, err)
	}

	return nil
}

func parseLine(line string, stats *SocketStats, config Config) {
	parts := strings.Fields(line)
	if len(parts) < 2 {
		return
	}

	switch parts[0] {
	case "sockets:":
		if len(parts) >= 3 {
			stats.SocketsUsed = parseInt(parts[2], config)
		}
	case "TCP:":
		parseTCP(parts, stats, config)
	case "UDP:":
		parseUDP(parts, stats, config)
	case "UDPLITE:":
		parseUDPLite(parts, stats, config)
	case "RAW:":
		parseRAW(parts, stats, config)
	case "FRAG:":
		parseFRAG(parts, stats, config)
	}
}

func parseLineIPv6(line string, stats *SocketStats) {
	parts := strings.Fields(line)
	if len(parts) < 2 {
		return
	}

	switch parts[0] {
	case "TCP6:":
		for i := 1; i < len(parts); i += 2 {
			if i+1 >= len(parts) {
				break
			}
			if parts[i] == "inuse" {
				stats.IPv6.TCPInUse = parseInt(parts[i+1], Config{LogLevel: "ERROR"})
			}
		}
	case "UDP6:":
		for i := 1; i < len(parts); i += 2 {
			if i+1 >= len(parts) {
				break
			}
			if parts[i] == "inuse" {
				stats.IPv6.UDPInUse = parseInt(parts[i+1], Config{LogLevel: "ERROR"})
			}
		}
	case "UDPLITE6:":
		for i := 1; i < len(parts); i += 2 {
			if i+1 >= len(parts) {
				break
			}
			if parts[i] == "inuse" {
				stats.IPv6.UDPLiteInUse = parseInt(parts[i+1], Config{LogLevel: "ERROR"})
			}
		}
	case "RAW6:":
		for i := 1; i < len(parts); i += 2 {
			if i+1 >= len(parts) {
				break
			}
			if parts[i] == "inuse" {
				stats.IPv6.RAWInUse = parseInt(parts[i+1], Config{LogLevel: "ERROR"})
			}
		}
	case "FRAG6:":
		for i := 1; i < len(parts); i += 2 {
			if i+1 >= len(parts) {
				break
			}
			if parts[i] == "inuse" {
				stats.IPv6.FRAGInUse = parseInt(parts[i+1], Config{LogLevel: "ERROR"})
			}
		}
	}
}

func parseTCP(parts []string, stats *SocketStats, config Config) {
	for i := 1; i < len(parts); i += 2 {
		if i+1 >= len(parts) {
			break
		}
		switch parts[i] {
		case "inuse":
			stats.TCP.InUse = parseInt(parts[i+1], config)
		case "orphan":
			stats.TCP.Orphan = parseInt(parts[i+1], config)
		case "tw":
			stats.TCP.TimeWait = parseInt(parts[i+1], config)
		case "alloc":
			stats.TCP.Allocated = parseInt(parts[i+1], config)
		case "mem":
			stats.TCP.Memory = parseInt(parts[i+1], config)
		case "tcp_hash_entries":
			stats.TCP.HashEntries = parseInt(parts[i+1], config)
		case "tcp_hash_rehash_entries":
			stats.TCP.RehashEntries = parseInt(parts[i+1], config)
		}
	}
}

func parseUDP(parts []string, stats *SocketStats, config Config) {
	for i := 1; i < len(parts); i += 2 {
		if i+1 >= len(parts) {
			break
		}
		switch parts[i] {
		case "inuse":
			stats.UDP.InUse = parseInt(parts[i+1], config)
		case "mem":
			stats.UDP.Memory = parseInt(parts[i+1], config)
		}
	}
}

func parseUDPLite(parts []string, stats *SocketStats, config Config) {
	for i := 1; i < len(parts); i += 2 {
		if i+1 >= len(parts) {
			break
		}
		if parts[i] == "inuse" {
			stats.UDPLite.InUse = parseInt(parts[i+1], config)
		}
	}
}

func parseRAW(parts []string, stats *SocketStats, config Config) {
	for i := 1; i < len(parts); i += 2 {
		if i+1 >= len(parts) {
			break
		}
		if parts[i] == "inuse" {
			stats.RAW.InUse = parseInt(parts[i+1], config)
		}
	}
}

func parseFRAG(parts []string, stats *SocketStats, config Config) {
	for i := 1; i < len(parts); i += 2 {
		if i+1 >= len(parts) {
			break
		}
		switch parts[i] {
		case "inuse":
			stats.FRAG.InUse = parseInt(parts[i+1], config)
		case "memory":
			stats.FRAG.Memory = parseInt(parts[i+1], config)
		}
	}
}

func parseInt(s string, config Config) int {
	val, err := strconv.Atoi(s)
	if err != nil {
		logMessage(config, "DEBUG", fmt.Sprintf("Failed to parse integer '%s': %v", s, err))
		return 0
	}
	return val
}

func displayStats(stats *SocketStats, config Config) {
	logMessage(config, "INFO", "Socket Summary:")

	if config.JSONOutput {
		outputJSON(stats, config)
	} else {
		outputHumanReadable(stats)
	}
}

func outputJSON(stats *SocketStats, config Config) {
	jsonData, err := json.MarshalIndent(stats, "", "  ")
	if err != nil {
		logMessage(config, "ERROR", fmt.Sprintf("Failed to marshal JSON: %v", err))
		return
	}
	fmt.Println(string(jsonData))
}

func outputHumanReadable(stats *SocketStats) {
	fmt.Printf("Sockets used: %d\n", stats.SocketsUsed)
	fmt.Printf("TCP:\n")
	fmt.Printf("  In use:        %d\n", stats.TCP.InUse)
	fmt.Printf("  Orphan:        %d\n", stats.TCP.Orphan)
	fmt.Printf("  Time wait:     %d\n", stats.TCP.TimeWait)
	fmt.Printf("  Allocated:     %d\n", stats.TCP.Allocated)
	fmt.Printf("  Memory:        %d pages\n", stats.TCP.Memory)
	fmt.Printf("  Hash entries:  %d\n", stats.TCP.HashEntries)
	fmt.Printf("  Rehash entries: %d\n", stats.TCP.RehashEntries)
	fmt.Printf("UDP:\n")
	fmt.Printf("  In use:        %d\n", stats.UDP.InUse)
	fmt.Printf("  Memory:        %d pages\n", stats.UDP.Memory)
	fmt.Printf("UDPLite:\n")
	fmt.Printf("  In use:        %d\n", stats.UDPLite.InUse)
	fmt.Printf("RAW:\n")
	fmt.Printf("  In use:        %d\n", stats.RAW.InUse)
	fmt.Printf("FRAG:\n")
	fmt.Printf("  In use:        %d\n", stats.FRAG.InUse)
	fmt.Printf("  Memory:        %d pages\n", stats.FRAG.Memory)
	fmt.Printf("IPv6:\n")
	fmt.Printf("  TCP in use:    %d\n", stats.IPv6.TCPInUse)
	fmt.Printf("  UDP in use:    %d\n", stats.IPv6.UDPInUse)
	fmt.Printf("  UDPLite in use: %d\n", stats.IPv6.UDPLiteInUse)
	fmt.Printf("  RAW in use:    %d\n", stats.IPv6.RAWInUse)
	fmt.Printf("  FRAG in use:   %d\n", stats.IPv6.FRAGInUse)
}
