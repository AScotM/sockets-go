package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Config holds application configuration
type Config struct {
	LogLevel  string
	JSONOutput bool
}

// SocketStats represents the parsed socket statistics
type SocketStats struct {
	SocketsUsed int `json:"sockets_used"`
	TCP         struct {
		InUse     int `json:"in_use"`
		Orphan    int `json:"orphan"`
		TimeWait  int `json:"time_wait"`
		Allocated int `json:"allocated"`
		Memory    int `json:"memory"`
	} `json:"tcp"`
	UDP struct {
		InUse  int `json:"in_use"`
		Memory int `json:"memory"`
	} `json:"udp"`
	UDPLite struct {
		InUse int `json:"in_use"`
	} `json:"udp_lite"`
	RAW struct {
		InUse int `json:"in_use"`
	} `json:"raw"`
	FRAG struct {
		InUse  int `json:"in_use"`
		Memory int `json:"memory"`
	} `json:"frag"`
}

var (
	config     Config
	logLevels  = map[string]int{"DEBUG": 0, "INFO": 1, "WARNING": 2, "ERROR": 3}
	sockstatPath = "/proc/net/sockstat"
)

func main() {
	// Parse command line flags
	flag.StringVar(&config.LogLevel, "log-level", "INFO", "Log level (DEBUG, INFO, WARNING, ERROR)")
	flag.BoolVar(&config.JSONOutput, "json", false, "Output in JSON format")
	help := flag.Bool("help", false, "Show help")
	flag.Parse()

	if *help {
		showHelp()
		return
	}

	// Validate configuration
	if err := validateConfig(); err != nil {
		log.Fatalf("Configuration error: %v", err)
	}

	// Check if sockstat file exists and is readable
	if err := checkSockstatFile(); err != nil {
		log.Fatalf("File error: %v", err)
	}

	// Get and display socket statistics
	stats, err := getSocketStats()
	if err != nil {
		log.Fatalf("Failed to get socket statistics: %v", err)
	}

	displayStats(stats)
}

func validateConfig() error {
	if _, exists := logLevels[config.LogLevel]; !exists {
		return fmt.Errorf("invalid log level: %s. Valid levels: DEBUG, INFO, WARNING, ERROR", config.LogLevel)
	}
	return nil
}

func checkSockstatFile() error {
	info, err := os.Stat(sockstatPath)
	if os.IsNotExist(err) {
		return fmt.Errorf("'%s' not found. Ensure you are running on a Linux system", sockstatPath)
	}
	if err != nil {
		return fmt.Errorf("cannot access '%s': %v", sockstatPath, err)
	}
	if info.Mode().Perm()&0444 == 0 {
		return fmt.Errorf("'%s' is not readable. Check permissions", sockstatPath)
	}
	return nil
}

func logMessage(level, message string) {
	if logLevels[level] >= logLevels[config.LogLevel] {
		timestamp := time.Now().Format("2006-01-02 15:04:05")
		if level == "ERROR" {
			log.Printf("%s - %s - %s", timestamp, level, message)
		} else {
			fmt.Printf("%s - %s - %s\n", timestamp, level, message)
		}
	}
}

func showHelp() {
	fmt.Printf(`Usage: %s [OPTIONS]

Options:
  --json         Output socket summary in JSON format
  --log-level LEVEL Set log level (DEBUG, INFO, WARNING, ERROR)
  --help         Display this help message

Examples:
  %s --json
  %s --log-level DEBUG
  %s --json --log-level WARNING
`, os.Args[0], os.Args[0], os.Args[0], os.Args[0])
}

func getSocketStats() (*SocketStats, error) {
	startTime := time.Now()
	logMessage("INFO", "Reading socket statistics from /proc/net/sockstat...")

	file, err := os.Open(sockstatPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open %s: %v", sockstatPath, err)
	}
	defer file.Close()

	stats := &SocketStats{}
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()
		parseLine(line, stats)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading %s: %v", sockstatPath, err)
	}

	elapsed := time.Since(startTime).Seconds()
	logMessage("INFO", fmt.Sprintf("Success! Retrieved socket summary in %.4fs.", elapsed))

	return stats, nil
}

func parseLine(line string, stats *SocketStats) {
	// Remove multiple spaces and split
	re := regexp.MustCompile(`\s+`)
	cleanLine := re.ReplaceAllString(line, " ")
	parts := strings.Split(cleanLine, " ")

	if len(parts) < 2 {
		return
	}

	switch parts[0] {
	case "sockets:":
		if len(parts) >= 3 {
			stats.SocketsUsed = parseInt(parts[2])
		}
	case "TCP:":
		parseTCP(parts, stats)
	case "UDP:":
		parseUDP(parts, stats)
	case "UDPLITE:":
		parseUDPLite(parts, stats)
	case "RAW:":
		parseRAW(parts, stats)
	case "FRAG:":
		parseFRAG(parts, stats)
	}
}

func parseTCP(parts []string, stats *SocketStats) {
	for i := 1; i < len(parts); i += 2 {
		if i+1 >= len(parts) {
			break
		}
		switch parts[i] {
		case "inuse":
			stats.TCP.InUse = parseInt(parts[i+1])
		case "orphan":
			stats.TCP.Orphan = parseInt(parts[i+1])
		case "tw":
			stats.TCP.TimeWait = parseInt(parts[i+1])
		case "alloc":
			stats.TCP.Allocated = parseInt(parts[i+1])
		case "mem":
			stats.TCP.Memory = parseInt(parts[i+1])
		}
	}
}

func parseUDP(parts []string, stats *SocketStats) {
	for i := 1; i < len(parts); i += 2 {
		if i+1 >= len(parts) {
			break
		}
		switch parts[i] {
		case "inuse":
			stats.UDP.InUse = parseInt(parts[i+1])
		case "mem":
			stats.UDP.Memory = parseInt(parts[i+1])
		}
	}
}

func parseUDPLite(parts []string, stats *SocketStats) {
	for i := 1; i < len(parts); i += 2 {
		if i+1 >= len(parts) {
			break
		}
		if parts[i] == "inuse" {
			stats.UDPLite.InUse = parseInt(parts[i+1])
		}
	}
}

func parseRAW(parts []string, stats *SocketStats) {
	for i := 1; i < len(parts); i += 2 {
		if i+1 >= len(parts) {
			break
		}
		if parts[i] == "inuse" {
			stats.RAW.InUse = parseInt(parts[i+1])
		}
	}
}

func parseFRAG(parts []string, stats *SocketStats) {
	for i := 1; i < len(parts); i += 2 {
		if i+1 >= len(parts) {
			break
		}
		switch parts[i] {
		case "inuse":
			stats.FRAG.InUse = parseInt(parts[i+1])
		case "memory":
			stats.FRAG.Memory = parseInt(parts[i+1])
		}
	}
}

func parseInt(s string) int {
	val, err := strconv.Atoi(s)
	if err != nil {
		logMessage("DEBUG", fmt.Sprintf("Failed to parse integer '%s': %v", s, err))
		return 0
	}
	return val
}

func displayStats(stats *SocketStats) {
	logMessage("INFO", "Socket Summary:")
	
	if config.JSONOutput {
		outputJSON(stats)
	} else {
		outputHumanReadable(stats)
	}
}

func outputJSON(stats *SocketStats) {
	jsonData, err := json.MarshalIndent(stats, "", "  ")
	if err != nil {
		logMessage("ERROR", fmt.Sprintf("Failed to marshal JSON: %v", err))
		return
	}
	fmt.Println(string(jsonData))
}

func outputHumanReadable(stats *SocketStats) {
	fmt.Printf("Sockets used: %d\n", stats.SocketsUsed)
	fmt.Printf("TCP:\n")
	fmt.Printf("  In use:     %d\n", stats.TCP.InUse)
	fmt.Printf("  Orphan:     %d\n", stats.TCP.Orphan)
	fmt.Printf("  Time wait:  %d\n", stats.TCP.TimeWait)
	fmt.Printf("  Allocated:  %d\n", stats.TCP.Allocated)
	fmt.Printf("  Memory:     %d\n", stats.TCP.Memory)
	fmt.Printf("UDP:\n")
	fmt.Printf("  In use:     %d\n", stats.UDP.InUse)
	fmt.Printf("  Memory:     %d\n", stats.UDP.Memory)
	fmt.Printf("UDPLite:\n")
	fmt.Printf("  In use:     %d\n", stats.UDPLite.InUse)
	fmt.Printf("RAW:\n")
	fmt.Printf("  In use:     %d\n", stats.RAW.InUse)
	fmt.Printf("FRAG:\n")
	fmt.Printf("  In use:     %d\n", stats.FRAG.InUse)
	fmt.Printf("  Memory:     %d\n", stats.FRAG.Memory)
}
