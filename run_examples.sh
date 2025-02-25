#!/bin/bash
# This script demonstrates different ways to run the cybersecurity pipeline

# Set up terminal colors for better readability
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}=== Agentic Cybersecurity Pipeline Examples ===${NC}"
echo -e "${YELLOW}This script will demonstrate different ways to run the cybersecurity pipeline.${NC}"
echo

# Example 1: Basic domain scan
example1() {
  echo -e "${GREEN}Example 1: Basic scan of a single domain${NC}"
  echo "Running: python main.py -t \"Scan example.com for open ports\" -d example.com"
  python main.py -t "Scan example.com for open ports" -d example.com
  echo
}

# Example 2: Multiple domains with verbose output
example2() {
  echo -e "${GREEN}Example 2: Scanning multiple domains with verbose output${NC}"
  echo "Running: python main.py -t \"Discover directories on multiple domains\" -d example.com test.org -v"
  python main.py -t "Discover directories on multiple domains" -d example.com test.org -v
  echo
}

# Example 3: IP range scan with custom output file
example3() {
  echo -e "${GREEN}Example 3: Scanning an IP range with custom output file${NC}"
  echo "Running: python main.py -t \"Find vulnerabilities in internal network\" -i 192.168.1.0/24 -o network_scan.json"
  python main.py -t "Find vulnerabilities in internal network" -i 192.168.1.0/24 -o network_scan.json
  echo
}

# Example 4: Domain and IP range combined scan with streaming output
example4() {
  echo -e "${GREEN}Example 4: Combined domain and IP range scan with streaming output${NC}"
  echo "Running: python main.py -t \"Comprehensive security audit\" -d example.com -i 10.0.0.0/24 --stream"
  python main.py -t "Comprehensive security audit" -d example.com -i 10.0.0.0/24 --stream
  echo
}

# Example 5: Launch the Streamlit UI
example5() {
  echo -e "${GREEN}Example 5: Launching the Streamlit UI${NC}"
  echo "Running: python main.py --streamlit"
  python main.py --streamlit
}

# Menu to select which example to run
show_menu() {
  echo -e "${BLUE}Select an example to run:${NC}"
  echo "1) Basic domain scan"
  echo "2) Multiple domains with verbose output"
  echo "3) IP range scan with custom output file"
  echo "4) Combined domain and IP range scan with streaming output"
  echo "5) Launch the Streamlit UI"
  echo "0) Exit"
  echo
  echo -n "Enter your choice (0-5): "
}

# Main execution
show_menu
read choice

case $choice in
  1) example1 ;;
  2) example2 ;;
  3) example3 ;;
  4) example4 ;;
  5) example5 ;;
  0) echo -e "${YELLOW}Exiting.${NC}" && exit 0 ;;
  *) echo -e "${RED}Invalid choice.${NC}" && exit 1 ;;
esac

echo -e "${BLUE}Done!${NC}"