#!/bin/bash
# fog-client.sh - Interactive SMTP client for fog network
# Selects random entry node and sends message

VERSION="1.0"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
NC='\033[0m'

# fog network nodes (onion addresses)
NODES=(
    "ej5dj774rkmfxvo3jexcmyotkq6bwgmr45dmwrbmk366lcvalnrgolad.onion:2525"  # kvara
    "iycr4wfrdzieogdfeo7uxrj77w2vjlrhlrv3jg2ve62oe5aceqsqu7ad.onion:2525"  # dries
    "66ehoz4ir6beuovmgt4gbpdfpmy43iuouj36dylqvkwgyp2dwpcbvjqd.onion:2525"  # mct8
    "y3lozzcvvxgorgfofupvfmn4j2fuu3sz2sw7ha3ifpcsxjkuafllzvyd.onion:2525"  # news
    "ejdrw3ka2mjhvsuz7uxjnzjircsdpoiu3a33g2xoywlafqetptjpqryd.onion:2525"  # pietro
)

NODE_NAMES=("kvara" "dries" "mct8" "news" "pietro")

# Tor SOCKS proxy
TOR_PROXY="127.0.0.1:9050"

# Functions
print_header() {
    echo -e "${CYAN}"
    echo "╔═══════════════════════════════════════════════════════════╗"
    echo "║              🌫️  fog Network Client v${VERSION}              ║"
    echo "║         Anonymous SMTP Relay - Sphinx Mixnet             ║"
    echo "╚═══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

check_dependencies() {
    local missing=0
    
    # Check nc (netcat)
    if ! command -v nc &> /dev/null; then
        echo -e "${RED}✗ netcat not found${NC}"
        echo "  Install: sudo apt install netcat-openbsd"
        missing=1
    fi
    
    # Check torify
    if ! command -v torify &> /dev/null; then
        echo -e "${RED}✗ torify not found${NC}"
        echo "  Install: sudo apt install tor"
        missing=1
    fi
    
    # Check if Tor is running
    if ! pgrep -x tor > /dev/null; then
        echo -e "${RED}✗ Tor is not running${NC}"
        echo "  Start: sudo systemctl start tor"
        missing=1
    fi
    
    if [ $missing -eq 1 ]; then
        echo ""
        echo -e "${RED}Please install missing dependencies and try again.${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}✓ All dependencies installed${NC}"
    echo ""
}

select_random_node() {
    local random_index=$((RANDOM % ${#NODES[@]}))
    SELECTED_NODE="${NODES[$random_index]}"
    SELECTED_NAME="${NODE_NAMES[$random_index]}"
    
    echo -e "${CYAN}Entry Node:${NC} ${MAGENTA}${SELECTED_NAME}${NC}"
    echo -e "${CYAN}Address:${NC} ${SELECTED_NODE}"
    echo ""
}

read_multiline() {
    local prompt="$1"
    local varname="$2"
    
    echo -e "${YELLOW}${prompt}${NC}"
    echo -e "${CYAN}(Press Ctrl+D when done, or enter a dot '.' on a line by itself)${NC}"
    
    local input=""
    local line
    
    while IFS= read -r line; do
        if [ "$line" = "." ]; then
            break
        fi
        input="${input}${line}"$'\n'
    done
    
    eval "$varname=\$input"
}

generate_message_id() {
    echo "<$(cat /dev/urandom | tr -dc 'a-f0-9' | fold -w 32 | head -n 1)@fog-client>"
}

send_message() {
    local from="$1"
    local to="$2"
    local subject="$3"
    local body="$4"
    
    echo -e "${CYAN}Connecting to ${SELECTED_NAME} via Tor...${NC}"
    
    local msgid=$(generate_message_id)
    local date=$(date -R)
    
    # Build SMTP conversation
    {
        sleep 1
        echo "EHLO fog-client"
        sleep 0.5
        echo "MAIL FROM:<${from}>"
        sleep 0.5
        echo "RCPT TO:<${to}>"
        sleep 0.5
        echo "DATA"
        sleep 0.5
        echo "From: ${from}"
        echo "To: ${to}"
        echo "Subject: ${subject}"
        echo "Message-ID: ${msgid}"
        echo "Date: ${date}"
        echo "Content-Type: text/plain; charset=utf-8"
        echo ""
        echo -e "${body}"
        echo "."
        sleep 0.5
        echo "QUIT"
    } | torify nc ${SELECTED_NODE/:/ } 2>&1 | while IFS= read -r line; do
        if [[ $line =~ ^[0-9]{3} ]]; then
            echo -e "${BLUE}← ${line}${NC}"
        else
            echo -e "${CYAN}  ${line}${NC}"
        fi
    done
    
    local exit_code=${PIPESTATUS[0]}
    
    echo ""
    
    if [ $exit_code -eq 0 ]; then
        echo -e "${GREEN}✓ Message sent successfully!${NC}"
        echo -e "${CYAN}Message-ID: ${msgid}${NC}"
    else
        echo -e "${RED}✗ Failed to send message${NC}"
        return 1
    fi
}

show_summary() {
    local from="$1"
    local to="$2"
    local subject="$3"
    
    echo -e "${YELLOW}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}Message Summary:${NC}"
    echo -e "  ${BLUE}From:${NC}    ${from}"
    echo -e "  ${BLUE}To:${NC}      ${to}"
    echo -e "  ${BLUE}Subject:${NC} ${subject}"
    echo -e "  ${BLUE}Via:${NC}     ${SELECTED_NAME} (random entry node)"
    echo -e "${YELLOW}═══════════════════════════════════════════════════════════${NC}"
    echo ""
}

interactive_mode() {
    echo -e "${CYAN}Enter message details:${NC}"
    echo ""
    
    # From
    read -p "$(echo -e ${YELLOW}From email address: ${NC})" from
    if [ -z "$from" ]; then
        echo -e "${RED}Error: From address required${NC}"
        exit 1
    fi
    
    # To
    read -p "$(echo -e ${YELLOW}To email address: ${NC})" to
    if [ -z "$to" ]; then
        echo -e "${RED}Error: To address required${NC}"
        exit 1
    fi
    
    # Subject
    read -p "$(echo -e ${YELLOW}Subject: ${NC})" subject
    if [ -z "$subject" ]; then
        subject="(no subject)"
    fi
    
    echo ""
    
    # Body (multiline)
    local body
    read_multiline "Message body:" body
    
    if [ -z "$body" ]; then
        echo -e "${RED}Error: Message body required${NC}"
        exit 1
    fi
    
    echo ""
    show_summary "$from" "$to" "$subject"
    
    # Confirm
    read -p "$(echo -e ${YELLOW}Send message? [y/N]: ${NC})" confirm
    
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        echo -e "${CYAN}Cancelled${NC}"
        exit 0
    fi
    
    echo ""
    send_message "$from" "$to" "$subject" "$body"
}

usenet_helper() {
    echo -e "${CYAN}Usenet Posting Helper${NC}"
    echo ""
    
    # From
    read -p "$(echo -e ${YELLOW}From (display name): ${NC})" from_name
    if [ -z "$from_name" ]; then
        from_name="Anonymous"
    fi
    from="${from_name} <noreply@example.com>"
    
    # Newsgroups
    read -p "$(echo -e ${YELLOW}Newsgroups (e.g., alt.test): ${NC})" newsgroups
    if [ -z "$newsgroups" ]; then
        echo -e "${RED}Error: Newsgroups required${NC}"
        exit 1
    fi
    
    # Subject
    read -p "$(echo -e ${YELLOW}Subject: ${NC})" subject
    if [ -z "$subject" ]; then
        subject="(no subject)"
    fi
    
    echo ""
    
    # Body
    local body
    read_multiline "Post body:" body
    
    if [ -z "$body" ]; then
        echo -e "${RED}Error: Post body required${NC}"
        exit 1
    fi
    
    # Add Newsgroups header to body
    local full_body="Newsgroups: ${newsgroups}"$'\n'"${body}"
    
    # Use mail2news gateway
    local to="mail2news@mail2news.tcpreset.net"
    
    echo ""
    echo -e "${YELLOW}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}Usenet Post Summary:${NC}"
    echo -e "  ${BLUE}From:${NC}       ${from}"
    echo -e "  ${BLUE}Newsgroups:${NC} ${newsgroups}"
    echo -e "  ${BLUE}Subject:${NC}    ${subject}"
    echo -e "  ${BLUE}Gateway:${NC}    ${to}"
    echo -e "  ${BLUE}Via:${NC}        ${SELECTED_NAME} (random entry node)"
    echo -e "${YELLOW}═══════════════════════════════════════════════════════════${NC}"
    echo ""
    
    # Confirm
    read -p "$(echo -e ${YELLOW}Post to Usenet? [y/N]: ${NC})" confirm
    
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        echo -e "${CYAN}Cancelled${NC}"
        exit 0
    fi
    
    echo ""
    send_message "$from" "$to" "$subject" "$full_body"
}

show_help() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -h, --help       Show this help message"
    echo "  -u, --usenet     Usenet posting mode"
    echo "  -v, --version    Show version"
    echo ""
    echo "Interactive mode (default):"
    echo "  Prompts for From, To, Subject, and Body"
    echo "  Selects random entry node from fog network"
    echo "  Sends message via Tor"
    echo ""
    echo "Examples:"
    echo "  $0                    # Interactive email mode"
    echo "  $0 --usenet           # Interactive Usenet posting mode"
    echo ""
}

# Main
main() {
    local mode="email"
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_help
                exit 0
                ;;
            -u|--usenet)
                mode="usenet"
                shift
                ;;
            -v|--version)
                echo "fog-client v${VERSION}"
                exit 0
                ;;
            *)
                echo "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done
    
    print_header
    check_dependencies
    select_random_node
    
    if [ "$mode" = "usenet" ]; then
        usenet_helper
    else
        interactive_mode
    fi
}

# Run
main "$@"
