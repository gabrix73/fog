#!/bin/bash
# fog-client.sh - Interactive SMTP client for fog network
# Selects random entry node and sends message via Tor

VERSION="2.0"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
NC='\033[0m'

# fog network nodes (onion SMTP addresses)
NODES=(
    "ej5dj774rkmfxvo3jexcmyotkq6bwgmr45dmwrbmk366lcvalnrgolad.onion 2525"   # kvara
    "iycr4wfrdzieogdfeo7uxrj77w2vjlrhlrv3jg2ve62oe5aceqsqu7ad.onion 2525"   # dries
    "66ehoz4ir6beuovmgt4gbpdfpmy43iuouj36dylqvkwgyp2dwpcbvjqd.onion 2525"   # mct8
    "y3lozzcvvxgorgfofupvfmn4j2fuu3sz2sw7ha3ifpcsxjkuafllzvyd.onion 2525"   # news
    "ejdrw3ka2mjhvsuz7uxjnzjircsdpoiu3a33g2xoywlafqetptjpqryd.onion 2525"   # pietro
)

NODE_NAMES=("kvara" "dries" "mct8" "news" "pietro")

print_header() {
    echo -e "${CYAN}"
    echo "========================================================="
    echo "  fog Network Client v${VERSION} - Anonymous SMTP Relay"
    echo "========================================================="
    echo -e "${NC}"
}

check_dependencies() {
    local missing=0

    if ! command -v nc &> /dev/null; then
        echo -e "${RED}[x] netcat not found (apt install netcat-openbsd)${NC}"
        missing=1
    fi

    if ! command -v torify &> /dev/null; then
        echo -e "${RED}[x] torify not found (apt install tor)${NC}"
        missing=1
    fi

    if ! pgrep -x tor > /dev/null 2>&1; then
        echo -e "${RED}[x] Tor is not running (systemctl start tor)${NC}"
        missing=1
    fi

    if [ $missing -eq 1 ]; then
        exit 1
    fi

    echo -e "${GREEN}[ok] Dependencies ready${NC}"
    echo ""
}

# CSPRNG node selection (not bash $RANDOM)
select_random_node() {
    local count=${#NODES[@]}
    local random_index
    random_index=$(od -An -tu4 -N4 /dev/urandom | tr -d ' ')
    random_index=$((random_index % count))

    SELECTED_NODE="${NODES[$random_index]}"
    SELECTED_NAME="${NODE_NAMES[$random_index]}"

    echo -e "${CYAN}Entry node:${NC} ${MAGENTA}${SELECTED_NAME}${NC}"
    echo ""
}

read_multiline() {
    local prompt="$1"

    echo -e "${YELLOW}${prompt}${NC}"
    echo -e "${CYAN}(End with a single dot '.' on its own line)${NC}"

    MULTILINE_RESULT=""
    local line

    while IFS= read -r line; do
        if [ "$line" = "." ]; then
            break
        fi
        MULTILINE_RESULT="${MULTILINE_RESULT}${line}"$'\r\n'
    done
}

send_message() {
    local from="$1"
    local to="$2"
    local subject="$3"
    local extra_headers="$4"
    local body="$5"

    local node_host node_port
    node_host=$(echo "$SELECTED_NODE" | awk '{print $1}')
    node_port=$(echo "$SELECTED_NODE" | awk '{print $2}')

    echo -e "${CYAN}Connecting to ${SELECTED_NAME} via Tor...${NC}"
    echo ""

    # SMTP conversation
    # No Date/Message-ID/User-Agent: exit node generates sanitized ones
    local response
    response=$(
    {
        sleep 2
        echo "EHLO localhost"
        sleep 1
        echo "MAIL FROM:<${from}>"
        sleep 0.5
        echo "RCPT TO:<${to}>"
        sleep 0.5
        echo "DATA"
        sleep 0.5
        printf "From: %s\r\n" "$from"
        printf "To: %s\r\n" "$to"
        printf "Subject: %s\r\n" "$subject"
        printf "MIME-Version: 1.0\r\n"
        printf "Content-Type: text/plain; charset=utf-8\r\n"
        printf "Content-Transfer-Encoding: 8bit\r\n"
        # Extra headers (Newsgroups, References, etc.)
        if [ -n "$extra_headers" ]; then
            printf "%s" "$extra_headers"
        fi
        printf "\r\n"
        # Body - use printf to avoid escape interpretation
        printf "%s" "$body"
        printf "\r\n.\r\n"
        sleep 1
        echo "QUIT"
    } | torify nc -w 30 "$node_host" "$node_port" 2>/dev/null
    )

    # Show server responses
    while IFS= read -r line; do
        if [ -n "$line" ]; then
            echo -e "${BLUE}  <- ${line}${NC}"
        fi
    done <<< "$response"

    echo ""

    if echo "$response" | grep -q "^250.*queued"; then
        echo -e "${GREEN}[ok] Message accepted by ${SELECTED_NAME}${NC}"
        echo -e "${CYAN}     Routing through Sphinx mixnet (3-6 hops)${NC}"
        return 0
    else
        echo -e "${RED}[fail] Message not accepted${NC}"
        return 1
    fi
}

interactive_mode() {
    echo -e "${CYAN}--- Compose Email ---${NC}"
    echo ""

    echo -e -n "${YELLOW}From: ${NC}"
    read -r from
    [ -z "$from" ] && { echo -e "${RED}Error: From required${NC}"; exit 1; }

    echo -e -n "${YELLOW}To: ${NC}"
    read -r to
    [ -z "$to" ] && { echo -e "${RED}Error: To required${NC}"; exit 1; }

    echo -e -n "${YELLOW}Subject: ${NC}"
    read -r subject
    [ -z "$subject" ] && subject="(no subject)"

    echo ""
    read_multiline "Body:"
    local body="$MULTILINE_RESULT"
    [ -z "$body" ] && { echo -e "${RED}Error: Body required${NC}"; exit 1; }

    echo ""
    echo -e "${YELLOW}---${NC}"
    echo -e "  From:    ${from}"
    echo -e "  To:      ${to}"
    echo -e "  Subject: ${subject}"
    echo -e "  Via:     ${SELECTED_NAME}"
    echo -e "${YELLOW}---${NC}"
    echo ""

    echo -e -n "${YELLOW}Send? [y/N]: ${NC}"
    read -r confirm
    [[ ! "$confirm" =~ ^[Yy]$ ]] && { echo "Cancelled"; exit 0; }

    echo ""
    send_message "$from" "$to" "$subject" "" "$body"
}

usenet_mode() {
    echo -e "${CYAN}--- Compose Usenet Post ---${NC}"
    echo ""

    echo -e -n "${YELLOW}From (name): ${NC}"
    read -r from_name
    [ -z "$from_name" ] && from_name="Anonymous"

    echo -e -n "${YELLOW}From (email) [noreply@fog.network]: ${NC}"
    read -r from_email
    [ -z "$from_email" ] && from_email="noreply@fog.network"
    local from="${from_name} <${from_email}>"

    echo -e -n "${YELLOW}Newsgroups (e.g. alt.test): ${NC}"
    read -r newsgroups
    [ -z "$newsgroups" ] && { echo -e "${RED}Error: Newsgroups required${NC}"; exit 1; }

    echo -e -n "${YELLOW}Subject: ${NC}"
    read -r subject
    [ -z "$subject" ] && subject="(no subject)"

    echo -e -n "${YELLOW}References (Message-ID to reply to, empty for new post): ${NC}"
    read -r references

    echo ""
    read_multiline "Post body:"
    local body="$MULTILINE_RESULT"
    [ -z "$body" ] && { echo -e "${RED}Error: Body required${NC}"; exit 1; }

    # Mail2news gateway - destination
    echo ""
    echo -e "${CYAN}Mail2news gateways:${NC}"
    echo -e "  1) mail2news@dizum.com (clearnet via Tor)"
    echo -e "  2) mail2news@xilb7y4kj6u6qfo45o3yk2kilfv54ffukzei3puonuqlncy7cn2afwyd.onion"
    echo -e "  3) Custom address"
    echo -e -n "${YELLOW}Gateway [1]: ${NC}"
    read -r gw_choice

    local to
    case "$gw_choice" in
        2) to="mail2news@xilb7y4kj6u6qfo45o3yk2kilfv54ffukzei3puonuqlncy7cn2afwyd.onion" ;;
        3)
            echo -e -n "${YELLOW}Custom gateway address: ${NC}"
            read -r to
            [ -z "$to" ] && { echo -e "${RED}Error: Address required${NC}"; exit 1; }
            ;;
        *) to="mail2news@dizum.com" ;;
    esac

    # Build extra headers (Newsgroups goes in email headers, NOT body)
    local extra_headers
    extra_headers=$(printf "Newsgroups: %s\r\n" "$newsgroups")
    if [ -n "$references" ]; then
        extra_headers="${extra_headers}$(printf "References: %s\r\n" "$references")"
    fi

    echo ""
    echo -e "${YELLOW}---${NC}"
    echo -e "  From:       ${from}"
    echo -e "  Newsgroups: ${newsgroups}"
    echo -e "  Subject:    ${subject}"
    [ -n "$references" ] && echo -e "  References: ${references}"
    echo -e "  Gateway:    ${to}"
    echo -e "  Via:        ${SELECTED_NAME}"
    echo -e "${YELLOW}---${NC}"
    echo ""

    echo -e -n "${YELLOW}Post? [y/N]: ${NC}"
    read -r confirm
    [[ ! "$confirm" =~ ^[Yy]$ ]] && { echo "Cancelled"; exit 0; }

    echo ""
    send_message "$from" "$to" "$subject" "$extra_headers" "$body"
}

show_help() {
    echo "Usage: $0 [OPTION]"
    echo ""
    echo "  -e, --email    Compose email (default)"
    echo "  -u, --usenet   Compose Usenet post"
    echo "  -v, --version  Show version"
    echo "  -h, --help     Show this help"
}

# Main
main() {
    local mode="email"

    while [[ $# -gt 0 ]]; do
        case $1 in
            -e|--email)   mode="email";  shift ;;
            -u|--usenet)  mode="usenet"; shift ;;
            -v|--version) echo "fog-client v${VERSION}"; exit 0 ;;
            -h|--help)    show_help; exit 0 ;;
            *)            echo "Unknown: $1"; show_help; exit 1 ;;
        esac
    done

    print_header
    check_dependencies
    select_random_node

    case "$mode" in
        email)  interactive_mode ;;
        usenet) usenet_mode ;;
    esac
}

main "$@"
