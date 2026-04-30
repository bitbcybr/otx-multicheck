#!/bin/bash
#script for curl otx api with ips from listfile and get some interesting fields with corresponding link to otx website

echo -e "\e[44m-- OTX Multi IP Check Bash Script v0.1 --\e[0m"

bold=$(tput bold)
normal=$(tput sgr0)

echo -e "${bold}This script is processing a plain or txt file with multiple ip addresses (separated with ';' or ',' or one per line) to run a check on OTX platform.${normal} \nWorks for IPv4. IPv6 is supported.\n
It will output some interesting findings(more or less) from the APIs endpoints 'general' and 'malware'. Feel free to modify it on behalf of your needs and always keep FOSS in mind."
echo -e "${bold}\nUsage:\n./otx_multicheck.sh [path/filename with your IPs]${normal}"
echo -e "${bold}API key:${normal} export OTX_API_KEY=yourkey"

listfile=$1
OTX_API_KEY="${OTX_API_KEY:-}"

if [ ! -f "$1" ]; then
    echo -e "${bold}File missing or input is not a file.${normal}\nPlease do ${bold}./otx_multicheck.sh filename${normal}\n"
    exit 1
else
    echo -e "\e[44m - Running $0 on: $1 \e[0m"
fi

if [ -z "$OTX_API_KEY" ]; then
    echo -e "\e[33mNote: No API key provided. Unauthenticated requests may be rate-limited.\e[0m"
fi

proc_listfile=$(cat "$listfile" | tr ';,' '\n' | awk NF)

echo "$proc_listfile" | while read -r ip; do

    echo -e "\n\e[1mProcessing IP: $ip\e[0m"

    if [[ "$ip" =~ : ]]; then
        ip_type="IPv6"
    else
        ip_type="IPv4"
    fi

    api_url_general="https://otx.alienvault.com/api/v1/indicators/$ip_type/$ip/general"
    api_url_malware="https://otx.alienvault.com/api/v1/indicators/$ip_type/$ip/malware"

    if [ -n "$OTX_API_KEY" ]; then
        general_response=$(curl -s -H "X-OTX-API-KEY: $OTX_API_KEY" "$api_url_general")
        malware_response=$(curl -s -H "X-OTX-API-KEY: $OTX_API_KEY" "$api_url_malware")
    else
        general_response=$(curl -s "$api_url_general")
        malware_response=$(curl -s "$api_url_malware")
    fi

    pulse_count=$(echo "$general_response" | grep -o '"count"[^,]*'           | head -1 | grep -o '[0-9]*')
    ind_count=$(echo "$general_response"   | grep -o '"indicator_count"[^,]*' | head -1 | grep -o '[0-9]*')
    ind_types=$(echo "$general_response"   | grep -o '"indicator_type_counts"[^}]*}' | head -1 \
                    | grep -o '"[A-Za-z0-9_-]*"[[:space:]]*:[[:space:]]*[0-9]*' \
                    | sed 's/"//g; s/ //g' | tr '\n' '  ')
    message=$(echo "$general_response"     | grep -o '"message"[^,}]*'        | head -1 | sed 's/"message":[[:space:]]*//' | tr -d '"')
    mal_count=$(echo "$malware_response"   | grep -o '"count"[^,}]*'          | head -1 | grep -o '[0-9]*')

    sep="\e[2m$(printf '%.0s─' {1..54})\e[0m"
    col="\e[2m│\e[0m"

    echo -e "\n$sep"
    printf "${col} %-20s ${col} %-28s ${col}\n" "Field"              "Value"
    echo -e "$sep"
    printf "${col} %-20s ${col} %-28s ${col}\n" "OTX Pulses"         "${pulse_count:--}"
    printf "${col} %-20s ${col} %-28s ${col}\n" "Indicator Count"    "${ind_count:--}"
    printf "${col} %-20s ${col} %-28s ${col}\n" "Indicator Types"    "${ind_types:--}"
    printf "${col} %-20s ${col} %-28s ${col}\n" "Malware Samples"    "${mal_count:--}"
    printf "${col} %-20s ${col} %-28s ${col}\n" "Validation Message" "${message:--}"
    echo -e "$sep"
    printf "\e[2m  More info: \e[0m\e[1mhttps://otx.alienvault.com/indicator/ip/$ip\e[0m\n"

done
