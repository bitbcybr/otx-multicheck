#!/bin/bash
#script for curl otx api with ips from listfile and get some interesting fields with corresponding link to otx website

#beginning of the script
#script name with colored background
echo -e "\e[44m-- OTX Multi IP Check Bash Script v0.1 --\e[0m"
#different text formating with tput
bold=$(tput bold)
normal=$(tput sgr0)

#description and usage
echo -e "${bold}This script is processing a plain or txt file with multiple ip addresses (seperated with "\;" or "\," or one per line) to run a check on OTX platform.${normal} \nWorks for IPv4. IPv6 and URLs not yet supported.\n
It will output some interesting findings(more or less) from the APIs endpoints 'general' and 'malware'. Feel free to modify it on behalf of your needs and always keep FOSS in mind."
echo -e "${bold}\nUsage:\n./otx_multicheck.sh [path/filename with your IPs] ${normal}"

#input of the file with list
listfile=$1

#check if input is a file if not print usage and exit
if [ ! -f "$1" ]; then
	echo -e "${bold}File missing or input is not a file.${normal}\nPlease do ${bold}./otx_multiipcheck.sh filename${normal}\n";
	exit 1
else
	echo -e "\e[44m - Running $0 on: $1 \e[0m"
fi

#start of loop
#read ips from the file and run through each ip in a while loop
#if ips using delimiter ; or , replace it with a new line for read command to process
#awk NF for filtering out all empty lines AND if not used the last ip is only read when followed by a empty line at the end of iplist file

proc_listfile=$(cat "$listfile" | tr ';,' '\n' | awk NF)

#changed cat to echo, because cat not working with proc_listfile variable and this is maybe needed for further purpose
echo "$proc_listfile" | while read ip; do
echo -e "\e[1mProcessing IP: $ip \e[0m"
#set url for the api query based on the ip addresses in given file
    api_url_general="https://otx.alienvault.com/api/v1/indicators/IPv4/$ip/general"
    api_url_malware="https://otx.alienvault.com/api/v1/indicators/IPv4/$ip/malware"

#example from otx api output:
# , "indicator_type_counts": {"FileHash-MD5": 77, "FileHash-SHA1": 77, "FileHash-SHA256": 77, "URL": 2, "domain": 4, "hostname": 2}, "indicator_count": 239, 

#grep -o for only the parts which are in a specfic format like "indicator": [^,]*
#with [^,]* match all characters that are not a comma ([^,]) any number of times (*) up to the first comma
# use sed to modify the standard output of otx api json key "count" to better description "OTX Pulses"

generalcheck=$(curl -s "$api_url_general" | grep -o '"count"[^,]*\|"message"[^,]*\|"indicator_type_counts"[^}]*\|"indicator_count"[^,]*' | sed -e 's/"count"/"Related OTX Pulses"/g' -e 's/"message":/"Validation Message":/g') 
echo -e "\nGeneral Check: \n$generalcheck"

malwarecheck=$(curl -s "$api_url_malware" | grep -o '"detections"[^}]*\|"count"[^}]*')
echo -e "\nMalware Check: \n$malwarecheck\n"

printf "\e[1mMore information: https://otx.alienvault.com/indicator/ip/$ip\n\e[0m"
    echo -e "--------------------------------------------------\n"
done
#end
