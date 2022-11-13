#!/usr/bin/bash

# @Author: Dipan Nama
# @Date:   2022-10-27 00:32:26
# @Last Modified by:   Dipan Nama
# @Last Modified time: 2022-10-29 03:41:35



# Defining Global variables

host=$1
wordlist="/snap/seclists/current/Discovery/DNS/dns-Jhaddix.txt"
resolvers="/snap/seclists/10/Miscellaneous/dns-resolvers.txt"
resolve_domains="/usr/bin/massdns -r /snap/seclists/10/Miscellaneous/dns-resolvers.txt -t A -o S -w"


domain_enum(){
	for domain in $(cat $host);
	do
		mkdir -p $domain $domain/sources $domain/recon $domain/recon/nuclei $domain/recon/wayback $domain/recon/gf $domain/recon/roots $domain/recon/wordlist $domain/recon/aquatone $domain/recon/masscan $domain/recon/nmap

		subfinder -d $domain -o $domain/sources/subfinder.txt
		assetfinder -subs-only $domain | tee $domain/sources/assetfinder.txt
		amass enum -passive -d $domain -o $domain/sources/amass.txt
		# shuffledns -d $domain -w $wordlist -r $resolvers -o $domain/sources/shuffledns.txt
		cat $domain/sources/*.txt | anew $domain/sources/domains.txt
	done
}


# resolving_domains(){
	# for domain in $(cat $host);
	# do
# 		shuffledns -d $domain -list $domain/sources/domains.txt -o $domain/domains.txt
	# done
# }
# resolving_domains

http_prob(){
	for domain in $(cat $host);
	do
		cat $domain/sources/domains.txt | httpx -threads 200 -o $domain/recon/httpx.txt
	done
}

get_data(){
	for domain in $(cat $host);
	do
		cat $domain/recon/httpx.txt | fff -d 1 -S -o $domain/recon/roots
	done
}

aquatone_data(){
	for domain in $(cat $host);
	do
		cat $domain/recon/httpx.txt | aquatone -out $domain/recon/aquatone
	done
}

scanner(){
	for domain in $(cat $host);
	do
		cat $domain/recon/httpx.txt | nuclei -t ~/nuclei-templates/cves/ -c 50 -o $domain/recon/nuclei/cves.txt
		cat $domain/recon/httpx.txt | nuclei -t ~/nuclei-templates/file/ -c 50 -o $domain/recon/nuclei/file.txt
		cat $domain/recon/httpx.txt | nuclei -t ~/nuclei-templates/technologies/ -c 50 -o $domain/recon/nuclei/technologies.txt
		cat $domain/recon/httpx.txt | nuclei -t ~/nuclei-templates/vulnerabilities/ -c 50 -o $domain/recon/nuclei/vulnerabilities.txt
	done
}

wayback_data(){
	for domain in $(cat $host);
	do
		cat $domain/sources/domains.txt | waybackurls | tee $domain/recon/wayback/tmp.txt
		cat $domain/recon/wayback/tmp.txt |  egrep -i -v "\.woff|\.ttf|\.svg|\.png|\.jpeg|\.jpg|\.svg|\.css|\.ico|\.pdf|\.gif" | sed 's/:80//g;s/:443//g' | sort -u >> $domain/recon/wayback/wayback.txt
	done
}

valid_urls(){
	for domain in $(cat $host);
	do
		ffuf -c -u "FUZZ" -w $domain/recon/wayback/wayback.txt -mc 200 -of csv -o $domain/recon/wayback/valid-tmp.txt 
		cat $domain/recon/wayback/valid-tmp.txt | grep http | awk -F ',' '{print $1}' >> $domain/recon/wayback/valid.txt
		rm $domain/recon/wayback/valid-tmp.txt
	done
}

gf_patterns(){
	for domain in $(cat $host);
	do
		gf xss $domain/recon/wayback/valid.txt | tee $domain/recon/gf/xss.txt
		gf lfi $domain/recon/wayback/valid.txt | tee $domain/recon/gf/lfi.txt
		gf rce $domain/recon/wayback/valid.txt | tee $domain/recon/gf/rce.txt
		gf idor $domain/recon/wayback/valid.txt | tee $domain/recon/gf/idor.txt
		gf sqli $domain/recon/wayback/valid.txt | tee $domain/recon/gf/sqli.txt
		gf ssrf $domain/recon/wayback/valid.txt | tee $domain/recon/gf/ssrf.txt
		gf ssti $domain/recon/wayback/valid.txt | tee $domain/recon/gf/ssti.txt
		# for i in ~/.gf/*; do cat valid.txt |  gf `echo $i | cut -d "." -f2  | cut -d "/" -f2` | tee $domain/recon/gf/$(echo $i | cut -d "." -f2  | cut -d "/" -f2).txt ; done
	done
}

custom_wordlist(){
	for domain in $(cat $host);
	do
		cat $domain/recon/wayback/wayback.txt | unfurl -unique paths > $domain/recon/wordlist/paths.txt
		cat $domain/recon/wayback/wayback.txt | unfurl -unique keys > $domain/recon/wordlist/params.txt
	done
}


get_ip(){
	for domain in $(cat $host);
	do
		$resolve_domains $domain/recon/masscan/results.txt $domain/sources/domains.txt
		gf ip $domain/recon/masscan/results.txt | cut -d ":" -f3 | sort -u > $domain/recon/masscan/ip.txt
	done
}


nmap_scan(){
	for domain in $(cat $host);
	do
		for ip in $(cat $domain/recon/masscan/ip.txt);
		do
			nmap -sC -sV -oN $domain/recon/nmap/nmap_out_$ip.txt -pn -p- $ip
		done
	done
}



# Checking for arguments

# Showing Usage if no arguments was passed
if [ -z "$1" ]
  then
  	echo -e "Automate your recon phase easily while drinking coffee... :)"
    echo -e "\nUsage: "
    echo -e "  recon [flags] <File>"
    echo -e "\nFlags:"
    echo -e "	-d, --domains				search for subdomains"
    echo -e "	-h, --httpx				probes http/https service on all the given subdomains"
    echo -e "	-g, --get				takes the httproben data to work with fff tool"
    echo -e "	-a, --aquatone				takes the httproben data to work with aquatone tool"
    echo -e "	-n, --nuclei				takes the httproben data to work with nuclei tool"
    echo -e "	-w, --wayback				takes all the domains and send them to wayback mechine"
    echo -e "	-f, --ffuf				takes the wayback data and send them to ffuf tool"
    echo -e "	-p, --patterns				takes the valid urls and send them through gf tool"
    echo -e "	-u, --unfurl				takes the wayback data and unfurl them"
    echo -e "	-i, --ip				use masscan to get valid ip addresses"
    echo -e "	-s, --scan				send the valid ip addresses to nmap for scanning"
    echo -e "\nExamples:"
    echo -e "	recon scope.txt" 
    echo -e "		-- [Works with all the tools altogether]"
    echo -e "	recon scope.txt -d -h -g"
    echo -e "		-- [Works with fatching domains, probing http/https service and getting all the data using fff]"
    echo -e "	recon scope.txt -a -R"
    echo -e "		-- [Starts working with the doamins from using aquatone to the end of the program]"
    exit
fi


while true; do
	case "$1" in
		-d | --domains)
			echo "-d was triggered" >&2
			exit 0
		;;
		-h | --httpx)
			echo "-h was triggered" >&2
			exit 0
		;;
		g)
			echo "-g was triggered" >&2
		;;
		a)
			echo "-a was triggered" >&2
		;;
		n)
			echo "-n was triggered" >&2
		;;
		w)
			echo "-w was triggered" >&2
		;;
		f)
			echo "-f was triggered" >&2
		;;
		p)
			echo "-p was triggered" >&2
		;;
		u)
			echo "-u was triggered" >&2
		;;
		i)
			echo "-i was triggered" >&2
		;;
		s)
			echo "-s was triggered" >&2
		;;
		\?)
			echo "Invalid option!" >&2
			echo "QUITING..."
			exit 1
		;;
	esac
done







































# All the available function callings
# domain_enum
# http_prob
# get_data
# aquatone_data
# scanner
# wayback_data
# valid_urls
# gf_patterns
# custom_wordlist
# get_ip
# nmap_scan



# TODO:
	# Need API keys for chaos :(