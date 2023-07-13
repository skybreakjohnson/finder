#!/usr/bin/bash

# .--------------------------------------------------------------.
# | ********************Finder for Nmap**************************|
# | Script for fast large scale vulnerability scanning with Nmap |
# | *************************************************************|
# *--------------------------------------------------------------*
# Large scale discovery and vulnerability scanning 
# Used tools: Nmap, Zmap, Masscan, Whatweb, Wpscan, Metasploit
# +++ work in progress +++
version='0.1.2dev'


# check if root
if [[ $EUID -ne 0 ]]; then
   echo -e "\033[1;31m[!] You are not root!\033[0m"
   exit 1
fi

# install tools
if [ -f /usr/bin/figlet ]; then echo -e '[i] Figlet is already installed\n'; else (echo -e '[+] Install Figlet...\n'; sudo apt install -y figlet); fi
if [ -f /usr/bin/nmap ]; then echo -e '\n[i] Nmap is already installed\n'; else (echo -e '\n[+] Install Nmap...\n'; sudo apt install -y nmap); fi
if [ -f /usr/sbin/zmap ]; then echo -e '\n[i] Zmap is already installed\n'; else (echo -e '\n[+] Install Zmap...\n'; sudo apt install -y zmap); fi
if [ -f /usr/bin/masscan ]; then echo -e '\n[i] Masscan is already installed\n'; else (echo -e '\n[+] Install masscan...\n'; sudo apt install -y masscan); fi

if (which masscan == 0); then (sudo apt install masscan); fi
if (which zmap == 0); then (sudo apt install zmap); fi
if (which msfconsole == 0); then (sudo apt install metasploit-framework); fi

# banner
pure_art () { 
clear;
figlet "Finder"
echo -e "\033[1;37m$version\033[0m"
echo -e "\033[1;95mLets grep the shit out of it.\033[0m"
nmap -V | head -n 1;
echo
}

# create directory for scan results
change_directory () {
    file_path=$HOME'/finder_scans'
    if [ -d $file_path ]; then
        cd $file_path
    else
        mkdir $file_path
	cd $file_path
    fi
}

# define some options
blacklist=$HOME/'blacklist.txt'
packets_per_second=40
bytes_per_second='100K'

# define vulnerable versions
postgresql='postgres|9.3|8.3.0|8.3.7|9.0|9.1|9.2'
ftp='2.3.4|'

# nmap only scan
nmap_only_scan () {

  	# scan info
	echo -e "\033[1;37m[i] \033[1;37mOk, scanning ${how_many} hosts on port ${ports} with Nmap...\033[0m";

	# large scale nmap scan
	# check if a blacklist is available
	if [ -f 'blacklist.txt' ]; then 
	    sudo nmap -D RND,ME,RND,RND,RND,RND -Pn -T5 --host-timeout=10 --max-retries=1 -p ${ports} -iR ${how_many} --excludefile=${blacklist} -n --open -oA og > /dev/null;
	else 
        # scan without a blacklist
            echo -e "\033[1;31m[!] No blacklist is used!\033[0m" && sudo nmap -D RND,ME,RND,RND,RND,RND -Pn -T5 --host-timeout=10 --max-retries=1 -p ${ports} -iR ${how_many} -n --open -oA og > /dev/null;
	fi

	# write ip's to file
	while [ -f hosts.lst ]; do
	    rm hosts.lst; done
	touch hosts.lst;
	for i in $(cat og.gnmap |grep -iE "(status)"); do
		echo $i | grep -oE '((1?[0-9][0-9]?|2[0-4][0-9]|25[0-5])\.){3}(1?[0-9][0-9]?|2[0-4][0-9]|25[0-5])' >> hosts.lst; done;
		echo -e "\033[1;37m[i] File with hosts:\033[0m hosts.lst";

	# count hosts
	for hosts in $(cat og.gnmap | grep -iE "(Ports:)" | uniq | wc -l);
	do echo -e "\033[1;92m[+] Hosts: \033[0m $hosts";
	
	# show scan time
	echo -e "\033[1;37m[i] Time:\033[0m " $(cat og.gnmap | tail -n 1 | cut -f19- -d ' ')

	# scan info
	echo -e "\033[1;37m[i] \033[1;37mOk, scanning ${hosts} hosts on port ${ports} for ${service} with Nmap...\033[0m";
	done;

	# service detection scan
	sudo nmap -D RND,ME,RND,RND,RND,RND -Pn -T5 --host-timeout=30 -p ${ports} -sV --version-intensity=4 -sS -iL hosts.lst -n --open -oA og > /dev/null;

	# grep services
	if cat og.gnmap | grep -iE "(${service})" | sed '/Nmap\|Up/d'; then 
	
	# show hosts with services found
	hosts=$(echo -e "\n\033[1;92m[+] ${service} found:\033[0m " $(cat og.gnmap | grep -iE "(${service})" | sed '/Nmap\|Up/d'| grep -oE '((1?[0-9][0-9]?|2[0-4][0-9]|25[0-5])\.){3}(1?[0-9][0-9]?|2[0-4][0-9]|25[0-5])' | uniq)); echo $hosts;
        fi;	
	
	# count hosts with services found
	if i=$(cat og.gnmap | grep -iE "(${service})" | sed '/Nmap\|Up/d'| grep -oE '((1?[0-9][0-9]?|2[0-4][0-9]|25[0-5])\.){3}(1?[0-9][0-9]?|2[0-4][0-9]|25[0-5])' | uniq | wc -w);
	then echo -e "\033[1;92m[+] Hosts with services found: \033[0m $i";
	fi;

	# show scan time
	echo -e "\033[1;37m[i] Time:\033[0m " $(cat og.gnmap | tail -n 1 | cut -f19- -d ' ');

	# write ip's with found services to file
	while [ -f $file ]; do
	    rm $file; done
	touch $file;
	for i in $(cat og.gnmap | grep -iE "(${service})" | sed '/Nmap\|Up/d');do 
	    echo $i | grep -oE '((1?[0-9][0-9]?|2[0-4][0-9]|25[0-5])\.){3}(1?[0-9][0-9]?|2[0-4][0-9]|25[0-5])' | uniq >> $file; done;
	echo -e "\033[1;37m[i] File with service hosts:\033[0m $file";
}

# version detection scan after zmap
version_detection () {

  	# scan info
	echo -e "\033[1;37m[i] \033[1;37mOk, scanning ${zmap_hosts} hosts on port ${ports} for ${service} with Nmap...\033[0m\n";

	# service detection scan
	sudo nmap -D RND,ME,RND,RND,RND,RND -Pn -T5 --host-timeout=30 -p ${ports} -sV --version-intensity=4 -sS -iL ${zmap} -n --open -oA og > /dev/null;

	# grep services
	if cat og.gnmap | grep -iE "(${service})"; 
	# show hosts
	then echo -e "\n\033[1;92m[+] ${service} found:\033[0m " $(cat og.gnmap | grep -iE "(${service})" | cut -f2 -d ' ');
	fi;

	# count hosts with services found
	for i in $(cat og.gnmap | grep -iE "(${service})" | wc -l);
	do echo -e "\033[1;37m[i] Hosts: \033[0m $i";
	done;

	# show scan time
	echo -e "\033[1;37m[i] Time:\033[0m " $(cat og.gnmap | tail -n 1 | cut -f19- -d ' ')
}

# ftp_scan
ftp_scan () { 

		# scan info
		echo -e "${pure_art}\n\n\033[1;37m[i] \033[1;37mOk, scanning ${how_many} hosts on port ${ports} with Nmap for vulnerabilities...\033[0m";
        echo -e "\033[1;37m[i] Vuln scan activ: Anonymous FTP login \033[0m\n";
        

        # ftp scan with NSE scripts	
		sudo nmap -mac -Pn -T5 --host-timeout=30 -p ${ports} -sV --version-intensity=4 -sC --script=ftp-anon -sS -iR ${how_many} -n --open -oA og > /dev/null;

		# show services	
		if cat og.gnmap | grep -iE "(${service})";
		then echo -e "\n\033[1;92m[+] ftp found:\033[0m " $(cat og.gnmap | grep -iE "(${service})" | cut -f2 -d ' '); 
		fi;

		# show Anonymous FTP login
		anon=$(echo -e "\n\033[1;92m[+] Anon found:\033[0m " $(cat og.nmap > /dev/null);
		cat og.nmap | grep -B 5 -iE "(code 230)"); echo $anon;

		# grep hosts
		# echo -e "\nHosts:"; echo $anon |head -n 3 | cut -f5 -d ' '; #bug
		# for i in $(echo $anon |head -n 3 | cut -f5 -d ' '); do
		# echo $i | grep -oE '((1?[0-9][0-9]?|2[0-4][0-9]|25[0-5])\.){3}(1?[0-9][0-9]?|2[0-4][0-9]|25[0-5])' >> anon_ftp.lst; done;
		anon=$(echo -e "\n\033[1;92m[+] Anon found:\033[0m " $(cat og.nmap > /dev/null);
                cat og.nmap | grep -B 5 -iE "(code 230)"); echo $anon | grep -oE '((1?[0-9][0-9]?|2[0-4][0-9]|25[0-5])\.){3}(1?[0-9][0-9]?|2[0-4][0-9]|25[0-5])' >> anon_ftp.lst;

		echo -e "\033[1;37m[i] File with hosts:\033[0m $file";
		
		# show scan time
		echo -e "\033[1;37m[i] Time:\033[0m " $(cat og.gnmap | tail -n 1 | cut -f19- -d ' ')
}

zmap () {

	echo -e "\033[1;91m[!] Be careful, this scan can and probably will be detected by your ISP. Maybe will result in a disconnect.\033[0m";	
	new_mac=$(sudo macchanger ${iface} -r | tail -n 1 | cut -f3- -d ' ' | cut -f1 -d '(');
	echo -e "\033[1;37m${pure_art}\n\n\033[1;37m[i] New MAC:\033[0m${new_mac}";
	echo -e "\033[1;37m[i] Ok, scanning ${how_many} hosts for open port ${ports} with Zmap...\033[0m";
	echo -e "\033[1;37m[i] \033[1;37mUsing blacklist:\033[0m ${blacklist}";
	#echo -e "\033[1;37m[i] \033[1;37mPackets per second: ${packets_per_second}\033[0m";
	#echo -e "\033[1;37m[i] \033[1;37mSpeed: ${bytes_per_second} per second\033[0m";

	sudo zmap -i ${iface} -G ${new_mac} -q -b ${blacklist} -n ${how_many} -p ${ports} -o zmap;
	for i in $(cat zmap | wc -l);
	 	do echo -e "\033[1;37m[i] Hosts found:\033[0m  $i";
	 	zmap_hosts=$i;
	 	continue
	done;
}

metasploit () {

    echo -e "\033[1;37m[i] Import hosts to Metasploit? \033[0m"
    read msf
    echo -e "\033[1;37m[i] (1) Import hosts with services found only without importing service informations, but u can scan again for more precise service informations\n    (2) Import all hosts found ( all services found will be imported! ) \033[0m"
    read import_hosts
    if [ "${msf}" == "yes" ] || [ "${import_hosts}" -eq 1 ]; then
        echo -e "\033[1;37m[i] Do u wanna scan again for ( more precise ) service informations? \033[0m"
	read precise_service_scan
	if [ "${precise_service_scan}" == "yes" ]; then
	    # check if msfb is running, initialize if not
            while [[ $(sudo msfdb status |grep dead) ]]; do
                echo -e "\033[1;31m[!] Msfdb not running. \033[0m\n\033[1;37m[i] Msfdb init... \n\033[0m"
	        sudo msfdb init; done
            echo -e "\033[1;37m[i] Starting msfconsole... \033[0m";
	    # import hosts with services found only and do a more precise service scan
	    echo -e "workspace -a finder\nworkspace finder\ndb_import $file\ndb_nmap -Pn -p$ports -sV --version-all -iL $file\nservices -S $service" > test.rc; 
	    msfconsole -q -x 'resource test.rc';
        elif [ "${precise_service_scan}" == "no" ]; then
	    while [[ $(sudo msfdb status |grep dead) ]]; do
                echo -e "\033[1;31m[!] Msfdb not running. \033[0m\n\033[1;37m[i] Msfdb init... \n\033[0m"
	        sudo msfdb init; done
            echo -e "\033[1;37m[i] Starting msfconsole... \033[0m";
	    # import hosts with services found only ( does not import service information in msfdb! )
	    echo -e "workspace -a finder\nworkspace finder\ndb_import $file\nhosts" > test.rc; 
	    msfconsole -q -x 'resource test.rc';
        else
	    echo -e "\033[1;37m[i] No option choosed. Yes or no! Bye. \033[0m"
	    exit
	fi
    elif [ "${msf}" == "yes" ] || [ "${import_hosts}" -eq 2 ]; then
        while [[ $(sudo msfdb status |grep dead) ]]; do
            echo -e "\033[1;31m[!] Msfdb not running. \033[0m\n\033[1;37m[i] Msfdb init... \n\033[0m"
	    sudo msfdb init; done
        echo -e "\033[1;37m[i] Starting msfconsole... \033[0m";
	# import all hosts found ( all services will be imported! )
	echo -e "workspace -a finder\nworkspace finder\ndb_import og.xml\nservices -S $service" > test.rc; 
	msfconsole -q -x 'resource test.rc';

    elif [[ "${msf}" -eq 0 ]]; then
	exit
    else
	exit
    fi
}       

user_input () {

	# define interface
	echo -e "\033[1;37mInterface: \033[0m"
	read iface
	# define how many hosts to scan
	echo -e "\033[1;37mHow many: \033[0m"
	read how_many;
	# define ports to scan
	echo -e "\033[1;37mWhich Port(s): \033[0m";
	read ports;
	# define search term
	echo -e "\033[1;37mWhat are u searching for?: \033[0m";
	read service;
	service_input

	# erstelle file
	if [ -z $service ]; then add_quotes_to_file_name=$HOME/'finder.lst'; else add_quotes_to_file_name=${service}.lst; fi
	file=$(echo $add_quotes_to_file_name | sed -e 's_|_\__g');


	#echo -e "\033[1;37m${pure_art}\n\n[i] \033[1;37mOk, scanning ${how_many} hosts on port ${ports} for ${service}...\033[0m\n";
	pure_art
	echo -e "\033[1;37mSearch for vulnerabilities? ( Can take some more time ) \033[0m"
	read search_for_vulns;
	pure_art
}

# define the service u want to search for
service_input () {
	
    if [ "${ports}" -eq 21 -a "${search_for_vulns}" == "yes" ]; then
	echo -e "(1) Anonymous FTP login  (2) FTP Vulns"
	read ftp
	if [ "${ftp}" -eq 1 ]; then
            ftp_scan;
	    ip_to_file
	    metasploit
	elif [ "${ftp}" -eq 2 ]; then
	    echo "Suck dick cyka"
	fi
    else 
	echo -e "\033[1;37m[i] No vulnerability search available
for this scan. \033[0m"
    fi
}

# define scan with nmap only
nmap_scan () {
	
	pure_art
	user_input
	service_input
	nmap_only_scan
	metasploit
}

# define scan with zmap
zmap_scan () {
	
	pure_art
	user_input
	zmap
	version_detection
	ip_to_file
	metasploit
}

# main
main () {
	
	# define which scan to use
	pure_art
	change_directory
	echo -e "\033[1;37m(1)Nmap or (2)Zmap: \033[0m"
	read nmap_or_zmap
	if [ "${nmap_or_zmap}" -eq 1 ]; then
		nmap_scan
	elif [ "${nmap_or_zmap}" -eq 2 ]; then
		zmap_scan
	else 
		echo "No input. Quit."
		exit
	fi
}

main


