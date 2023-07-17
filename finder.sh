#!/usr/bin/bash

# .--------------------------------------------------------------.
# | *************************Finder******************************|
# |     Script for fast large scale vulnerability scanning       |
# | *************************************************************|
# *--------------------------------------------------------------*
# Large scale discovery and vulnerability scanning 
# and more... 
# +++ work in progress +++
version='0.2.0-pre-alpha'


######################################################################################
# miscellaneous
######################################################################################

# check if root
if [[ $EUID -ne 0 ]]; then
   echo -e "\033[1;31m[!] You are not root!\033[0m"
   exit 1
fi

# install tools
# tools: figlet, nmap, zmap, dmitry, metasploit-framework

if [ -f /usr/bin/figlet ]; then 
    echo -e '[i] Figlet is already installed\n' 
else      
    echo -e '[+] Install Figlet...\n'
    sudo apt install -y figlet 
fi
if [ -f /usr/bin/nmap ]; then 
    echo -e '\n[i] Nmap is already installed\n' 
else 
    echo -e '\n[+] Install Nmap...\n'
    sudo apt install -y nmap
fi
if [ -f /usr/sbin/zmap ]; then 
    echo -e '\n[i] Zmap is already installed\n' 
else
    echo -e '\n[+] Install Zmap...\n'
    sudo apt install -y zmap 
fi
if [ -f /usr/bin/masscan ]; then 
    echo -e '\n[i] Masscan is already installed\n' 
else 
    echo -e '\n[+] Install masscan...\n'
    sudo apt install -y masscan
fi
if (which masscan == 0); then 
    sudo apt install masscan
fi
if (which zmap == 0); then 
    sudo apt install zmap
fi
if (which msfconsole == 0); then 
    sudo apt install metasploit-framework 
fi

# banner
pure_art () { 
    clear;
    figlet "Finder"
    echo -e "\033[1;37m$version\033[0m"
    echo -e "\033[1;95mLets grep the shit out of it.\033[0m\n"
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

check_interface () {
    
    while [[ $iface = "" ]]; do
	ifconfig -s | cut -d ' ' -f 1 | awk '{if (NR!=1) {print}}'
        echo -e "\n\033[1;37mInterface: \033[0m"
	read iface
    done
}

# define some options
blacklist=$HOME/'blacklist.txt'
packets_per_second=40
bytes_per_second='100K'
country_ipv4_directory=$HOME/'finder/ipv4/'

# define country list
country_list=(afghanistan=af.lst aland_islands=ax.lst albania=al.lst algeria=dz.lst american_samoa=as.lst andorra=ad.lst angola=ao.lst anguilla=ai.lst antarctica=aq.lst anigua_and_barbuda=ag.lst argentina=ar.lst armenia=am.lst aruba=aw.lst australia=au.lst austria=at.lst azerbaijan=az.lst bahamas=bs.lst bahrain=bh.lst bangladesh=bd.lst barbados=bb.lst belarus=by.lst belgium=be.lst belize=bz.lst benin=bj.lst bermuda=bm.lst bhutan=bt.lst bolivia=bo.lst bonaire_sint_saba=bq.lst bosnia_and_herzegovina=ba.lst botswana=bw.lst bouvet_island=bv.lst brazil=br.lst british_indian_ocean_territory=io.lst brunei_darussalam=bn.lst bulgaria=bg.lst burkina_faso=bf.lst burma= burundi=bi.lst cabo_verde=cv.lst cambodia=kh.lst cameroon=cm.lst canada=ca.lst cayman_islands=ky.lst central_african_republic=cf.lst chad=td.lst chile=cl.lst china=cn.lst christmas_island=cx.lst cocos=cc.lst colombia=co.lst comoros=km.lst congo_democratic_republic=cd.lst congo=cg.lst cook_islands=ck.lst costa_rica=cr.lst cote_dlvoire=ci.lst croatia=hr.lst cuba=cu.lst curacao=cw.lst cyprus=cy.lst czechia=cz.lst denmark=dk.lst djibouti=dj.lst dominica=dm.lst dominican_republic=do.lst ecuador=ec.lst egypt=eg.lst el_salvador=sv.lst equatorial_guinea=gq.lst eritrea=er.lst estonia=ee.lst eswatini=sz.lst ethiopia=et.lst falkland_islands=fk.lst faroe_islands=fo.lst fiji=fj.lst finland=fi.lst france=fr.lst french_guiana=gf.lst french_polynesia=pf.lst french_southern_territories=tf.lst gabon=ga.lst gambia=gm.lst georgia=ge.lst germany=de.lst ghana=gh.lst gibraltar=gi.lst great_britain=gb.lst greece=gr.lst greenland=gl.lst grenada=gd.lst guadeloupe=gp.lst guam=gu.lst guatemala=gt.lst guernsey=gg.lst guinea=gn.lst guinea_bissau=gw.lst guyana=gy.lst haiti=ht.lst heard_island_and_mcdonald_island=hm.lst holy_see_vatikan=va.lst honduras=hn.lst hongkong=hk.lst hungary=hu.lst iceland=is.lst india=in.lst indonesia=id.lst iran=ir.lst iraq=iq.lst ireland=ie.lst isle_of_man=im.lst israel=il.lst italy=it.lst ivory_coast= jamaica=jm.lst japan=jp.lst jersey=je.lst jordan=jo.lst kazakhstan=kz.lst kenya=ke.lst kiribati=ki.lst korea_north=kp.lst korea_south=kr.lst kuwait=kw.lst kyrgyzstan=kg.lst lao=la.lst latvia=lv.lst lebanon=lb.lst lesotho=ls.lst liberia=lr.lst libya=ly.lst liechtenstein=li.lst lithuania=lt.lst luxembourg=lu.lst macao=mo.lst north_mazedonia=mk.lst madagascar=mg.lst malawi=mw.lst malaysia=my.lst maldives=mv.lst malo=ml.lst malta=mt.lst marshall_islands=mh.lst martinique=mq.lst mauritania=mr.lst mauritius=mu.lst mayotte=yt.lst mexico=mx.lst micronesia=fm.lst moldava=md.lst monaco=mc.lst mongolia=mn.lst montenegro=me.lst montserrat=ms.lst morocco=ma.lst mozambique=mz.lst myanmar=mm.lst namibia=na.lst nauru=nr.lst nepal=np.lst netherlands=nl.lst new_caledonia=nc.lst new_zealand=nz.lst nicaragua=ni.lst niger=ne.lst nigeria=ng.lst niue=nu.lst norfolk_island=nf.lst northern_mariana_islands=mp.lst norway=no.lst oman=om.lst pakistan=pk.lst palau=pw.lst palestine=ps.lst panama=pa.lst papua_new_guinea=pg.lst paraguay=py.lst peru=pe.lst phillipines=ph.lst pitcairn=pn.lst poland=pl.lst portugal=pt.lst puerto_rico=pr.lst qatar=qa.lst reunion=re.lst romania=ro.lst russia=ru.lst rwanda=rw.lst saint_barhelemy=bl.lst saint_helena_ascension_island_tristan_da_cunha=sh.lst saint_kitts_and_nevis=kn.lst saint_lucia=lc.lst saint_martin=mf.lst saint_pierre_and_miquelon=pm.lst saint_vincent_and_the_grenadines=vc.lst samoa=ws.lst san_marino=sm.lst sao_tome_and_principe=st.lst saudi_arabia=sa.lst senegal=sn.lst serbia=rs.lst seychelles=sc.lst sierra_leone=sl.lst singapore=sg.lst sint_maarten=sx.lst slovakia=sk.lst slovenia=si.lst solomon_islands=sb.lst somalia=so.lst south_africa=za.lst south_georgia_and_the_sandwhich_islands=gs.lst south_sudan=ss.lst spain=es.lst sri_lanka=lk.lst sudan=sd.lst suriname=sr.lst svalbard_and_jan_mayen=sj.lst sweden=se.lst switzerland=ch.lst syrian=sy.lst taiwan=tw.lst tajikistan=tj.lst tanzania=tz.lst thailand=th.lst timor_leste=tl.lst togo=tg.lst tokelau=tk.lst tonga=to.lst trinidad_and_tobago=tt.lst tunesia=tn.lst turkey=tr.lst turkmenistan=tm.lst turks_and_caicos_islands=tc.lst tuvalu=tv.lst uganda=ug.lst ukraine=ua.lst united_arab_emirates=ae.lst britain_northern_ireland=gb.lst us_minor_outlying_islands=um.lst usa=us.lst uruguay=uy.lst uzbekistan=uz.lst vanuatu=vu.lst venezuela=ve.lst vietnam=vn.lst virgin_islands_gb=vg.lst virgin_islands_us=vi.lst wallis_and_futuna=wf.lst western_sahara=eh.lst yemen=ye.lst zambia=zm.lst zimbabwe=zw.lst)

# define vulnerable versions
postgresql='postgres|9.3|8.3.0|8.3.7|9.0|9.1|9.2'
ftp='2.3.4|'

###################################################################################
# large scale scans
###################################################################################

# nmap random scan
nmap_random_scan () {

  	# scan info
	echo -e "\033[1;37m[i] \033[1;37mOk, scanning ${how_many} hosts on port ${ports} with Nmap...\033[0m";
	# show Nmap version
	echo -e "\033[1;37m[i] $(nmap -V | head -n 1)\033[m" 
	# largeiscale nmap scan, check if a blacklist is available
	if [ -f 'blacklist.txt' ]; then 
	    sudo nmap -D RND,ME,RND,RND,RND,RND -Pn -T5 --host-timeout=10 --max-retries=1 -p ${ports} -iR ${how_many} --excludefile=${blacklist} -n --open -oA og > /dev/null;
	else 
        # scan without a blacklist
            echo -e "\033[1;31m[!] No blacklist is used!\033[0m"
	    sudo nmap -D RND,ME,RND,RND,RND,RND -Pn -T5 --host-timeout=10 --max-retries=1 -p ${ports} -iR ${how_many} -n --open -oA og > /dev/null;
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
	echo -e "\033[1;37m[i] File with service hosts:\033[0m $file"
	
	# check if cameras being searched, if yes asking for camera scan 
        # replace "|" with " " in $file to actually can grep it
        services_list=$(echo $service | sed -e 's/|/ /g')
        for service in $services_list; do 
            if [ "cam" == "$service" ]; then 
                camera_scanner
            fi
        done
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

nmap_country_only_scan () {

        # scan info
	echo -e "\033[1;37m[i] \033[1;37mOk, scanning ${which_country} ( ${country} ) on port ${ports} with Nmap...\033[0m";
	# show Nmap version
	echo -e "\033[1;37m[i] $(nmap -V | head -n 1)\033[m" 
	# large scale nmap scan, check if a blacklist is available
	if [ -f 'blacklist.txt' ]; then 
	    sudo nmap -D RND,ME,RND,RND,RND,RND -Pn -T5 --host-timeout=10 --max-retries=1 -p ${ports} -iL $country_ipv4_directory$country --excludefile=${blacklist} -n --open -oA og > /dev/null;
	else 
        # scan without a blacklist
            echo -e "\033[1;31m[!] No blacklist is used!\033[0m"
	    sudo nmap -D RND,ME,RND,RND,RND,RND -Pn -T5 --host-timeout=10 --max-retries=1 -p ${ports} -iL $country_ipv4_directory$country -n --open -oA og > /dev/null;
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

######################################################################################
# Advanced information gathering
######################################################################################

# ftp_scan
ftp_scan () { 

    # scan info
    echo -e "${pure_art}\n\n\033[1;37m[i] \033[1;37mOk, scanning ${how_many} hosts on port ${ports} with Nmap for vulnerabilities...\033[0m";
    echo -e "\033[1;37m[i] Vuln scan activ: Anonymous FTP login \033[0m\n";
        

    # ftp scan with NSE scripts	
    sudo nmap -mac -Pn -T5 --host-timeout=30 -p ${ports} -sV --version-intensity=4 -sC --script=ftp-anon -sS -iR ${how_many} -n --open -oA og > /dev/null;

    # show services	
    if cat og.gnmap | grep -iE "(${service})"; then
        echo -e "\n\033[1;92m[+] ftp found:\033[0m " $(cat og.gnmap | grep -iE "(${service})" | cut -f2 -d ' '); 
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

metasploit () {

    echo -e "\033[1;37m[?] Import hosts to Metasploit? \033[0m"
    read msf
    # fix exit when no import is needed
    echo -e "\033[1;37m(1) Import hosts with services found only without importing service informations, but u can scan again for more precise service informations\n(2) Import all hosts found ( all services found will be imported! ) \033[0m"
    read import_hosts
    if [ "${msf}" == "yes" ] || [ "${import_hosts}" -eq 1 ]; then
        echo -e "\033[1;37m[?] Do u wanna scan again for ( more precise ) service informations? \033[0m"
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

whois_scanner () {

    echo -e "\033[1;37m[?] Do u wanna see whois information? \033[0m"
    read more_info
    if [[ $more_info == "yes" ]]; then
        for i in $(cat /root/finder_scans/$file); do
            dmitry -iwn $i | grep -iE "(HostIP|HostName|netname|descr|country|role)"
        done
    fi
}

camera_scanner () {

    # check if any cameras are found and grep the IP addresses
    if hosts=($(cat $HOME/finder_scans/og.gnmap | grep -iE "(cam)" | sed '/Nmap\|Up/d'| grep -oE '((1?[0-9][0-9]?|2[0-4][0-9]|25[0-5])\.){3}(1?[0-9][0-9]?|2[0-4][0-9]|25[0-5])' | uniq)); then
        # if no cameras being found print that information
        if [ -z $hosts ]; then
            echo -e "\033[1;37m[i] No Cameras found. \033[0m"
        else
            # if cameras being found, show them and ask for opening them in a browser
            echo -e "\033[1;92m[+] Cameras found: \033[0m" $hosts
                for host in $hosts; do
                    echo -e "\033[1;37m[?] Do u wanna open all found cams in your Browser? \033[0m"
                    read open_browser
                    if [[ $open_browser == "yes" ]]; then
                        # add 'http://' at the begin of every IP address
                        for i in $hosts; do
                            url=$(echo 'http://'$i)
                            xdg-open $url
                        done
                    fi
                done
        fi
    else
        echo "og.gnmap not found"
    fi
}

######################################################################################
# user inputs
######################################################################################

user_input_random_scan () {

    # define interface
    echo -e "\033[1;37mInterface: \033[0m"
    read iface
    check_interface
    # define how many hosts to scan
    echo -e "\033[1;37mHow many: \033[0m"
    read how_many
    # define ports to scan
    echo -e "\033[1;37mWhich Port(s): \033[0m";
    read ports
    # define search term
    echo -e "\033[1;37mWhat are u searching for?: \033[0m";
    read service;
    service_input

    # erstelle file
    if [ -z $service ]; then
        add_quotes_to_file_name=$HOME/'finder.lst'; 
    else
        add_quotes_to_file_name=${service}.lst; 
    fi
    file=$(echo $add_quotes_to_file_name | sed -e 's_|_\__g');


	#echo -e "\033[1;37m${pure_art}\n\n[i] \033[1;37mOk, scanning ${how_many} hosts on port ${ports} for ${service}...\033[0m\n";
	pure_art
	echo -e "\033[1;37mSearch for vulnerabilities? ( Can take some more time ) \033[0m"
	read search_for_vulns;
	pure_art
}

user_input_country_scan () {

	# define interface
	echo -e "\033[1;37mInterface: \033[0m"
	read iface
        check_interface
	# define the country('s) to scan
	echo -e "\033[1;37mWhich country('s) do u wanna scan?:  \033[0m"
	read which_country
	# add a '=' instead of ' ' to make a list of country variables
	country=$(echo ${country_list[@]} |awk -v FPAT=${which_country}[^[:space:]]+ 'NF{ print $1 }' |cut -d '=' -f2)
	# define ports to scan
	echo -e "\033[1;37mWhich Port(s): \033[0m";
	read ports;
	# define search term
	echo -e "\033[1;37mWhat are u searching for?: \033[0m";
	read service;
	service_input

	# erstelle file
	if [ -z $service ]; then
	    add_quotes_to_file_name=$HOME/'finder.lst'
	else add_quotes_to_file_name=${service}.lst
	fi
	file=$(echo $add_quotes_to_file_name | sed -e 's_|_\__g');
	pure_art
	echo -e "\033[1;37mSearch for vulnerabilities? ( Can take some more time ) \033[0m"
	read search_for_vulns;
	pure_art
}

# define the vulnerabilities u want to search for
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

######################################################################################
# main
######################################################################################

# define scan with nmap only
nmap_scan () {
	
    pure_art
    user_input_random_scan
    service_input
    nmap_random_scan
    whois_scanner
    metasploit
}

# define scan with zmap
zmap_scan () {
	
    pure_art
    user_input_random_scan
    zmap
    version_detection
    ip_to_file
    metasploit
}

# define country scan with nmap only
nmap_country_scan () {
	
    pure_art
    user_input_country_scan
    service_input
    nmap_country_only_scan
    metasploit
}

# main
main () {
	
    # define which scan to use
    pure_art
    change_directory
    echo -e "\033[1;37m(1) Random scan or (2) Country based scan?: \033[0m"
    read random_or_country
    if [ "${random_or_country}" -eq 1 ]; then
        echo -e "\033[1;37m(1) Nmap or (2) Zmap: \033[0m"
        read nmap_or_zmap
        if [ "${nmap_or_zmap}" -eq 1 ]; then
            nmap_scan
        elif [ "${nmap_or_zmap}" -eq 2 ]; then
	    zmap_scan
        else 
	    echo "No input. Quit."
	    exit
        fi
    elif [ "${random_or_country}" -eq 2 ]; then
	echo -e "\033[1;37m(1) Nmap or (2) Zmap: \033[0m"
	read nmap_or_zmap
	if [ "${nmap_or_zmap}" -eq 1 ]; then
            nmap_country_scan
        elif [ "${nmap_or_zmap}" -eq 2 ]; then
	    zmap_country_scan
        else 
	    echo "No input. Quit."
	    exit
        fi
    else
	echo "No input. Quit."
	exit
    fi
	

}

main


