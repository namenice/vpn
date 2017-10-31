#!/bin/bash

#

#

newclient () {

	# Generates the custom client.ovpn

	cp /etc/openvpn/client-common.txt ~/$1.ovpn

	echo "<ca>" >> ~/$1.ovpn

	cat /etc/openvpn/easy-rsa/pki/ca.crt >> ~/$1.ovpn

	echo "</ca>" >> ~/$1.ovpn

	echo "<cert>" >> ~/$1.ovpn

	cat /etc/openvpn/easy-rsa/pki/issued/$1.crt >> ~/$1.ovpn

	echo "</cert>" >> ~/$1.ovpn

	echo "<key>" >> ~/$1.ovpn

	cat /etc/openvpn/easy-rsa/pki/private/$1.key >> ~/$1.ovpn

	echo "</key>" >> ~/$1.ovpn

	echo "<tls-auth>" >> ~/$1.ovpn

	cat /etc/openvpn/ta.key >> ~/$1.ovpn

	echo "</tls-auth>" >> ~/$1.ovpn

}



manageiface() {

	while  :

	do    

		echo "Manage interface"

		echo ""

		echo "   1) Add network interface"

		echo "   2) Remove network interface"

		echo "   3) Show nat interface"

		echo "   4) Exit"

		read -p "Select an option [1-4]: " option

		case $option in

			1)

			clear

            addinterface

			continue;;

			2) 

			clear

			removeinterface     

            continue;;

			3) 

			clear

			shownatinterface     

            continue;;

            4)  

            break;;

		esac

	done

}



shownatinterface() {

		interface=$(cat /etc/openvpn/server.conf | grep  'push' |cut -d " " -f6)							

		ip=$(cat /etc/openvpn/server.conf | grep  'push' |cut -d " " -f3)	

		mask=$(cat /etc/openvpn/server.conf | grep  'push' |cut -d " " -f4)

	    set -f        

	    mask=$(echo "$mask" | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b")             

	    netmask=(${mask})

	    iface=(${interface})

	    address=(${ip})

	    ## show ip address

	    List=${#iface[@]}

	    if [[ "$List" < 1 ]]; then

	    	echo ""

	    	echo -e "\e[93mNo interface to NAT.\e[0m"

	    	echo ""

	    else

	    for i in "${!iface[@]}"

	    do

	    	echo "$[i+1]) NAT Network: ${address[i]} ${netmask[i]} to Interface: ${iface[i]}"

	    done

	    read -n1 -r -p "Press Enter or any key to continue..."

	    clear

		fi

}



addinterface() {

	gg=$(ip r show|grep " src "|cut -d " " -f 1)

	gx=$(ip r show|grep " src "|cut -d " " -f 3)

	mask=$(ifconfig | grep 'Mask:' | cut -d: -f4)

	set -f             

	networkstr=(${gg//\n/ })

	ifacestr=(${gx//;/ })

	maskstr=(${mask//\n/ })

	for i in "${!networkstr[@]}"

	do

		j=i+1

		echo ""

    	echo "Interface $[j] : ${ifacestr[i]}"

    	echo "Network $[j] : ${networkstr[i]}"

    	echo "-------------------------------"

	done





	List=${#networkstr[@]}

	echo ""

	echo "## choose one of choice. ##"

	echo "## *If you need to exit choose other choice ##"

	read -p "Select [1-$List]: " option

	newop=$(($option-1))

	if [[ "$newop" < "$List" ]]; then

		if [[ "$option" < ${List}+1 ]]; then

			k=option-1

			#network

			ipnetwork=$(echo "${networkstr[k]}" | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b")

			#interface

			interfacenetwork=${ifacestr[k]}

			#subnetnetwork

			subnetnetwork=${maskstr[k]}

			echo "Interface$[option]: $interfacenetwork"

			echo "Network$[option]: $ipnetwork"

			echo "subnetmask$[option]: $subnetnetwork"

		fi

		network=$ipnetwork

		subnet=$subnetnetwork

		interface=$interfacenetwork

		read -p "Do you really want to add network ? [y/n]: " -e -i y addfi

			if [[ "$addfi" = 'y' ]]; then

			#echo "-A POSTROUTING -s 10.8.0.0/24 -o $interface -j MASQUERADE"

            #add			

 				if grep -q "push \"route $network $subnet\"" /etc/openvpn/server.conf; 

				then

    				sed -i -e "/push \"route $network $subnet\" # $interface/c\push \"route $network $subnet\" # $interface" /etc/openvpn/server.conf

				else

					echo "push \"route $network $subnet\" # $interface" >> /etc/openvpn/server.conf

				fi 		

 			#check new add

 				if grep -q ":POSTROUTING ACCEPT \[0:0\]" /etc/ufw/before.rules; 

				then

					if ! grep -q -e "-A POSTROUTING -s 10.8.0.0/24 -o $interface -j MASQUERADE" /etc/ufw/before.rules; 

					then

						sed -i -e '/:POSTROUTING ACCEPT \[0:0\]/a -A POSTROUTING -s 10.8.0.0/24 -o '$interface' -j MASQUERADE' /etc/ufw/before.rules

						echo "Add network:$network to interface: $interface success!"  	

    				else

    					echo -e "\e[93mThis $interface has been NAT.\e[0m"

					fi	

				else

                    sed -i -e "1s/^/#START OPENVPN RULES NAT table rules\n/" /etc/ufw/before.rules

                    sed -i -e '/#START OPENVPN RULES NAT table rules/a *nat' /etc/ufw/before.rules

                    sed -i -e '/*nat/a :POSTROUTING ACCEPT [0:0]' /etc/ufw/before.rules

                    sed -i -e '/:POSTROUTING ACCEPT \[0:0\]/a -A POSTROUTING -s 10.8.0.0/24 -o '$interface' -j MASQUERADE' /etc/ufw/before.rules

                    sed -i -e '/-A POSTROUTING -s 10.8.0.0\/24 -o '$interface' -j MASQUERADE/a COMMIT' /etc/ufw/before.rules

                    echo "Add network:$network to interface:$interface success!" 

				fi

			ufw reload

            systemctl restart openvpn@server

            #echo "Add $network to $interface success!"      

            fi     

    else

		clear

    	echo -e "\e[93mPlease choose choice again.\e[0m"

    fi

}



removeinterface() {

	while :		

	do

	echo "1) Remove private network"

	echo "2) Exit"

	read -p "Number [1-2]: " number

	echo ""

	case $number in

		1)

		clear

		interface=$(cat /etc/openvpn/server.conf | grep  'push' |cut -d " " -f6)							

		ip=$(cat /etc/openvpn/server.conf | grep  'push' |cut -d " " -f3)	

		mask=$(cat /etc/openvpn/server.conf | grep  'push' |cut -d " " -f4)

	    set -f        

	    mask=$(echo "$mask" | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b")             

	    netmask=(${mask})

	    iface=(${interface})

	    address=(${ip})

	    ## show ip address

	    List=${#iface[@]}

	    if [[ "$List" < 1 ]]; then

	    	echo -e "\e[93mError Not Interface to NAT.\e[0m"

	    	echo ""

	    else

	    for i in "${!iface[@]}"

	    do

	    	echo "$[i+1]) ${iface[i]}  ${address[i]} ${netmask[i]}"

	    done

	    a=$i

		echo ""

	    read -p "Select number of network if you want to remove  [1-$List]: " option

	    newop=$(($option-1))

	    echo delete interface ${iface[newop]} network ${address[newop]} mask ${netmask[newop]}

	    if [[ "$newop" > "$a" ]]

	        then

	        clear

	        echo ""

	        echo -e "\e[31mError Plese select number of network again !!\e[0m"

	        echo ""

	    	else

	    		read -p "Do you really want to remove network? [y/n]: " -e -i y q

	    		if [[ "$q" = 'y' ]]; then

		     	interface=(${iface[newop]})

		        addr=(${address[newop]})

			    subnet=(${netmask[newop]})

				#subnet=$(echo "$subnet" | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b")

		        sed -i -e "/push \"route $addr $subnet\" # $interface/c\\" /etc/openvpn/server.conf

		        sed -i -e "/-A POSTROUTING -s 10.8.0.0\/24\ -o $interface -j MASQUERADE/c\\" /etc/ufw/before.rules

				ufw reload

				systemctl restart openvpn@server

				clear

				echo ""

				echo "Remove network $addr $subnet success!"

				echo "=================================================="  

		        echo ""

		        else

		        	break

	    		fi

		fi

		fi

	    ;;

		2) clear

		break

		;;			

	esac

	done

}



adduser(){

			clear

			echo ""

			echo "Tell me a name for the client certificate"

			echo "Please, use one word only, no special characters"

			read -p "Client name: " -e -i client CLIENT

			read -p "Do you really want to add new user ? [y/n]: " -e -i y adduser

			if [[ "$adduser" = 'y' ]]; then

				cd /etc/openvpn/easy-rsa/

				./easyrsa build-client-full $CLIENT nopass

				# Generates the custom client.ovpn

				newclient "$CLIENT"

				echo ""

				echo "Client $CLIENT added, configuration is available at" ~/"$CLIENT.ovpn"

				read -n1 -r -p "Press Enter or any key to continue..."

				systemctl restart openvpn@server.service

			fi

}



removeuser(){

	clear

			# This option could be documented a bit better and maybe even be simplimplified

			# ...but what can I say, I want some sleep too

			NUMBEROFCLIENTS=$(tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep -c "^V")

			if [[ "$NUMBEROFCLIENTS" = '0' ]]; then

				echo ""

				echo "You have no existing clients!"

				exit 6

			fi

			echo ""

			echo "Select the existing client certificate you want to revoke"

			tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | nl -s ') '

			if [[ "$NUMBEROFCLIENTS" = '1' ]]; then

				read -p "Select one client [1]: " CLIENTNUMBER

			else

				read -p "Select one client [1-$NUMBEROFCLIENTS]: " CLIENTNUMBER

			fi

			CLIENT=$(tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | sed -n "$CLIENTNUMBER"p)

			cd /etc/openvpn/easy-rsa/



			read -p "Do you really want to delete this user ? [y/n]: " -e -i y reuser

			if [[ "$reuser" = 'y' ]]; then

				./easyrsa --batch revoke $CLIENT

				EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl

				rm -rf pki/reqs/$CLIENT.req

				rm -rf pki/private/$CLIENT.key

				rm -rf pki/issued/$CLIENT.crt

				rm -rf /etc/openvpn/crl.pem

				cp /etc/openvpn/easy-rsa/pki/crl.pem /etc/openvpn/crl.pem

				# CRL is read with each client connection, when OpenVPN is dropped to nobody

				chown nobody:$GROUPNAME /etc/openvpn/crl.pem

				echo ""

				echo "Certificate for client $CLIENT revoked"

				read -n1 -r -p "Press Enter or any key to continue..."

				systemctl restart openvpn@server.service

			fi

}



uninstallvpn(){

			clear

			echo ""

			read -p "Do you really want to remove OpenVPN? [y/n]: " -e -i n REMOVE

			if [[ "$REMOVE" = 'y' ]]; then

                apt-get remove --purge -y openvpn

                rm -rf /etc/openvpn

                echo "OpenVPN removed finish!"

            fi

}



installvpn(){

    apt-get update

    #apt install openvpn easy-rsa

    apt-get install openvpn openssl ca-certificates easy-rsa -y

	wget -O ~/EasyRSA-3.0.3.tgz "https://github.com/OpenVPN/easy-rsa/releases/download/v3.0.3/EasyRSA-3.0.3.tgz"

	tar xzf ~/EasyRSA-3.0.3.tgz -C ~/

	sed -i 's/\[\[/\[/g;s/\]\]/\]/g;s/==/=/g' ~/EasyRSA-3.0.3/easyrsa

	mv ~/EasyRSA-3.0.3/ /etc/openvpn/

	mv /etc/openvpn/EasyRSA-3.0.3/ /etc/openvpn/easy-rsa/

	chown -R root:root /etc/openvpn/easy-rsa/

	rm -rf ~/EasyRSA-3.0.3.tgz

	cd /etc/openvpn/easy-rsa/

	./easyrsa init-pki

	./easyrsa --batch build-ca nopass

	./easyrsa gen-dh

	./easyrsa build-server-full server nopass

	./easyrsa build-client-full $CLIENT nopass

	EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl

	cp pki/ca.crt pki/private/ca.key pki/dh.pem pki/issued/server.crt pki/private/server.key pki/crl.pem /etc/openvpn

	# CRL is read with each client connection, when OpenVPN is dropped to nobody

	chown nobody:$GROUPNAME /etc/openvpn/crl.pem

	# Generate key for tls-auth

	openvpn --genkey --secret /etc/openvpn/ta.key

	# Generate server.conf

}

### check IP

IP=$(ip addr | grep 'inet' | grep -v inet6 | grep -vE '127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | grep -o -E '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | head -1)

if [[ "$IP" = "" ]]; then

                IP=$(wget -4qO- "http://whatismyip.akamai.com/")

fi

### create new user

if [[ -e /etc/openvpn/server.conf ]]; then

	while :

	do

	clear

		echo "Looks like OpenVPN is already installed"

		echo -e "\033[31m* Previous installed OpenVPN should be done by this script if not please remove previous one then reinstall by using this script * \e[0m"

		echo ""

		echo "What do you want to do?"

		echo ""

		echo "   1) Add a new user"

		echo "   2) Remove user"

		echo "   3) Manage interface"

		echo "   4) Remove OpenVPN"

		echo "   5) Exit"

		read -p "Select an option [1-5]: " option

		case $option in

			1) adduser

			;;

			2) removeuser

			;;

			3) 

			clear

			   manageiface

			echo "If you need to manageinterface go to run this file"

			;;

            4) uninstallvpn

            exit;;      

			5) exit;;

		esac

	done

else

## input data

        clear

        echo 'Welcome to this quick OpenVPN "road warrior" installer'

        echo ""

        # OpenVPN setup and first user creation

        echo "I need to ask you a few questions before starting the setup"

        echo "You can leave the default options and just press enter if you are ok with them"

        echo ""

        echo "First I need to know the IPv4 address of the network interface you want OpenVPN"

        echo "listening to."

        read -p "IP address: " -e -i $IP IP

        echo ""

		echo "Which protocol do you want for OpenVPN connections?"

		echo "   1) UDP (recommended)"

		echo "   2) TCP"

		read -p "Protocol [1-2]: " -e -i 1 PROTOCOL

		case $PROTOCOL in

			1) 

			PROTOCOL=udp

			;;

			2) 

			PROTOCOL=tcp

			;;

		esac

        echo ""

        echo "What port do you want OpenVPN listening to?"

        read -p "Port: " -e -i 1194 PORT

        echo ""

        echo "Finally, tell me your name for the client certificate"

        echo "Please, use one word only, no special characters"

        read -p "Client name: " -e -i client CLIENT

        echo ""

        echo "Okay, that was all I needed. We are ready to setup your OpenVPN server now"

        read -n1 -r -p "Press Enter or any key to continue..."

        installvpn

echo "port $PORT

proto $PROTOCOL

dev tun

ca ca.crt

cert server.crt

key server.key

dh dh.pem

tls-auth ta.key 0

topology subnet

server 10.8.0.0 255.255.255.0

ifconfig-pool-persist ipp.txt

keepalive 10 120

comp-lzo

persist-key

persist-tun

status openvpn-status.log

verb 3

crl-verify crl.pem" > /etc/openvpn/server.conf

## Enable net.ipv4.ip_forward for the system

    sed -i '/\<DEFAULT_FORWARD_POLICY\>/c\DEFAULT_FORWARD_POLICY="ACCEPT"' /etc/default/ufw

	if ! grep -q "\<DEFAULT_FORWARD_POLICY\>" /etc/default/ufw; then

		echo 'DEFAULT_FORWARD_POLICY="ACCEPT"' >> /etc/default/ufw

	fi



	sed -i '/\<net.ipv4.ip_forward\>/c\net.ipv4.ip_forward=1' /etc/sysctl.conf

	if ! grep -q "\<net.ipv4.ip_forward\>" /etc/sysctl.conf; then

		echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf

	fi

	sysctl -p /etc/sysctl.conf

        ufw allow $PORT/$PROTOCOL

        ufw allow OpenSSH

        ufw disable

		ufw enable

        systemctl restart openvpn@server.service

## create client

echo "client

dev tun

proto $PROTOCOL

remote $IP $PORT

resolv-retry infinite

nobind

persist-key

persist-tun

remote-cert-tls server

comp-lzo

setenv opt block-outside-dns

key-direction 1

verb 3" > /etc/openvpn/client-common.txt

	# Generates the custom client.ovpn

	newclient "$CLIENT"

	read -p "Do you want to manage your interface? [y/n]: " -e -i y q

	if [[ "$q" = 'y' ]]; then

    manageiface

    echo "Finished to manage interface"

    else echo "IF you need to manage interface try to run this file."

	fi

	echo ""

	echo "Install Finished!"

fi

clear

	echo "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ READ ME @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"

	echo "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@  Configure Server  @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"

	echo ""

	echo "1) You can run script again for manage user and network. "

	echo ""

	echo "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@  Configure client  @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"

	echo ""

	echo "1) install openvpn at client using command \"sudo apt-get install openvpn\""

	echo "2) Copy key from Server usding command \"sudo cp filename.opvpn /etc/openvpn/client.conf\""

	echo "3) Restart openvpn using command \"sudo systemctl restart openvpn@client\""

	echo ""

	echo "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@"
