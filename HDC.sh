#!/bin/bash

function write_header(){
		local h="$@"
		echo "---------------------------------------------------------------"
		echo "     ${h}"
		echo "---------------------------------------------------------------"
}		

function check_forward(){
		for dir in `cat /etc/passwd | awk -F: '{ print $6 }'`; do
		if [ ! -h "$dir/.forward" -a -f "$dir/.forward" ]; then
		echo ".forward file $dir/.forward exists"
		fi
		done
}

function check_netrc(){
		for dir in `cat /etc/passwd | awk -F: '{ print $6 }'`; do
		if [ ! -h "$dir/.netrc" -a -f "$dir/.netrc" ]; then
		echo ".netrc file $dir/.netrc exists"
		fi
		done
}

function check_user_dup(){
		cat /etc/passwd | cut -f1 -d":" | sort -n | uniq -c | while read x ; do
		[ -z "${x}" ] && break
		set - $x
		if [ $1 -gt 1 ]; then
				uids=`awk -F: '($1 == n) { print $3 }' n=$2 /etc/passwd | xargs`
				echo "Duplicate User Name ($2): ${uids}"
		fi
		done
}

function check_group_dup(){
		cat /etc/group | cut -f1 -d":" | sort -n | uniq -c | while read x ; do
		[ -z "${x}" ] && break
		set - $x
		if [ $1 -gt 1 ]; then
				gids=`gawk -F: '($1 == n) { print $3 }' n=$2 /etc/group | xargs`
				echo "Duplicate Group Name ($2): ${gids}"
		fi
		done
}

function check_uid_dup(){
		cat /etc/passwd | cut -f3 -d":" | sort -n | uniq -c | while read x ; do
		[ -z "${x}" ] && break
		set - $x
		if [ $1 -gt 1 ]; then
		users=`awk -F: '($3 == n) { print $1 }' n=$2 /etc/passwd | xargs`
		echo "Duplicate UID ($2): ${users}"
		fi
		done
}

function check_gid_dup(){
		cat /etc/group | cut -f3 -d":" | sort -n | uniq -c | while read x ; do
		[ -z "${x}" ] && break
		set - $x
		if [ $1 -gt 1 ]; then
		groups=`awk -F: '($3 == n) { print $1 }' n=$2 /etc/group | xargs`
		echo "Duplicate GID ($2): ${groups}"
		fi
		done
}

function check_group(){
		for i in $(cut -s -d: -f4 /etc/passwd | sort -u ); do
		grep -q -P "^.*?:[^:]*:$i:" /etc/group
		if [ $? -ne 0 ]; then
		echo "Group $i is referenced by /etc/passwd but does not exist in /etc/group"
		fi
		done
}

function check_rhost(){
		for dir in `cat /etc/passwd | egrep -v '(root|halt|sync|shutdown)' | awk -F: '($7 != "/usr/sbin/nologin") { print $6 }'`; do
		for file in $dir/.rhosts; do
		if [ ! -h "$file" -a -f "$file" ]; then
		echo ".rhosts file in $dir"
		fi
		done
		done
}

function check_usb(){
for DEV in /sys/block/sd*
do

        if readlink $DEV/device | grep -q usb
        then
                DEV=`basename $DEV`
                echo "$DEV is a USB device, info:"
                udevinfo --query=all --name $DEV
                if [ -d /sys/block/${DEV}/${DEV}1 ]
                then
                        echo "Has partitions " /sys/block/$DEV/$DEV[0-9]*
                else
                        echo "Has no partitions"
                fi
                echo
        fi
done
}

		motd="/etc/motd"
		ll="/etc/issue"
		rl="/etc/issue.net"
		ssh="/etc/ssh/sshd_config"
		
		write_header "Disabling unused filesystems"

		echo "install cramfs /bin/true" >> /etc/modprobe.d/CIS.conf
		echo "install freevxfs /bin/true" >> /etc/modprobe.d/CIS.conf
		echo "install jffs2 /bin/true" >> /etc/modprobe.d/CIS.conf
		echo "install hfs /bin/true" >> /etc/modprobe.d/CIS.conf
		echo "install hfsplus /bin/true" >> /etc/modprobe.d/CIS.conf
		echo "install squashfs /bin/true" >> /etc/modprobe.d/CIS.conf
		echo "install udf /bin/true" >> /etc/modprobe.d/CIS.conf
		echo "install vfat /bin/true" >> /etc/modprobe.d/CIS.conf
		
		write_header "Remounting filesystems"
		mount -o remount,nodev,nosuid /tmp
		mount -o remount,nodev,nosuid,noexec /var/tmp
		mount -o remount,nodev /home
		mount -o remount,nodev,nosuid,noexec /dev/shm
		
		write_header "Disabling Sticky Bit"
		df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type d -perm -0002 2>/dev/null | xargs chmod a+t
		
		write_header "Disabling autofs service"
		systemctl disable autofs
		
		write_header "Enabling cron service"
		systemctl enable cron
		
		write_header "Change Banner Setting"
		read -p "Enter Message of The day: " _motd
		touch "$motd"
		cp -pi "$motd" "$motd".bak$(date +"%Y%m%d_%H%M")
		> "$motd"
		echo "$_motd" >> "$motd"
		
		read -p "Enter Local Login Banner: " _ll
		cp -pi "$ll" "$ll".bak$(date +"%Y%m%d_%H%M")
		> "$ll"
		echo "$_ll" >> "$ll"
		
		read -p "Enter Remote Login Banner: " _rl
		cp -pi "$rl" "$rl".bak$(date +"%Y%m%d_%H%M")
		> "$rl"
		echo "$_rl" >> "$rl"
		
		cp -pi "$ssh" "$ssh".bak$(date +"%Y%m%d_%H%M")
		sed -i 's/.*Banner.*/Banner \/etc\/issue.net/' "/etc/ssh/sshd_config"
		
		write_header "Change Banner Permissions"
		chown root:root /etc/motd /etc/issue /etc/issue.net
		chmod 644 /etc/motd /etc/issue /etc/issue.net

		write_header "Change Cron File Permissions"
		chown root:root /etc/cron*
		chmod og-rwx /etc/cron*
		
		write_header "Change SSH file Permissions"	
		chown root:root /etc/ssh/sshd_config
		chmod og-rwx /etc/ssh/sshd_config
		service ssh restart
		
		write_header "Password Policy Setting"
		__maxage=$(grep ^PASS_MAX_DAYS /etc/login.defs | awk '{ print $2 }')
		__maxreuse=$(egrep '^password\s+sufficient\s+pam_unix.so' /etc/pam.d/common-password | awk 'BEGIN {FS="="};{print $2}')
		read -p "Enter Password Max Age: " _maxage
		sed -i.bak$(date +"%Y%m%d_%H%M") s/$__maxage/$_maxage/g /etc/login.defs
		read -p "Enter Password Max Reuse: " _maxreuse
		if [ -z "$__maxreuse" ]; then
			echo "password sufficient pam_unix.so remember="$_maxreuse >> /etc/pam.d/common-password
		else
			sed -i.bak$(date +"%Y%m%d_%H%M") s/$__maxreuse/$_maxreuse/g /etc/pam.d/common-password
		fi
		
		write_header "Password Policy Setting"
		sysfile="/etc/sysctl.conf"
		cp -pi "$sysfile" "$sysfile".bak$(date +"%Y%m%d_%H%M")
		sysctl -w net.ipv4.conf.all.send_redirects=0
		sysctl -w net.ipv4.conf.default.send_redirects=0 
		sysctl -w net.ipv4.conf.all.accept_redirects=0 
		sysctl -w net.ipv4.conf.default.accept_redirects=0 
		sysctl -w net.ipv4.conf.all.secure_redirects=0 
		sysctl -w net.ipv4.conf.default.secure_redirects=0 
		sysctl -w net.ipv4.route.flush=1
		
		write_header "Set default group for the root account"
		usermod -g 0 root
		
		write_header "Setting System File Permissions"
		
		chown root:root /etc/passwd
		chmod 644 /etc/passwd
			
		chown root:shadow /etc/shadow
		chmod o-rwx,g-wx /etc/shadow
				
		chown root:root /etc/group
		chmod 644 /etc/group
		
		chown root:shadow /etc/gshadow
		chmod o-rwx,g-rw /etc/gshadow
		
		chown root:root /etc/passwd-
		chmod 600 /etc/passwd-
		
		chown root:root /etc/shadow-
		chmod 600 /etc/shadow-
		
		chown root:root /etc/group-
		chmod 600 /etc/group-
		
		chown root:root /etc/gshadow-
		chmod 600 /etc/gshadow-
		
		write_header "User and Group Settings"
		check_forward
		check_netrc
		check_user_dup
		check_group_dup
		check_uid_dup
		check_gid_dup
		check_rhost
		check_usb

		
		
		
		
		
		
		