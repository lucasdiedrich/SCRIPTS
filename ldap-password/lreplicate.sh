#!/bin/bash

#
# SCRIPT FOR LDAP PASSWORD REPLICATION - FreeIPA -> OpenLDAP
#
# This script should be runned on Freeipa Server (Local Server) and 
# must be configured above. Basically it gets all users password encoded, decode it,
# create an LDIF file, and sent it to the remote server (OpenLDAP).
#
# Usage: lreplicate.sh "remote admin password"
#

#
# GLOBAL VARIABLES
#

# Password Attribute on both servers
v_lp_f="userPassword"
v_skel_file="./pass.skel"
v_timestamp_file="./last.tmp"
v_tmp_folder="./tmp/"
v_old_timestamp=""
# TEMP FILE CONTAINING CHANGED USER ON TIME INTERVAL
v_tmp_file="${RANDOM}.tmp" 
# MILISECONDS
v_time_interval=30000

#
# LOCAL SERVER DATA (FreeIPA)
# User Base DN
v_lp_l_bs="cn=users,cn=accounts,dc=unila"
v_lp_l_dn="admin"
#
# REMOTE SERVER DATA (OpenLDAP)
# Hostname
v_lp_r_dt="FOO.INTERNALDOMAIN.DOMAIN"
# Top Base DN
v_lp_r_bs="dc=FOO,dc=bar" 
# Admin
v_lp_r_dn="cn=admin,$v_lp_r_bs"
# Admin Password - Should be passed as parameter
v_lp_r_ps="${1}"

readonly SCRIPT_NAME=$(basename $0)
set -m # Enable Job Control
trap "wait" TERM EXIT

#
# Main
#
Principal(){
	echo "Starting replication..."
	
	kinit $v_lp_l_dn

	if [[ $? -eq 0 ]]; then
		tmpfiles		
		querie
		rm $v_tmp_file
	else
		err "Failed to kinit $v_lp_l_dn"
		exit 1
	fi
	
	echo "Replication finished."
}

#
# Search on local LDAP how many user should be synced
#
querie(){
	ldapsearch -Y GSSAPI -xLLL -b "$v_lp_l_bs" "krbLastPwdChange>=${v_old_timestamp}" $v_lp_f | perl -p00e 's/\r?\n //g' > $v_tmp_file

	v_num_enc=`cat $v_tmp_file | grep uid | wc -l`

	if [[ "$v_num_enc" -ne "0" ]]; then 
		log "${v_num_enc} candiates to be synced."
		verify
	fi
}

#
# Verifies if the user exists on the remote ldap, if it does, sync.
#
verify(){
	IFS=' ' read -a array <<< `cat $v_tmp_file`
	for i in "${!array[@]}"
	do
		if [[ $(($i%2)) -ne '0' && "${array[i]}" == *"uid"* ]]; then		
			l_uid="$( cut -d ',' -f 1 <<< "${array[i]}" )"
			l_decoded_password=`get_decoded_password ${array[i + 2]}` #User Pass

			v_shouldsync=`shouldsync $l_uid $l_decoded_password`

			if [ "$v_shouldsync" == "true" ]; then
				replicate $l_uid
			fi
		fi
	done
}

shouldsync(){
	result_querie=`ldapsearch -xLLL -h "$v_lp_r_dt" -D "$v_lp_r_dn" -w $v_lp_r_ps -b "$v_lp_r_bs" "($1)" userPassword | perl -p00e 's/\r?\n //g'`
	v_return="false"

	if [[ "$result_querie" == "" ]]; then
		err "User $1 not find on remote server, not syncing."
	else
		IFS=' ' read -a array <<< "$result_querie"
		for i in "${!array[@]}"
		do
			if [[ $(($i%2)) -ne '0' && "${array[i]}" == *"uid"* ]]; then	
				r_uid="${array[i]}" 
				r_decoded_password=`perl -e "use MIME::Base64; print(decode_base64('${result_querie##*::}'));"` 

				if [[ "${2}" != "${r_decoded_password}" ]]; then
					create_mod_file ${1} ${2} ${r_uid}
					v_return="true"
				else
					log "Password from user ${1} its the same as local server, not syncing." 
				fi
			fi
		done
	fi

	echo $v_return
}

#
# Create temporary modification file for user
#
create_mod_file(){
	v_user_pass="${2}"
	v_lm_file=`get_lm_file ${1}` 

	# Uses \# as delimiter	
	cp ${v_skel_file} ${v_lm_file} 
	sed -i -e "s/%USERDN/${3}/g" ${v_lm_file}
	sed -i -e "s#%PASSWORD#${v_user_pass}#g" ${v_lm_file}
}

#
# Replicates the password for remote server
#
replicate(){
	v_lm_file=`get_lm_file ${1}`
	ldapmodify -h $v_lp_r_dt -D $v_lp_r_dn -w $v_lp_r_ps -f $v_lm_file
	rm $v_lm_file
	log "User ${1} synced with remote server."
}

#
# Create and verifies local timestamp and stuff
#
tmpfiles(){
	if [ -f $v_timestamp_file ]; then
		v_old_timestamp=`cat $v_timestamp_file`
	fi
	export_timestamp
	if [ ! -d $v_tmp_folder ]; then
		mkdir $v_tmp_folder
	fi
}

#
# Some utils methods
#
get_lm_file(){
	echo "${v_tmp_folder}${1}.tmp"
}
get_decoded_password(){
	v_user_pass=`perl -e "use MIME::Base64; print(decode_base64('${1}'));"` 
	echo "$v_user_pass"
}

# Export time stamp
export_timestamp(){
	echo `date --utc +%Y%m%d%H%M%SZ` > $v_timestamp_file
}

log() {
  echo "$@"
  logger -p user.notice -t $SCRIPT_NAME "$@"
}

err() {
  echo "$@" >&2
  logger -p user.error -t $SCRIPT_NAME "$@"
}

Principal
