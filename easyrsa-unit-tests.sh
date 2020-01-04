#!/bin/sh
#
# Runs operational testing

set -e

usage ()
{
cat << __EOF__

	Tests run:
	* standard ca [penelope]
	* standard server + renew [s01]
	* standard server with SAN [s02]
	* standard serverClient [s03]
	* standard serverClient with SAN [s04]
	* standard client + renew [c01]
	* standard sign imported server [specter]
	* standard sign imported serverClient [heartbleed]
	* standard sign imported serverClient with SAN [VORACLE]
	* standard sign imported client [meltdown]
	* standard sign imported ca [maximilian]
	* subca to origin
	* subca sign server [specter]
	* subca sign serverClient [heartbleed]
	* subca sign serverClient with SAN [VORACLE]
	* subca sign client [meltdown]
	* delete all keys and revoke all certs on the fly
	* generate various CRLs

__EOF__
exit 0
}

init ()
{
	ROOT_DIR="$(pwd)"
	WORK_DIR="$ROOT_DIR/easyrsa3"
	TEMP_DIR="$WORK_DIR/unit-tests-temp"
	IGNORE_TEMP=${IGNORE_TEMP:-0}

	if [ -d "$TEMP_DIR" ] && [ $((IGNORE_TEMP)) -eq 0 ]
	then
		print "Aborted! Temporary directory exists: $TEMP_DIR"
		exit 1
	else
		[ $((IGNORE_TEMP)) -eq 1 ] && rm -rf "$TEMP_DIR" && warn "*** Deleted $TEMP_DIR ***"
	fi

	DIE="${DIE:-1}"
	S_ERRORS=0
	T_ERRORS=0
	DELAY=${DELAY:-1}
	VERBOSE="${VERBOSE:-0}"
	VVERBOSE="${VVERBOSE:-0}"
	SHOW_CERT="${SHOW_CERT:-0}"
	SAVE_PKI="${SAVE_PKI:-0}"
	ERSA_OUT="${ERSA_OUT:-0}"
	ERSA_BIN="./easyrsa"
	CUSTOM_VARS="${CUSTOM_VARS:-1}"
	UNSIGNED_PKI="${UNSIGNED_PKI:-1}"
	SYS_SSL_ENABLE="${SYS_SSL_ENABLE:-1}"
	SYS_SSL_LIBB="openssl"
	BROKEN_PKI="${BROKEN_PKI:-0}"
	CUSTOM_OPTS="${CUSTOM_OPTS:-0}"
	export DEPS_DIR="$ROOT_DIR/testdeps"
	export EASYRSA_CA_EXPIRE="${EASYRSA_CA_EXPIRE:-1}"
	export EASYRSA_CERT_EXPIRE="${EASYRSA_CERT_EXPIRE:-1}"
	export OPENSSL_ENABLE="${OPENSSL_ENABLE:-0}"
	export OPENSSL_BUILD="${OPENSSL_BUILD:-0}"
	export OPENSSL_VERSION="${OPENSSL_VERSION:-git}"
	export OSSL_LIBB="${OSSL_LIBB:-"$DEPS_DIR/openssl-dev/bin/openssl"}"
	export CUST_SSL_ENABLE="${CUST_SSL_ENABLE:-0}"
	export CUST_SSL_LIBB="${CUST_SSL_LIBB:-"$DEPS_DIR/cust-ssl-inst/bin/openssl"}"
	export LIBRESSL_ENABLE="${LIBRESSL_ENABLE:-0}"
	export LIBRESSL_BUILD="${LIBRESSL_BUILD:-0}"
	export LIBRESSL_VERSION="${LIBRESSL_VERSION:-2.8.3}"
	export LSSL_LIBB="${LSSL_LIBB:-"$DEPS_DIR/libressl/usr/local/bin/openssl"}"

	# Register cleanup on EXIT
	trap "cleanup" EXIT
	# When SIGHUP, SIGINT, SIGQUIT, SIGABRT and SIGTERM,
	# explicitly exit to signal EXIT (non-bash shells)
	trap "exit 1" 1
	trap "exit 2" 2
	trap "exit 3" 3
	trap "exit 6" 6
	trap "exit 14" 15

}

# Wrapper around printf - clobber print since it's not POSIX anyway
print() { printf "%s\n" "$1"; }

warn ()
{
	print "|| >> $1"
}

die ()
{
	warn "$0 FATAL ERROR! exit 1: ${1:-unknown error}"
	[ $((DIE)) -eq 1 ] && exit 1
	warn "Ignored"
	S_ERRORS=$((S_ERRORS + 1))
	T_ERRORS=$((T_ERRORS + 1))
	warn "$STAGE_NAME Errors: $S_ERRORS"
	return 0
}

newline ()
{
	[ $((VVERBOSE + SHOW_CERT_ONLY)) -eq 0 ] && return 0
	if [ "$1" = "1" ]
	then
		print "|| ============================================================================"
	else
		[ $((ERSA_OUT)) -ne 1 ] || print
	fi
}

notice ()
{
	[ $((VERBOSE)) -eq 1 ] || return 0
	printf "%s\n" "$1"
}

verbose ()
{
	[ $((VERBOSE)) -eq 1 ] || return 0
	MSG="$(print "$1" | sed -e s/^--.*0\ //g -e s\`/.*/\`\`g -e s/\ nopass//g)"
	printf "%s" "$MSG .. "
}

completed ()
{
	[ $((VERBOSE)) -eq 1 ] || return 0
	print "ok"
}

vverbose ()
{
	[ $((VVERBOSE)) -eq 1 ] || return 0
	MSG="$(print "$1" | sed -e s/^--.*0\ //g -e s\`/.*/\`\`g -e s/\ nopass//g)"
	print "|| :: $MSG"
}

vdisabled ()
{
	[ $((VVERBOSE)) -eq 1 ] || return 0
	print "|| -- DISABLED OPTION: $1"
}

vcompleted ()
{
	[ $((VVERBOSE)) -eq 1 ] || return 0
	MSG="$(print "$1" | sed -e s/^--.*0\ //g -e s\`/.*/\`\`g -e s/\ nopass//g)"
	print "|| ++ $MSG .. ok"
}

vvverbose ()
{
	[ $((VVERBOSE)) -eq 1 ] || return 0
	print "|| :: $1"
}

verb_on ()
{
	VERBOSE="$SAVE_VERB"
	VVERBOSE="$SAVE_VVERB"
	ERSA_OUT="$SAVE_EOUT"
}

verb_off ()
{
	SAVE_VERB="$VERBOSE"
	VERBOSE=0
	SAVE_VVERB="$VVERBOSE"
	VVERBOSE=0
	SAVE_EOUT="$ERSA_OUT"
	ERSA_OUT=0
}

version ()
{
	newline 1
	ERSA_UTEST_VERSION="1.2"
	notice "easyrsa-unit-tests manual version: $ERSA_UTEST_VERSION"
	vverbose "easyrsa-unit-tests manual version: $ERSA_UTEST_VERSION"

	# Windows requirement
	# shellcheck disable=SC2230
	if which curl >/dev/null 2>&1; then
		ERSA_UTEST_CURL_OPTS='-H "User-Agent: tincantech"'
		[ $((VVERBOSE)) -eq 1 ] && ERSA_UTEST_CURL_VERB='-v'
		ERSA_UTEST_CURL_TARGET="${ERSA_UTEST_CURL_TARGET:-Openvpn/easyrsa-unit-tests}"
		ERSA_UTEST_GIT_WEB_URL="https://github.com/$ERSA_UTEST_CURL_TARGET/commit"
		ERSA_UTEST_GIT_API_URL="https://api.github.com/repos/$ERSA_UTEST_CURL_TARGET/git/refs/heads/master"
		ERSA_UTEST_GIT_HEAD_CURL="$(curl -s "$ERSA_UTEST_CURL_VERB" "$ERSA_UTEST_CURL_OPTS" "$ERSA_UTEST_GIT_API_URL")"
		ERSA_UTEST_GIT_HEAD_SHA="$(printf "%s\n" "$ERSA_UTEST_GIT_HEAD_CURL" \
			| sed -e 's/\"//g' -e 's/\,//g' | grep 'sha: ' | awk '{print $2}')"
		ERSA_UTEST_GIT_HEAD_URL="$ERSA_UTEST_GIT_WEB_URL/$ERSA_UTEST_GIT_HEAD_SHA"
		notice "easyrsa-unit-tests git commit URL: $ERSA_UTEST_GIT_HEAD_URL"
		vverbose "easyrsa-unit-tests git commit URL: $ERSA_UTEST_GIT_HEAD_URL"
	fi
}

wait_sec ()
{
	verbose "Wait"
	vverbose "Wait"
	( sleep "$DELAY" 2>/dev/null ) || \
	{ ( ping -n 1 127.0.0.1 >/dev/null 2>&1 ) && ping -n "$DELAY" 127.0.0.1 >/dev/null 2>&1; }
	completed
}

setup ()
{
	newline 1
	verbose "Setup"
	vverbose "Setup"

	cd "$WORK_DIR" || die "cd $WORK_DIR"
	vvverbose "Working dir: $WORK_DIR"

	destroy_data

	STEP_NAME="vars"
	if [ $((CUSTOM_VARS)) -eq 1 ]
	then
		[ -f "$WORK_DIR/vars.example" ] || dir "File missing: $WORK_DIR/vars.example"
		cp "$WORK_DIR/vars.example" "$WORK_DIR/vars" || die "cp vars.example vars"
		create_vars >> "$WORK_DIR/vars" || die "create_vars"
		vcompleted "$STEP_NAME"
	else
		vdisabled "$STEP_NAME"
	fi

	STEP_NAME="Custom opts"
	if [ $((CUSTOM_OPTS)) -eq 1 ]
	then
		# https://github.com/OpenVPN/easy-rsa/pull/278
		export CUSTOM_EASYRSA_REQ_ORG2="Custom Option"
		export LIBRESSL_ENABLE=0
		YACF="$WORK_DIR/openssl-easyrsa.cnf"
		[ -f "$YACF" ] || die "File missing: $YACF"
		[ -f "$YACF.orig" ] && die "Aborted! Temporary file exists: $YACF.orig"
		mv "$YACF" "$YACF.orig"
		create_custom_opts > "$YACF"
		vcompleted "$STEP_NAME"
	fi

	STAGE_NAME="Sample requests"
	if [ $((UNSIGNED_PKI)) -eq 1 ] && [ $((SYS_SSL_ENABLE + CUST_SSL_ENABLE + OPENSSL_ENABLE + LIBRESSL_ENABLE)) -ne 0 ]
	then
		verb_off
		NEW_PKI="pki-req"
		create_req || die "$STAGE_NAME create_req"
		mv "$TEMP_DIR/$NEW_PKI" "$TEMP_DIR/pki-bkp" || die "$STAGE_NAME mv"
		verb_on
		vcompleted "$STAGE_NAME"
	else
		vdisabled "$STAGE_NAME"
	fi

	completed
}

destroy_data ()
{
	if [ $((SAVE_PKI)) -ne 1 ]
	then
		rm -rf "$TEMP_DIR"
		rm -f "$WORK_DIR/vars"
		if [ -f "$YACF.orig" ]; then mv -f "$YACF.orig" "$YACF"; fi
	else
		warn "*** PKI and vars have not been deleted ***"
	fi
}

secure_key ()
{
	rm -f "$EASYRSA_PKI/private/$REQ_name.key"
}

cleanup ()
{
	destroy_data
	cd ..
}

create_vars ()
{
	print ' set_var EASYRSA_DN "org"'
	print '# Unsupported characters:'
	print '# `'
	print '# $'
	print '# "'
	print "# '"
	print '# #'
	print '# & (Win)'
	print ' set_var EASYRSA_REQ_COUNTRY   "00"'
	print ' set_var EASYRSA_REQ_PROVINCE  "test"'
	print ' set_var EASYRSA_REQ_CITY      "TEST ,./<>  ?;:@~  []!%^  *()-=  _+| (23) TEST"'
	print ' set_var EASYRSA_REQ_ORG       "example.org"'
	print ' set_var EASYRSA_REQ_EMAIL     "me@example.net"'
	print ' set_var EASYRSA_REQ_OU        "TEST esc \{ \} \£ \¬ (4) TEST"'
}

create_custom_opts ()
{
	head -n 91 "$YACF.orig"
	print "1.organizationName		= Second Organization Name"
	print "1.organizationName_default 	= \$ENV::CUSTOM_EASYRSA_REQ_ORG2"
	tail -n +91 "$YACF.orig"
}

create_req ()
{
	export EASYRSA_PKI="$TEMP_DIR/$NEW_PKI"

	STEP_NAME="init-pki"
	action

	export EASYRSA_BATCH=1
	export EASYRSA_REQ_CN="maximilian"
	STEP_NAME="build-ca nopass subca"
	action
	[ -f "$EASYRSA_PKI/reqs/ca.req" ] && mv "$EASYRSA_PKI/reqs/ca.req" "$EASYRSA_PKI/reqs/maximilian.req"

	export EASYRSA_REQ_CN="specter"
	STEP_NAME="gen-req $EASYRSA_REQ_CN nopass"
	action
	secure_key

	export EASYRSA_REQ_CN="meltdown"
	STEP_NAME="gen-req $EASYRSA_REQ_CN nopass"
	action
	secure_key

	export EASYRSA_REQ_CN="heartbleed"
	STEP_NAME="gen-req $EASYRSA_REQ_CN nopass"
	action
	secure_key

	export EASYRSA_REQ_CN="VORACLE"
	STEP_NAME="--subject-alt-name='DNS:www.example.org,IP:0.0.0.0' gen-req $EASYRSA_REQ_CN nopass"
	action
	secure_key

	STEP_NAME="show-req $EASYRSA_REQ_CN nopass"
	action

	unset EASYRSA_REQ_CN
	unset EASYRSA_BATCH
}

restore_req ()
{
	STEP_NAME="Restore sample requests"
	rm -rf "$TEMP_DIR/pki-req"
	cp -Rf "$TEMP_DIR/pki-bkp" "$TEMP_DIR/pki-req" >/dev/null 2>&1 || die "$STEP_NAME"
	vcompleted "$STEP_NAME"
}

move_ca ()
{
	newline 1
	STEP_NAME="Send ca to origin"
	verbose "$STEP_NAME"
	mv "$EASYRSA_PKI/issued/$REQ_name.crt" "$TEMP_DIR/pki-req/ca.crt" >/dev/null 2>&1 || die "$STEP_NAME"
	completed
	vcompleted "$STEP_NAME"

	STEP_NAME="Change PKI to origin"
	verbose "$STEP_NAME"
	export EASYRSA_PKI="$TEMP_DIR/pki-req"
	completed
	vcompleted "$STEP_NAME"
}

action ()
{
	verbose "$STEP_NAME"
	vverbose "$STEP_NAME"
	# Required to support $PATH with spaces (import-req)
	ACT_FILE_NAME="$1"
	ACT_OPTS="$2"
	if [ $((ERSA_OUT + SHOW_CERT_ONLY)) -eq 0 ]
	then
		newline
		# shellcheck disable=SC2086
		"$ERSA_BIN" $STEP_NAME "$ACT_FILE_NAME" "$ACT_OPTS" >/dev/null 2>&1 || die "$STEP_NAME"
	else
		# shellcheck disable=SC2086
		"$ERSA_BIN" $STEP_NAME "$ACT_FILE_NAME" "$ACT_OPTS" || die "$STEP_NAME"
	fi
	completed
}

init_pki ()
{
	STEP_NAME="init-pki"
	action
}

build_ca ()
{
	STEP_NAME="build-ca nopass"
	export EASYRSA_REQ_CN="penelope"
	action
	unset EASYRSA_REQ_CN
}

show_ca ()
{
	STEP_NAME="show-ca"
	[ $((SHOW_CERT)) -eq 1 ] && SHOW_CERT_ONLY=1
	action
	newline
	unset SHOW_CERT_ONLY
}

build_full ()
{
	newline 1
	STEP_NAME="build-$REQ_type-full $REQ_name nopass"
	action
	secure_key
}

build_san_full ()
{
	newline 1
	STEP_NAME="--subject-alt-name=DNS:www.example.org,IP:0.0.0.0 build-$REQ_type-full $REQ_name nopass"
	action
	secure_key
}

import_req ()
{
	REQ_file="$TEMP_DIR/pki-req/reqs/$REQ_name.req"

	# Note: easyrsa still appears to work in batch mode for this action ?
	export EASYRSA_BATCH=0
	newline 1
	STEP_NAME="import-req"
	action "$REQ_file" "$REQ_name"
	export EASYRSA_BATCH=1
}

show_req ()
{
	STEP_NAME="show-req $REQ_name"
	[ $((SHOW_CERT)) -eq 1 ] && SHOW_CERT_ONLY=1
	action
	newline
	unset SHOW_CERT_ONLY
}

sign_req ()
{
	newline 1
	STEP_NAME="sign-req $REQ_type $REQ_name nopass"
	action
}

show_cert ()
{
	STEP_NAME="show-cert $REQ_name"
	[ $((SHOW_CERT)) -eq 1 ] && SHOW_CERT_ONLY=1
	action
	newline
	unset SHOW_CERT_ONLY
}

renew_cert ()
{
	wait_sec
	newline 1
	STEP_NAME="renew $REQ_name nopass"
	action
}

revoke_cert ()
{
	STEP_NAME="revoke $REQ_name"
	CAT_THIS="$EASYRSA_PKI/index.txt"
	verb_off
	action
	verb_on
}

gen_crl ()
{
	newline 1
	STEP_NAME="gen-crl"
	action
	CAT_THIS="$EASYRSA_PKI/crl.pem"
	cat_file
}

cat_file ()
{
	[ $((ERSA_OUT)) -eq 1 ] || return 0
	newline
	vverbose "cat $CAT_THIS"
	newline
	[ -f "$CAT_THIS" ] || die "cat $CAT_THIS"
	[ $((VVERBOSE)) -eq 1 ] && [ -f "$CAT_THIS" ] && cat "$CAT_THIS"
	newline
}

create_pki ()
{
	newline 1
	vverbose "$STAGE_NAME"
	vvverbose "EASYRSA_OPENSSL: $EASYRSA_OPENSSL"
	notice "$($EASYRSA_OPENSSL version)"
		#  2> /dev/null
	vverbose "$($EASYRSA_OPENSSL version 2> /dev/null)"

	restore_req

	export EASYRSA_PKI="$TEMP_DIR/$NEW_PKI"
	if [ "$EASYRSA_PKI" = "$TEMP_DIR/pki-empty" ] || [ "$EASYRSA_PKI" = "$TEMP_DIR/pki-error" ]
	then
		vverbose "OMITTING init-pki"
	else
		init_pki
	fi
	export EASYRSA_BATCH=1

	build_ca
	show_ca

	REQ_type="server"
	REQ_name="s01"
	build_full
	show_cert
	renew_cert
	show_cert
	revoke_cert

	REQ_type="server"
	REQ_name="s02"
	build_san_full
	show_cert
	renew_cert
	show_cert
	revoke_cert

	REQ_type="serverClient"
	REQ_name="s03"
	build_full
	show_cert
	renew_cert
	show_cert
	revoke_cert

	REQ_type="serverClient"
	REQ_name="s04"
	build_san_full
	show_cert
	renew_cert
	show_cert
	revoke_cert

	REQ_type="client"
	REQ_name="c01"
	build_full
	show_cert
	renew_cert
	show_cert
	revoke_cert

	REQ_type="server"
	REQ_name="specter"
	import_req
	sign_req
	show_cert
	revoke_cert

	REQ_type="serverClient"
	REQ_name="heartbleed"
	import_req
	sign_req
	show_cert
	revoke_cert

	REQ_type="serverClient"
	REQ_name="VORACLE"
	import_req
	sign_req
	show_cert
	revoke_cert

	REQ_type="client"
	REQ_name="meltdown"
	import_req
	sign_req
	show_cert
	revoke_cert

	gen_crl

	REQ_type="ca"
	REQ_name="maximilian"
	import_req
	sign_req

	# goto origin
	move_ca
	show_ca

	REQ_type="server"
	REQ_name="specter"
	sign_req
	show_cert
	revoke_cert

	REQ_type="serverClient"
	REQ_name="heartbleed"
	sign_req
	show_cert
	revoke_cert

	REQ_type="serverClient"
	REQ_name="VORACLE"
	sign_req
	show_cert
	revoke_cert

	REQ_type="client"
	REQ_name="meltdown"
	sign_req
	show_cert
	revoke_cert

	gen_crl

	unset EASYRSA_BATCH
	unset EASYRSA_PKI

	newline 1
	vcompleted "$STAGE_NAME (Errors: $S_ERRORS)"
	S_ERRORS=0
	newline 1
}


######################################

	for i in $1
	do
		case $i in
		-u|-h|--help)	usage ;;
		-v)		VERBOSE=1 ;;
		-vv)		VVERBOSE=1; ERSA_OUT="${ERSA_OUT:-1}" ;;
		-b)		DIE=0; BROKEN_PKI=1; SYS_SSL_ENABLE="${SYS_SSL_ENABLE:-0}";
				VVERBOSE="${VVERBOSE:-1}"; ERSA_OUT="${ERSA_OUT:-1}" ;;
		-f)		DIE=0; CUST_SSL_ENABLE=1; OPENSSL_ENABLE=1; LIBRESSL_ENABLE=1;
				VVERBOSE="${VVERBOSE:-1}"; ERSA_OUT="${ERSA_OUT:-1}" ;;
		*)		print "Unknown option: $i"; exit 1 ;;
		esac
	done

	init
	version

	#[ -f "$DEPS_DIR/custom-ssl.sh" ] || export CUST_SSL_ENABLE=0
	#[ $((CUST_SSL_ENABLE)) -eq 1 ] && "$DEPS_DIR/custom-ssl.sh"

	#[ -f "$DEPS_DIR/openssl.sh" ] || export OPENSSL_ENABLE=0
	#[ $((OPENSSL_ENABLE)) -eq 1 ] && "$DEPS_DIR/openssl.sh"

	#[ -f "$DEPS_DIR/libressl.sh" ] || export LIBRESSL_ENABLE=0
	#[ $((LIBRESSL_ENABLE)) -eq 1 ] && "$DEPS_DIR/libressl.sh"

	setup

	STAGE_NAME="System ssl"
	if [ $((SYS_SSL_ENABLE)) -eq 1 ]
	then
		export EASYRSA_OPENSSL="$SYS_SSL_LIBB"
		NEW_PKI="pki-sys-ssl"
		create_pki
		unset EASYRSA_OPENSSL
	else
		vdisabled "$STAGE_NAME"
	fi

	STAGE_NAME="Custom ssl"
	if [ $((CUST_SSL_ENABLE)) -eq 1 ]
	then
		[ -f "$CUST_SSL_LIBB" ] || die "$0: missing custom ssl: $CUST_SSL_LIBB"
		export EASYRSA_OPENSSL="$CUST_SSL_LIBB"
		NEW_PKI="pki-custom-ssl"
		create_pki
		unset EASYRSA_OPENSSL
	else
		vdisabled "$STAGE_NAME"
	fi

	STAGE_NAME="Openssl"
	if [ $((OPENSSL_ENABLE)) -eq 1 ]
	then
		[ -f "$OSSL_LIBB" ] || die "$0: missing openssl: $OSSL_LIBB"
		export EASYRSA_OPENSSL="$OSSL_LIBB"
		NEW_PKI="pki-openssl"
		create_pki
		unset EASYRSA_OPENSSL
	else
		vdisabled "$STAGE_NAME"
	fi

	STAGE_NAME="Libressl"
	if [ $((LIBRESSL_ENABLE)) -eq 1 ]
	then
		[ -f "$LSSL_LIBB" ] || die "$0: missing libressl: $LSSL_LIBB"
		export EASYRSA_OPENSSL="$LSSL_LIBB"
		NEW_PKI="pki-libressl"
		create_pki
		unset EASYRSA_OPENSSL
	else
		vdisabled "$STAGE_NAME"
	fi

	STAGE_NAME="Common errors (Does *not* die on errors)"
	if [ $((BROKEN_PKI)) -eq 1 ]
	then
		NEW_PKI="pki-empty"
		#restore_req
		DIE=0 create_pki
	else
		vdisabled "$STAGE_NAME"
	fi

	cleanup

notice "Completed $(date) (Total errors: $T_ERRORS)"
vcompleted "Completed $(date) (Total errors: $T_ERRORS)"

exit 0
