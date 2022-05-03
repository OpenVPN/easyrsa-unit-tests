#!/bin/sh
#
# Runs operational testing

# Easy-RSA 3 -- A Shell-based CA Utility
#
# Copyright (C) 2020 by the Open-Source OpenVPN development community.
# A full list of contributors can be found in the ChangeLog.
#
# This code released under version 2 of the GNU GPL; see COPYING and the
# Licensing/ directory of this project for full licensing details.
#
# easyrsa-unit-tests.sh (2020)

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
success 0
}

init ()
{
	DIE="${DIE:-1}"
	ROOT_DIR="$PWD"
	WORK_DIR="${ROOT_DIR}/easyrsa3"
	TEMP_DIR="${WORK_DIR}/unit tests"
	S_ERRORS=0
	T_ERRORS=0
	WAIT_DELAY="${WAIT_DELAY:-0}"
	LOG_INDENT_1=" - "
	LOG_INDENT_2="    - "

	if [ -d "$TEMP_DIR" ]; then
		if [ -z "$IGNORE_TEMP" ]; then
			SAVE_PKI=1
			die "Aborted! Temporary directory exists: $TEMP_DIR"
		fi
		rm -rf "$TEMP_DIR" || {
			SAVE_PKI=1
			die "Failed to clean Temporary directory: $TEMP_DIR"
			}
		mkdir "$TEMP_DIR" || {
			die "Failed to create Temporary directory: $TEMP_DIR"
			}
	fi

	SHOW_CERT="${SHOW_CERT:-0}"
	#SAVE_PKI="${SAVE_PKI:-0}"
	ERSA_OUT="${ERSA_OUT:-0}"
	ACT_OUT="$TEMP_DIR/.act.out"
	ACT_ERR="$TEMP_DIR/.act.err"
	if [ -f "$WORK_DIR/easyrsa" ]; then ERSA_BIN="$WORK_DIR/easyrsa"; else ERSA_BIN="easyrsa"; fi

	TEST_ALGOS="rsa ec ed"
	[ "$LIBRESSL_LIMIT" ] && TEST_ALGOS="rsa ec"

	CUSTOM_VARS="${CUSTOM_VARS:-1}"
	UNSIGNED_PKI="${UNSIGNED_PKI:-1}"
	SYS_SSL_ENABLE="${SYS_SSL_ENABLE:-1}"
	SYS_SSL_LIBB="${SYS_SSL_LIBB:-openssl}"
	BROKEN_PKI="${BROKEN_PKI:-0}"
	CUSTOM_OPTS="${CUSTOM_OPTS:-0}"
	EASYRSA_SP="${EASYRSA_SP:-private}"
	ERSA_UTEST_CURL_TARGET="${ERSA_UTEST_CURL_TARGET:-default}"
	export DEPS_DIR="$ROOT_DIR/testdeps"
	export EASYRSA_KEY_SIZE="${EASYRSA_KEY_SIZE:-1024}"
	export EASYRSA_CA_EXPIRE="${EASYRSA_CA_EXPIRE:-1}"
	export EASYRSA_CERT_EXPIRE="${EASYRSA_CERT_EXPIRE:-1}"
	export EASYRSA_CERT_RENEW="${EASYRSA_CERT_RENEW:-10000}"
	export EASYRSA_FIX_OFFSET="${EASYRSA_FIX_OFFSET:-163}"

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
}

success ()
{
	vverbose "EXIT: exit 0"
	exit 0
}

failed ()
{
	ERROR_COUNT="$((ERROR_COUNT+1))"
	ERROR_CODE="$1"
	cleanup || print "cleanup failed!"
	print
	print "ERROR: exit $ERROR_CODE"
	exit "$ERROR_CODE"
}



# Wrapper around printf - clobber print since it's not POSIX anyway
print() { printf "%s\n" "$1"; }

warn ()
{
	[ "$SILENCE_WARN" ] && return
	print "$1"
}

die ()
{
	print
	print "FATAL ERROR! Command failed -> ${1:-unknown error}"
	[ -f "$ACT_OUT" ] && print && print "EasyRSA log:" && cat "$ACT_OUT"
	[ -f "$ACT_ERR" ] && print && print "Error message:" && cat "$ACT_ERR"
	[ $((DIE)) -eq 1 ] && failed 1
	warn "Ignored"
	S_ERRORS=$((S_ERRORS + 1))
	T_ERRORS=$((T_ERRORS + 1))
	warn "$STAGE_NAME Errors: $S_ERRORS"
	return 0
}

newline ()
{
	[ $((VVERBOSE + SHOW_CERT_ONLY)) -eq 0 ] && return 0
	if [ "$1" = "3" ]; then
		print "|| ###########################################################################"
	elif [ "$1" = "2" ]; then
		print "|| ==========================================================================="
	elif [ "$1" = "1" ]; then
		print "|| - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -"
	else
		[ $((ERSA_OUT)) -ne 1 ] || print "||"
	fi
}

notice ()
{
	[ $((VERBOSE)) -eq 1 ] || return 0
	print "$1"
}

# shellcheck disable=SC2016
filter_msg ()
{
	MSG="$(	print "$1" | sed \
		-e 's/ $//' \
		-e 's/--subject-alt-name.*,//' \
		-e 's/IP:[0-9]\.[0-9]\.[0-9]\.[0-9]\ //' \
		-e 's`/.*/``' \
		-e 's/ nopass//' \
		-e 's/ inline//' \
		)"
}

# verbose and completed work together
verbose ()
{
	[ $((VERBOSE)) -eq 1 ] || return 0
	filter_msg "$1"
	printf "%s" "$LOG_INDENT" "$MSG .. "
}

completed ()
{
	[ $((VERBOSE)) -eq 1 ] || return 0
	print "ok"
}

vverbose ()
{
	[ $((VVERBOSE)) -eq 1 ] || return 0
	filter_msg "$1"
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
	filter_msg "$1"
	print "|| ++ $MSG .. ok"
}

vvverbose ()
{
	[ $((VVERBOSE)) -eq 1 ] || return 0
	print "|| :: $1"
}

verb_on ()
{
	unset SILENCE_WARN
	VERBOSE="$SAVE_VERB"
	VVERBOSE="$SAVE_VVERB"
	ERSA_OUT="$SAVE_EOUT"
}

verb_off ()
{
	SILENCE_WARN=1
	SAVE_VERB="$VERBOSE"
	unset VERBOSE
	SAVE_VVERB="$VVERBOSE"
	unset VVERBOSE
	SAVE_EOUT="$ERSA_OUT"
	unset ERSA_OUT
}

easyrsa_unit_test_version ()
{
	newline 3

	print "easyrsa-unit-tests.sh version: $ERSA_UTEST_VERSION"
	print "easyrsa-unit-tests.sh source:  $ERSA_UTEST_CURL_TARGET"
	print "easyrsa source:                $ERSA_BIN"

	#print "SYS_SSL_LIBB: $SYS_SSL_LIBB"
	#SYS_LIB_VERSION="$("$SYS_SSL_LIBB" version)"
	#print "SYS_SSL_LIBB version: $SYS_LIB_VERSION"

	#print "EASYRSA_OPENSSL: $EASYRSA_OPENSSL"
	#ERSA_LIB_VERSION="$("$EASYRSA_OPENSSL" version)"
	#print "EASYRSA_OPENSSL version: $ERSA_LIB_VERSION"

	ssl_version="$("$EASYRSA_OPENSSL" version)"
	printf '%s\n' "" "* EASYRSA_OPENSSL:" \
		"  $EASYRSA_OPENSSL (env)" "  ${ssl_version}"
}

wait_sec ()
{
	[ $((WAIT_DELAY)) -eq 0 ] && return 0
	verbose "Wait"
	vverbose "Wait"
	{ sleep "$WAIT_DELAY" 2>/dev/null; } || echo "* Windows is slow enough *"
	completed
}

setup ()
{
	newline 3
	verbose "Setup"
	vverbose "Setup"

	# dir: ./easyrsa3
	mkdir -p "$WORK_DIR" ||  die "mkdir $WORK_DIR"
	cd "$WORK_DIR" || die "cd $WORK_DIR"
	vvverbose "Working dir: $WORK_DIR"

	# dir: ./easyrsa3/unit test
	mkdir -p "$TEMP_DIR" || die "Cannot mkdir: -p $TEMP_DIR"
	vvverbose "Temp dir: $TEMP_DIR"

	STEP_NAME="vars"
	if [ $((CUSTOM_VARS)) -eq 1 ]
	then
		# TODO: MUST Find a usable vars.example because of the live code in vars
		# FOUND_VARS=`where is vars.example`
		#[ -f "$FOUND_VARS/vars.example" ] || dir "File missing: $FOUND_VARS/vars.example"
		#cp "$FOUND_VARS/vars.example" "$WORK_DIR/vars" || die "cp vars.example vars"
		create_vars > "$TEMP_DIR/vars.utest" || die "create_vars"
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
		[ "$VVERBOSE" ] || verb_off
		for i in $TEST_ALGOS
		do
			export EASYRSA_ALGO="$i"
			NEW_PKI="pki-req-$EASYRSA_ALGO"
			[ "$EASYRSA_ALGO" = "ed" ] && export EASYRSA_CURVE="ed25519"
			create_req
			mv "$TEMP_DIR/$NEW_PKI" "$TEMP_DIR/pki-bkp-$EASYRSA_ALGO" || \
				die "$STAGE_NAME mv $TEMP_DIR/$NEW_PKI"

			unset EASYRSA_ALGO EASYRSA_CURVE
			unset NEW_PKI
		done
		[ "$VVERBOSE" ] || verb_on
		vcompleted "$STAGE_NAME"
	else
		vdisabled "$STAGE_NAME"
	fi

	completed
}

secure_key ()
{
	rm -f "$EASYRSA_PKI/$EASYRSA_SP/$REQ_name.key"
	rm -f "$EASYRSA_PKI/$EASYRSA_SP/$EASYRSA_REQ_CN.key"
	[ $((LIVE_PKI)) -eq 1 ] || rm -f "$EASYRSA_PKI/$EASYRSA_SP/ca.key"
	rm -f "$EASYRSA_PKI/$REQ_name.creds"
}

cleanup ()
{
	print
	print "Unit-test: cleanup"
	if [ -z "$SAVE_PKI" ]; then
		print "Remove temp dir: $TEMP_DIR"
		rm -rf "$TEMP_DIR"
	else
		print "Saving temp dir: SAVE_PKI=$SAVE_PKI"
	fi
	cd ..
}

create_vars ()
{
	print ' set_var EASYRSA_FIX_OFFSET 163'
	print ' set_var EASYRSA_DN "org"'
	print '# Unsupported characters:'
	print '# `'
	print '# $'
	print '# "'
	print '# single-quote'
	print '# #'
	print '# & (Win)'
	print ' set_var EASYRSA_REQ_COUNTRY   "00"'
	print ' set_var EASYRSA_REQ_PROVINCE  "test"'
	print ' set_var EASYRSA_REQ_CITY      "TEST ,./<>  ?;:@~  []!%^  *()-=  _+| (23) TEST"'
	print ' set_var EASYRSA_REQ_ORG       "example.org Skåne Eslöv"'
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

	init_pki
	cp "$TEMP_DIR/vars.utest" "$EASYRSA_PKI/vars" || die "New vars"

	export EASYRSA_BATCH=1
	export EASYRSA_REQ_CN="maximilian"
	LIVE_PKI=1
	STEP_NAME="build-ca nopass subca"
	action
	[ -f "$EASYRSA_PKI/reqs/ca.req" ] && mv "$EASYRSA_PKI/reqs/ca.req" "$EASYRSA_PKI/reqs/maximilian.req"

	export EASYRSA_REQ_CN="specter"
	gen_req

	export EASYRSA_REQ_CN="meltdown"
	gen_req

	export EASYRSA_REQ_CN="heartbleed"
	gen_req

	export EASYRSA_REQ_CN="VORACLE"
	gen_req "--subject-alt-name=DNS:www.example.org,IP:0.0.0.0"

	unset LIVE_PKI
	unset EASYRSA_REQ_CN
	unset EASYRSA_BATCH
	unset EASYRSA_PKI
}

restore_req ()
{
	[ "$EASYRSA_ALGO" ] || die "restore_req - missing algo"
	STEP_NAME="Restore sample requests for ALGO: $EASYRSA_ALGO"
	rm -rf "$TEMP_DIR/pki-req-$EASYRSA_ALGO"
	mkdir -p "$TEMP_DIR/pki-req-$EASYRSA_ALGO"
	# ubuntu: cp -R, -r, --recursive (copy directories recursively)
	# Windows: cp.exe -R --recursive (-r copy recursively, non-directories as files)
	# xcode10.1: cp -R only, does not support --recursive
	cp -f  -R \
		"${TEMP_DIR}/pki-bkp-${EASYRSA_ALGO}/"* \
		"$TEMP_DIR/pki-req-$EASYRSA_ALGO" \
			2>"$ACT_ERR" 1>"$ACT_OUT" || die "$STEP_NAME"
	rm -f "$ACT_ERR" "$ACT_OUT"
	vcompleted "$STEP_NAME"
}

move_ca ()
{
	newline 3
	STEP_NAME="Send $EASYRSA_ALGO sub-ca maximilian to origin"
	verbose "$STEP_NAME"
	mv "$EASYRSA_PKI/issued/$REQ_name.crt" "$TEMP_DIR/pki-req-$EASYRSA_ALGO/ca.crt" 2>"$ACT_ERR" 1>"$ACT_OUT" || die "$STEP_NAME"
	rm -f "$ACT_ERR" "$ACT_OUT"
	completed
	vcompleted "$STEP_NAME"

	STEP_NAME="Change PKI to $EASYRSA_ALGO sub-ca maximilian"
	verbose "$STEP_NAME"
	export EASYRSA_PKI="$TEMP_DIR/pki-req-$EASYRSA_ALGO"
	completed
	vcompleted "$STEP_NAME"
}

action ()
{
	# Required to support $PATH with spaces (import-req)
	ACT_FILE_NAME="$1"
	ACT_OPTS="$2"

	verbose "$EASYRSA_ALGO: ${ACT_GLOBAL_OPTS:+"$ACT_GLOBAL_OPTS "}$STEP_NAME $ACT_OPTS"
	vverbose "$EASYRSA_ALGO: ${ACT_GLOBAL_OPTS:+"$ACT_GLOBAL_OPTS "}$STEP_NAME $ACT_OPTS"
	newline
	vvverbose "EASYRSA_OPENSSL: ${EASYRSA_OPENSSL}"
	newline

	# shellcheck disable=SC2086
	if [ $((ERSA_OUT + SHOW_CERT_ONLY)) -eq 0 ]
	then
		vvverbose "***** $ERSA_BIN ${ACT_GLOBAL_OPTS} ${STEP_NAME} $ACT_FILE_NAME $ACT_OPTS"
		"$ERSA_BIN" ${ACT_GLOBAL_OPTS} ${STEP_NAME} "$ACT_FILE_NAME" "$ACT_OPTS" \
			2>"$ACT_ERR" 1>"$ACT_OUT" || die "$STEP_NAME"

		rm -f "$ACT_ERR" "$ACT_OUT"
	else
		vvverbose "***** $ERSA_BIN ${ACT_GLOBAL_OPTS} ${STEP_NAME} $ACT_FILE_NAME $ACT_OPTS"
		"$ERSA_BIN" ${ACT_GLOBAL_OPTS} ${STEP_NAME} "$ACT_FILE_NAME" "$ACT_OPTS" \
			|| die "$STEP_NAME"
	fi
	completed
}

execute_node ()
{
	[ $LIVE_PKI ] || return 0
	show_cert
	renew_cert
	show_cert
	revoke_renewed_cert
	# This revokes the renewed (2nd) cert
	revoke_cert
}

init_pki ()
{
	newline 2
	STEP_NAME="init-pki"
	action
}

build_ca ()
{
	newline 2
	STEP_NAME="build-ca nopass"
	action
}

show_ca ()
{
	STEP_NAME="show-ca"
	[ $((SHOW_CERT)) -eq 1 ] && SHOW_CERT_ONLY=1
	action
	newline
	unset SHOW_CERT_ONLY
}

pkcs_export ()
{
	newline 2
	#export EASYRSA_PASSIN=pass:
	#export EASYRSA_PASSOUT=pass:
	STEP_NAME="export-$1 $REQ_name $2 $3"
	action
	unset EASYRSA_PASSIN EASYRSA_PASSOUT
}

build_full ()
{
	newline 2
	STEP_NAME="build-$REQ_type-full $REQ_name nopass inline"
	action
	pkcs_export p12 nokey nopass
	pkcs_export p7 noca
	pkcs_export p8 nopass
	if [ "$EASYRSA_ALGO" = rsa ] && [ -f "${EASYRSA_PKI}/private/${REQ_name}.key" ]
	then
		pkcs_export p1 nopass
	fi
	secure_key
	execute_node
}

build_san_full ()
{
	newline 2
	STEP_NAME="--subject-alt-name=DNS:www.example.org,IP:0.0.0.0 build-$REQ_type-full $REQ_name nopass inline"
	action
	pkcs_export p12 nokey nopass
	pkcs_export p7 noca
	pkcs_export p8 nopass
	if [ "$EASYRSA_ALGO" = rsa ] && [ -f "${EASYRSA_PKI}/private/${REQ_name}.key" ]
	then
		pkcs_export p1 nopass
	fi
	secure_key
	execute_node
}

gen_req ()
{
	newline 1
	STEP_NAME="$1 gen-req $REQ_type $EASYRSA_REQ_CN nopass"
	action
	secure_key
}

import_req ()
{
	newline 2
	REQ_file="${TEMP_DIR}/pki-req-${EASYRSA_ALGO}/reqs/${REQ_name}.req"

	# Note: easyrsa still appears to work in batch mode for this action ?
	unset EASYRSA_BATCH
	STEP_NAME="import-req"
	action "$REQ_file" "$REQ_name"
	export EASYRSA_BATCH=1
}

show_req ()
{
	newline
	STEP_NAME="show-req $REQ_name"
	[ $((SHOW_CERT)) -eq 1 ] && SHOW_CERT_ONLY=1
	action
	unset SHOW_CERT_ONLY
}

sign_req ()
{
	newline 1
	STEP_NAME="sign-req $REQ_type $REQ_name nopass"
	action
	pkcs_export p12 nokey nopass
	pkcs_export p7 noca
	# pkcs_export p8 nokey - Unsupported
	if [ "$EASYRSA_ALGO" = rsa ] && [ -f "${EASYRSA_PKI}/private/${REQ_name}.key" ]
	then
		pkcs_export p1 nopass
	fi
	secure_key
	execute_node
}

show_cert ()
{
	newline
	STEP_NAME="show-cert $REQ_name"
	[ $((SHOW_CERT)) -eq 1 ] && SHOW_CERT_ONLY=1
	action
	unset SHOW_CERT_ONLY
}

show_crl ()
{
	newline
	STEP_NAME="show-crl"
	[ $((SHOW_CERT)) -eq 1 ] && SHOW_CERT_ONLY=1
	action
	unset SHOW_CERT_ONLY
}

renew_cert ()
{
	newline 1
	wait_sec
	# This will probably need an inline option
	STEP_NAME="renew $REQ_name nopass"
	action
	secure_key
}

revoke_renewed_cert ()
{
	newline 1
	wait_sec
	# This will probably need an inline option
	STEP_NAME="revoke-renewed $REQ_name superseded"
	action
	secure_key
}

revoke_cert ()
{
	newline 1
	STEP_NAME="revoke $REQ_name cessationOfOperation"
	CAT_THIS="$EASYRSA_PKI/index.txt"
	#verb_off
	action
	#verb_on
	secure_key
}

gen_crl ()
{
	newline 2
	STEP_NAME="gen-crl"
	action
	CAT_THIS="$EASYRSA_PKI/crl.pem"
	cat_file
}

cat_file ()
{
	[ $((ERSA_OUT)) -eq 1 ] || return 0
	#newline
	#vverbose "cat $CAT_THIS"
	newline
	[ -f "$CAT_THIS" ] || die "cat $CAT_THIS"
	[ $((VVERBOSE)) -eq 1 ] && cat "$CAT_THIS"
	newline
}

create_pki ()
{
	newline 3
	vvverbose "$STAGE_NAME"

	restore_req || die "restore_req failed"

		ssl_version="$("$EASYRSA_OPENSSL" version)"
		printf '%s\n' "" "* EASYRSA_OPENSSL:" \
			"  $EASYRSA_OPENSSL (env)" "  ${ssl_version}"

	export EASYRSA_PKI="$TEMP_DIR/$NEW_PKI"
	vvverbose "* EASYRSA_PKI: $EASYRSA_PKI"

	if [ "$EASYRSA_PKI" = "$TEMP_DIR/pki-empty" ] || [ "$EASYRSA_PKI" = "$TEMP_DIR/pki-error" ]
	then
		vverbose "OMITTING init-pki"
	else
		init_pki
		cp "$TEMP_DIR/vars.utest" "$EASYRSA_PKI/vars" || die "New vars"
	fi
	export EASYRSA_BATCH=1
	LIVE_PKI=1

	LOG_INDENT="$LOG_INDENT_1"

	export EASYRSA_REQ_CN="penelope"
	build_ca
	show_ca

	REQ_type="server"
	REQ_name="s01"
	build_full

	REQ_type="server"
	REQ_name="s02"
	build_san_full

	REQ_type="serverClient"
	REQ_name="s03"
	build_full

	REQ_type="serverClient"
	REQ_name="s04"
	build_san_full

	REQ_type="client"
	REQ_name="c01"
	build_full

	REQ_type="server"
	REQ_name="specter"
	import_req
	sign_req

	REQ_type="serverClient"
	REQ_name="heartbleed"
	import_req
	sign_req

	REQ_type="serverClient"
	REQ_name="VORACLE"
	import_req
	sign_req

	REQ_type="client"
	REQ_name="meltdown"
	import_req
	sign_req

	gen_crl
	show_crl

	unset LIVE_PKI
	REQ_type="ca"
	REQ_name="maximilian"
	import_req
	sign_req
	secure_key

	# goto sub-ca maximilian
	LOG_INDENT=""
	move_ca
	LOG_INDENT="$LOG_INDENT_2"
		LIVE_PKI=1
		show_ca

		REQ_type="server"
		REQ_name="specter"
		sign_req

		REQ_type="serverClient"
		REQ_name="heartbleed"
		sign_req

		REQ_type="serverClient"
		REQ_name="VORACLE"
		sign_req

		REQ_type="client"
		REQ_name="meltdown"
		sign_req

		gen_crl
		show_crl

		unset LIVE_PKI
		secure_key

	unset EASYRSA_BATCH
	unset EASYRSA_PKI
	unset LOG_INDENT

	newline 2
	vcompleted "$STAGE_NAME (Errors: $S_ERRORS)"
	S_ERRORS=0
	newline 3
}


######################################

	# This is badly copied from easyrsa and not fixed, yet..
	# Register cleanup on EXIT
	#trap "exited 0" 0
	# When SIGHUP, SIGINT, SIGQUIT, SIGABRT and SIGTERM,
	# explicitly exit to signal EXIT (non-bash shells)
	trap "failed 1" 1
	trap "failed 2" 2
	trap "failed 3" 3
	trap "failed 6" 6
	trap "failed 15" 15

	ERSA_UTEST_VERSION="2.3.0"

	# Options
	while [ "$1" ]
	do
		case "$1" in
		version)
			echo "easyrsa-unit-tests.sh version: $ERSA_UTEST_VERSION"
			exit 0
		;;
		-u|-h|--help)	usage ;;
		-v)		VERBOSE=1 ;;
		-vv)	VVERBOSE=1; ERSA_OUT="${ERSA_OUT:-1}" ;;
		-t)		WAIT_DELAY=0; VERBOSE=1 ;;
		-b)		DIE=0; BROKEN_PKI=1; SYS_SSL_ENABLE="${SYS_SSL_ENABLE:-0}";
				VVERBOSE="${VVERBOSE:-1}"; ERSA_OUT="${ERSA_OUT:-1}" ;;
		-f)		DIE=0; CUST_SSL_ENABLE=1; OPENSSL_ENABLE=1; LIBRESSL_ENABLE=1;
				VVERBOSE="${VVERBOSE:-1}"; ERSA_OUT="${ERSA_OUT:-1}" ;;
		-x)		export ACT_GLOBAL_OPTS="--x509-alt" ;;
		-l)		LIBRESSL_LIMIT=1 ;;
		*)		print "Unknown option: $i"; failed 1 ;;
		esac
		shift
	done

	init

	#[ -f "$DEPS_DIR/custom-ssl.sh" ] || export CUST_SSL_ENABLE=0
	#[ $((CUST_SSL_ENABLE)) -eq 1 ] && "$DEPS_DIR/custom-ssl.sh"

	#[ -f "$DEPS_DIR/openssl.sh" ] || export OPENSSL_ENABLE=0
	#[ $((OPENSSL_ENABLE)) -eq 1 ] && "$DEPS_DIR/openssl.sh"

	#[ -f "$DEPS_DIR/libressl.sh" ] || export LIBRESSL_ENABLE=0
	#[ $((LIBRESSL_ENABLE)) -eq 1 ] && "$DEPS_DIR/libressl.sh"


	if [ $((SYS_SSL_ENABLE)) -eq 1 ]
	then
		export EASYRSA_OPENSSL="${EASYRSA_OPENSSL:-"$SYS_SSL_LIBB"}"
		easyrsa_unit_test_version

		newline 2
		"$ERSA_BIN" version

		# Don't use vverbose because it filters off the path,
		# which is what we need to know
		vvverbose "EASYRSA_OPENSSL: ${EASYRSA_OPENSSL}"

		# Setup requests with same SSL lib
		setup
		for i in $TEST_ALGOS
		do
			export EASYRSA_ALGO="$i"
			[ "$EASYRSA_ALGO" = "ed" ] && export EASYRSA_CURVE="ed25519"
			STAGE_NAME="System ssl $EASYRSA_ALGO"
			NEW_PKI="pki-sys ssl-$EASYRSA_ALGO"
			printf '%s\n' ">>>>> >>>>> Begin easyrsa $EASYRSA_ALGO tests"
			create_pki
			printf '%s\n' "<<<<< <<<<< End easyrsa $EASYRSA_ALGO tests"
			unset EASYRSA_ALGO EASYRSA_CURVE
		done
		easyrsa_unit_test_version
		unset NEW_PKI
		unset STAGE_NAME
		unset EASYRSA_OPENSSL
	else
		vdisabled "$STAGE_NAME"
	fi

	STAGE_NAME="Custom ssl"
	if [ $((CUST_SSL_ENABLE)) -eq 1 ]
	then
		[ -f "$CUST_SSL_LIBB" ] || die "Missing custom ssl: $CUST_SSL_LIBB"
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
		[ -f "$OSSL_LIBB" ] || die "Missing openssl: $OSSL_LIBB"
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
		[ -f "$LSSL_LIBB" ] || die "Missing libressl: $LSSL_LIBB"
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
		export EASYRSA_OPENSSL="$SYS_SSL_LIBB"
		NEW_PKI="pki-empty"
		#restore_req
		DIE=0 create_pki
	else
		vdisabled "$STAGE_NAME"
	fi

	cleanup

notice "Completed $(date) (Total errors: $T_ERRORS)"
vcompleted "Completed $(date) (Total errors: $T_ERRORS)"

success 0
