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

	# Setup the 'easyrsa' executable to use
		# In PATH
		ERSA_BIN="easyrsa"

		# For '${ROOT_DIR}/easyrsa'
		if [ -f "$ROOT_DIR/easyrsa" ]; then
			ERSA_BIN="$ROOT_DIR/easyrsa"
		fi

		# For '${ROOT_DIR}/easyrsa3/easyrsa'
		if [ -f "$WORK_DIR/easyrsa" ]; then
			ERSA_BIN="$WORK_DIR/easyrsa"
		fi

	TEST_ALGOS="rsa ec ed"
	[ "$LIBRESSL_LIMIT" ] && TEST_ALGOS="rsa ec"

	CUSTOM_VARS="${CUSTOM_VARS:-1}"
	UNSIGNED_PKI="${UNSIGNED_PKI:-1}"

	# Don't change this
	SYS_SSL_ENABLE="${SYS_SSL_ENABLE:-1}"
	SYS_SSL_LIBB="${SYS_SSL_LIBB:-openssl}"

	# Change this
	# Use any custom command line SSL lib for this
	OSSL_LIBB="${OSSL_LIBB:-"$SYS_SSL_LIBB"}"

	export EASYRSA_KEY_SIZE="${EASYRSA_KEY_SIZE:-1024}"
	export EASYRSA_CA_EXPIRE="${EASYRSA_CA_EXPIRE:-1}"
	export EASYRSA_CERT_EXPIRE="${EASYRSA_CERT_EXPIRE:-365}"
	export EASYRSA_CERT_RENEW="${EASYRSA_CERT_RENEW:-529}"
	export EASYRSA_FIX_OFFSET="${EASYRSA_FIX_OFFSET:-162}"

	# Not worth this dev effort
	#BROKEN_PKI="${BROKEN_PKI:-0}"
	#CUSTOM_OPTS="${CUSTOM_OPTS:-0}"
	#EASYRSA_SP="${EASYRSA_SP:-private}"
	#ERSA_UTEST_CURL_TARGET="${ERSA_UTEST_CURL_TARGET:-default}"
	#export DEPS_DIR="$ROOT_DIR/testdeps"
	#export OPENSSL_ENABLE="${OPENSSL_ENABLE:-0}"
	#export OPENSSL_BUILD="${OPENSSL_BUILD:-0}"
	#export OPENSSL_VERSION="${OPENSSL_VERSION:-git}"

	#export OSSL_LIBB="${OSSL_LIBB:-"$DEPS_DIR/openssl-dev/bin/openssl"}"

	#export CUST_SSL_ENABLE="${CUST_SSL_ENABLE:-0}"
	#export CUST_SSL_LIBB="${CUST_SSL_LIBB:-"$DEPS_DIR/cust-ssl-inst/bin/openssl"}"
	#export LIBRESSL_ENABLE="${LIBRESSL_ENABLE:-0}"
	#export LIBRESSL_BUILD="${LIBRESSL_BUILD:-0}"
	#export LIBRESSL_VERSION="${LIBRESSL_VERSION:-2.8.3}"
	#export LSSL_LIBB="${LSSL_LIBB:-"$DEPS_DIR/libressl/usr/local/bin/openssl"}"
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
	case "$1" in
	3)
		print \
"|| ###########################################################################"
	;;
	2)
		print \
"|| ==========================================================================="
	;;
	1)
		print \
"|| - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -"
	;;
	'')
		[ $((ERSA_OUT)) -ne 1 ] || print "||"
	;;
	*)
		die "Unrecognised newline type: $1"
	esac
}

notice ()
{
	[ $((VERBOSE)) -eq 1 ] || return 0
	print "$1"
}

# shellcheck disable=SC2016
filter_msg ()
{
	MSG="$(
		print "$1" | \
		sed \
			-e 's/--subject-alt-name=[[:alnum:][:punct:]]*[[:blank:]]//' \
			-e 's`/.*/``' \
			-e 's/ nopass//' \
			-e 's/ inline//' \
			-e 's/^ //' \
			-e 's/ $//' \
			-e 's/  / /' \
		)"
}

# verbose and completed work together
verbose ()
{
	[ $((VERBOSE)) -eq 1 ] || return 0
	filter_msg "$1"
	printf "%s" "$LOG_INDENT" "$MSG .."
}

verbose_update ()
{
	# verb is turned off when this is used
	[ "$VVERBOSE" ] && return 0
	printf '%s' "."
}

completed ()
{
	[ $((VERBOSE)) -eq 1 ] || return 0
	print " ok"
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

	detect_host # set LIBRESSL_LIMIT, when required..
}

# Identify host OS
detect_host() {
	unset -v easyrsa_host_os easyrsa_host_test easyrsa_win_git_bash

	# Detect Windows
	[ "${OS}" ] && easyrsa_host_test="${OS}"

	# shellcheck disable=SC2016 # expansion inside '' blah
	easyrsa_ksh='@(#)MIRBSD KSH R39-w32-beta14 $Date: 2013/06/28 21:28:57 $'
	[ "${KSH_VERSION}" = "${easyrsa_ksh}" ] && easyrsa_host_test="${easyrsa_ksh}"
	unset -v easyrsa_ksh

	# If not Windows then nix
	if [ "${easyrsa_host_test}" ]; then
		easyrsa_host_os=win
		easyrsa_uname="${easyrsa_host_test}"
		easyrsa_shell="$SHELL"
		# Detect Windows git/bash
		if [ "${EXEPATH}" ]; then
			easyrsa_shell="$SHELL (Git)"
			easyrsa_win_git_bash="${EXEPATH}"
			# If found then set openssl NOW!
			[ -e /usr/bin/openssl ] && set_var EASYRSA_OPENSSL /usr/bin/openssl
		fi
	else
		easyrsa_host_os=nix
		easyrsa_uname="$(uname 2>/dev/null)"
		easyrsa_shell="$SHELL"

		# Test the Unit Test SSL Library version,
echo "SSL config: $OPENSSL_CNF"
"$EASYRSA_OPENSSL" version
		val="$("$EASYRSA_OPENSSL" version 2>/dev/null)"
		case "${val%% *}" in
			# OpenSSL does not require a safe config-file
			OpenSSL)
				#unset -v require_safe_ssl_conf
				:
			;;
			LibreSSL)
				#require_safe_ssl_conf=1
				export LIBRESSL_LIMIT=1
				TEST_ALGOS="rsa ec"
			;;
			*) die "\
Missing or invalid OpenSSL
Expected to find openssl command at: $EASYRSA_OPENSSL"
		esac
	fi
	host_out="$easyrsa_host_os | $easyrsa_uname | $easyrsa_shell"
	host_out="${host_out}${easyrsa_win_git_bash+ | "$easyrsa_win_git_bash"}"
	unset -v easyrsa_host_test
} # => detect_host()

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
	verbose_update
	vvverbose "Working dir: $WORK_DIR"

	# dir: ./easyrsa3/unit test
	mkdir -p "$TEMP_DIR" || die "Cannot mkdir: -p $TEMP_DIR"
	verbose_update
	vvverbose "Temp dir: $TEMP_DIR"

	STEP_NAME="vars"
	if [ $((CUSTOM_VARS)) -eq 1 ]
	then
		# TODO: MUST Find a usable vars.example because of the live code in vars
		# FOUND_VARS=`where is vars.example`
		#[ -f "$FOUND_VARS/vars.example" ] || dir "File missing: $FOUND_VARS/vars.example"
		#cp "$FOUND_VARS/vars.example" "$WORK_DIR/vars" || die "cp vars.example vars"

		#if [ "$LIBRESSL_LIMIT" ]; then
		#	create_vars > "$TEMP_DIR/vars.utest" || die "create_vars"
		#else
		#	create_mad_vars > "$TEMP_DIR/vars.utest" || die "create_vars"
		#	#create_vars > "$TEMP_DIR/vars.utest" || die "create_vars"
		#fi
		create_mad_vars > "$TEMP_DIR/vars.utest" || die "create_vars"

		verbose_update
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
		verbose_update
		vcompleted "$STEP_NAME"
	else
		vdisabled "$STEP_NAME"
	fi

	STAGE_NAME="Sample requests"
	if [ $((UNSIGNED_PKI)) -eq 1 ] && [ $((SYS_SSL_ENABLE + CUST_SSL_ENABLE + OPENSSL_ENABLE + LIBRESSL_ENABLE)) -ne 0 ]
	then
		vverbose "$STAGE_NAME"
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
		verbose_update
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
	print "

Unit-test: cleanup"
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
	#print ' set_var EASYRSA_FIX_OFFSET 163'
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
	print ' set_var EASYRSA_REQ_ORG       "example.org Skåne & Eslöv"'
	print ' set_var EASYRSA_REQ_EMAIL     "me@example.net"'
	print " set_var EASYRSA_REQ_OU        \"TEST esc \{ \} \£ \¬ \$ TEST # Doe's & Beer's #\""
}

create_mad_vars ()
{
	cat << "UTEST_VARS"

set_var EASYRSA_FIX_OFFSET 163

# Unsupported characters:
# `   # back-tick - CANNOT BE USED - Incompatible with easyrsa_openssl()
# "   # double-quote - MUST be double escaped. MUST be exported (Do not use 'set_var')
#       Example: export EASYRSA_REQ_OU="My \\\"Organisational\\\" Unit"
# $   # dollar-sign - MUST be escaped, due to set_var()
#       Note: Any alpha-numeric character directly following '$' MUST also be escaped
#       Examples: "\$ foo" (With a space separator) or "\$\foo" (Without a space separator
# {,} # Curly-brace - MUST be escaped, due to set_var()

set_var EASYRSA_DN				"org"
set_var EASYRSA_REQ_COUNTRY		"XX"
set_var EASYRSA_REQ_EMAIL		"\{ set_var \} () ~me@example.net~ #"

set_var EASYRSA_REQ_PROVINCE	"\{ set_var \} () PROV Skåne Eslöv #  Doe's & Beer's  # ¬!£%^*() #"
set_var EASYRSA_REQ_CITY		"\{ set_var \} () CITY Skåne Eslöv #  Doe's & Beer's  # -_=+[]/? #"
set_var EASYRSA_REQ_ORG			"\{ set_var \} () ORGN Skåne Eslöv #  Doe's & Beer's  # .> ,< |~ #"
set_var EASYRSA_REQ_OU			"\{ set_var \} () ORGU Skåne Eslöv #  Deer's & Boe's  # \$        #"
set_var EASYRSA_REQ_SERIAL		"a-z,A-Z,0-9 -+/=.,?:()"

# This does not throw unsupported chars warning
#export EASYRSA_REQ_OU="{ *^export* } () ORGU Skåne Eslöv # \\\"Deer'\$ & Boe'\$\\\" # \$$ $  $\# #"

UTEST_VARS
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
	verbose_update
	cp "$TEMP_DIR/vars.utest" "$EASYRSA_PKI/vars" || die "New vars"

	LIVE_PKI=1
	export EASYRSA_BATCH=1
	export EASYRSA_REQ_CN="maximilian"

	build_sub_ca
	verbose_update

	[ -f "$EASYRSA_PKI/reqs/ca.req" ] && \
		mv "$EASYRSA_PKI/reqs/ca.req" "$EASYRSA_PKI/reqs/$EASYRSA_REQ_CN.req"
	unset EASYRSA_REQ_CN

	REQ_name="specter"
	gen_req
	verbose_update

	REQ_name="meltdown"
	gen_req
	verbose_update

	REQ_name="heartbleed"
	gen_req
	verbose_update

	REQ_name="VORACLE"
	gen_req "--subject-alt-name=DNS:www.example.org,IP:0.0.0.0"
	verbose_update

	unset EASYRSA_BATCH
	unset EASYRSA_PKI
	unset LIVE_PKI
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
	cp -f -R \
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

	if [ "$EASYRSA_USE_PASS" ]; then
		PASSIN_OPT=--passin=pass:EasyRSA
		PASSOUT_OPT=--passout=pass:EasyRSA
	else
		unset -v PASSIN_OPT PASSOUT_OPT
	fi

	verbose "$EASYRSA_ALGO: \
${ACT_GLOBAL_OPTS:+"${ACT_GLOBAL_OPTS}" }$STEP_NAME${ACT_OPTS+ "$ACT_OPTS"}"
	vverbose "$EASYRSA_ALGO: \
${ACT_GLOBAL_OPTS:+"${ACT_GLOBAL_OPTS}" }$STEP_NAME${ACT_OPTS+ "$ACT_OPTS"}"

	newline
	vvverbose "EASYRSA_OPENSSL: ${EASYRSA_OPENSSL}"
	newline

	# shellcheck disable=SC2086
	if [ $((ERSA_OUT + SHOW_CERT_ONLY)) -eq 0 ]
	then
		vvverbose "\
***** $ERSA_BIN \
${PASSIN_OPT+"$PASSIN_OPT" }${PASSOUT_OPT+"$PASSOUT_OPT" }\
${ACT_GLOBAL_OPTS+"$ACT_GLOBAL_OPTS" }\
${STEP_NAME}${ACT_FILE_NAME+ "$ACT_FILE_NAME"}${ACT_OPTS+ "$ACT_OPTS"}"

		"$ERSA_BIN" ${PASSIN_OPT+"$PASSIN_OPT" }${PASSOUT_OPT+"$PASSOUT_OPT" }\
			${ACT_GLOBAL_OPTS+"${ACT_GLOBAL_OPTS} "}\
			${STEP_NAME} \
			"$ACT_FILE_NAME" "$ACT_OPTS" \
			2>"$ACT_ERR" 1>"$ACT_OUT" \
				|| die "<<<<< easyrsa <<<<< $STEP_NAME"

		rm -f "$ACT_ERR" "$ACT_OUT"
	else
		vvverbose "\
***** $ERSA_BIN \
${PASSIN_OPT+"$PASSIN_OPT" }${PASSOUT_OPT+"$PASSOUT_OPT" }\
${ACT_GLOBAL_OPTS+"$ACT_GLOBAL_OPTS" }\
${STEP_NAME}${ACT_FILE_NAME+ "$ACT_FILE_NAME"}${ACT_OPTS+ "$ACT_OPTS"}"

		"$ERSA_BIN" \
			${PASSIN_OPT+"$PASSIN_OPT" }${PASSOUT_OPT+"$PASSOUT_OPT" }\
			${ACT_GLOBAL_OPTS+"${ACT_GLOBAL_OPTS} "}\
			${STEP_NAME} \
			"$ACT_FILE_NAME" "$ACT_OPTS" \
				|| die "<<<<< easyrsa <<<<< $STEP_NAME"
	fi
	completed
	newline
}

execute_node ()
{
	[ $LIVE_PKI ] || return 0
	show_cert
	renew_cert
	show_cert
	status_reports
	revoke_renewed_cert
	# This revokes the renewed (2nd) cert
	revoke_cert
}

init_pki ()
{
	STEP_NAME="init-pki"
	action
}

build_ca ()
{
	newline 1
	STEP_NAME="build-ca nopass"
	[ "$EASYRSA_USE_PASS" ] && STEP_NAME="build-ca"
	action
}

build_sub_ca ()
{
	newline 1
	STEP_NAME="build-ca subca nopass"
	[ "$EASYRSA_USE_PASS" ] && STEP_NAME="build-ca subca"
	action
}

show_ca ()
{
	newline 1
	STEP_NAME="show-ca"
	[ $((SHOW_CERT)) -eq 1 ] && SHOW_CERT_ONLY=1
	action
	unset SHOW_CERT_ONLY
}

pkcs_all() {
	#PKCS#12
		if [ "$EASYRSA_USE_PASS" ]; then
			pkcs_export p12 nokey
		else
			pkcs_export p12 nokey nopass
		fi

	# PKCS#7
	pkcs_export p7 noca

	# PKCS#8
	if [ -f "${EASYRSA_PKI}/private/${REQ_name}.key" ]
	then
		if [ "$EASYRSA_USE_PASS" ]; then
			pkcs_export p8
		else
			pkcs_export p8 nopass
		fi
	fi

	# PKCS#1
	if [ "$EASYRSA_ALGO" = rsa ] && [ -f "${EASYRSA_PKI}/private/${REQ_name}.key" ]
	then
		if [ "$EASYRSA_USE_PASS" ]; then
			pkcs_export p1
		else
			pkcs_export p1 nopass
		fi
	fi
}

pkcs_export ()
{
	newline 1
	pkcs_type="$1"
	shift
	opt_1="$1"
	opt_2="$2"
	STEP_NAME="export-$pkcs_type ${REQ_name}${opt_1:+ "$opt_1"}${opt_2:+ "$opt_2"}"
	action
	vcompleted "$STEP_NAME"
	newline
}

build_full ()
{
	newline 2
	STEP_NAME="build-$REQ_type-full $REQ_name nopass inline"
	[ "$EASYRSA_USE_PASS" ] && STEP_NAME="build-$REQ_type-full $REQ_name inline"
	action
	verify_cert
	pkcs_all
	secure_key
	execute_node
}

build_san_full ()
{
	newline 2
	user_SAN="--subject-alt-name=DNS:primary.example.net,DNS:alternate.example.net,IP:0.0.0.0,IP:255.255.255.255"
	STEP_NAME="$user_SAN build-$REQ_type-full $REQ_name nopass inline"
	[ "$EASYRSA_USE_PASS" ] && STEP_NAME="$user_SAN build-$REQ_type-full $REQ_name inline"
	action
	verify_cert
	pkcs_all
	secure_key
	execute_node
}

gen_req ()
{
	newline 1
	STEP_NAME="$1 gen-req $REQ_type $REQ_name nopass"
	[ "$EASYRSA_USE_PASS" ] && STEP_NAME="$1 gen-req $REQ_type $REQ_name"
	action
	secure_key
}

sign_req ()
{
	newline 1
	STEP_NAME="sign-req $REQ_type $REQ_name nopass"
	[ "$EASYRSA_USE_PASS" ] && STEP_NAME="sign-req $REQ_type $REQ_name"
	action
	verify_cert
	pkcs_all
	secure_key
	execute_node
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
	newline 1
	STEP_NAME="show-req $REQ_name"
	[ $((SHOW_CERT)) -eq 1 ] && SHOW_CERT_ONLY=1
	action
	unset SHOW_CERT_ONLY
}

verify_cert ()
{
	newline 1
	STEP_NAME="verify $REQ_name"
	[ $((SHOW_CERT)) -eq 1 ] && SHOW_CERT_ONLY=1
	action
	unset SHOW_CERT_ONLY
}

show_cert ()
{
	newline 1
	STEP_NAME="show-cert $REQ_name"
	[ $((SHOW_CERT)) -eq 1 ] && SHOW_CERT_ONLY=1
	action
	unset SHOW_CERT_ONLY
}

show_crl ()
{
	newline 2
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
	[ "$EASYRSA_USE_PASS" ] && STEP_NAME="renew $REQ_name"
	action
	verify_cert
	pkcs_all
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
	action
	secure_key
}

status_reports ()
{
	newline 1
	STEP_NAME="show-expire"
	action
	newline 1
	STEP_NAME="show-revoke"
	action
	newline 1
	STEP_NAME="show-renew"
	action
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
	newline 2
	verbose "cat $CAT_THIS"
	vverbose "cat $CAT_THIS"
	newline
	[ -f "$CAT_THIS" ] || die "cat $CAT_THIS"
	[ $((ERSA_OUT)) -eq 1 ] && [ $((VVERBOSE)) -eq 1 ] && cat "$CAT_THIS"
	completed
	newline
}

create_pki ()
{
	newline 3
	vvverbose "$STAGE_NAME"

	restore_req || die "restore_req failed"

	ssl_version="$("$EASYRSA_OPENSSL" version)"
	printf '%s\n' "" "* EASYRSA_OPENSSL:" \
		"  $EASYRSA_OPENSSL (env)" "  ${ssl_version}" ""

	[ "$EASYRSA_USE_PASS" ] && print "* Use Passwords!" && print

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
	unset -v EASYRSA_REQ_CN

	REQ_type="server"
	REQ_name="s01"
	build_full

	if [ "$EASYRSA_WIN" ]; then
		: # ok - Skip the rest
	else
		# Full test

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

	CAT_THIS="$EASYRSA_PKI/index.txt"
	cat_file

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

		CAT_THIS="$EASYRSA_PKI/index.txt"
		cat_file

		# END Full Test
	fi

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

	ERSA_UTEST_VERSION="3.1.2"

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
		-p)		EASYRSA_USE_PASS=1 ;;
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

	# Detect Host and disable Edwards curve tests for LibreSSL
	#detect_host


	#[ -f "$DEPS_DIR/custom-ssl.sh" ] || export CUST_SSL_ENABLE=0
	#[ $((CUST_SSL_ENABLE)) -eq 1 ] && "$DEPS_DIR/custom-ssl.sh"

	#[ -f "$DEPS_DIR/openssl.sh" ] || export OPENSSL_ENABLE=0
	#[ $((OPENSSL_ENABLE)) -eq 1 ] && "$DEPS_DIR/openssl.sh"

	#[ -f "$DEPS_DIR/libressl.sh" ] || export LIBRESSL_ENABLE=0
	#[ $((LIBRESSL_ENABLE)) -eq 1 ] && "$DEPS_DIR/libressl.sh"


	if [ $((SYS_SSL_ENABLE)) -eq 1 ]
	then
		#export EASYRSA_OPENSSL="${EASYRSA_OPENSSL:-"$SYS_SSL_LIBB"}"
		export EASYRSA_OPENSSL="${EASYRSA_OPENSSL:-"$OSSL_LIBB"}"
		easyrsa_unit_test_version

		newline 2
		"$ERSA_BIN" show-host

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
		[ "$EASYRSA_USE_PASS" ] && print && print "* Use Passwords!" && print
		unset NEW_PKI
		unset STAGE_NAME
		#unset EASYRSA_OPENSSL
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
	# shellcheck disable=SC2153  ##  (info): Possible misspelling: LSSL_LIBB
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


######## shut-down

		newline 2
		"$ERSA_BIN" version

	cleanup

notice "Completed $(date) (Total errors: $T_ERRORS)"
vcompleted "Completed $(date) (Total errors: $T_ERRORS)"

success 0
