#!/usr/bin/env bash
# shellcheck disable=SC1090,SC2317

set -o nounset
set -o errtrace
set -o pipefail

# http://redsymbol.net/articles/unofficial-bash-strict-mode/
IFS=$'\n\t'

# DEFAULTS BEGIN
typeset -i DEBUG=0
# DEFAULTS END

# CONSTANTS BEGIN
readonly PATH=/bin:/usr/bin:/sbin:/usr/sbin

readonly GOOGLE_URL=https://www.gstatic.com/ipranges/goog.txt
readonly FACEBOOK_URL=https://raw.githubusercontent.com/platformbuilds/FacebookIPLists/refs/heads/master/facebook_ipv4_cidr_blocks.lst

typeset bn="" LOGERR=""
bn="$(basename "$0")"
LOGERR=$(mktemp --tmpdir "${bn%\.*}.XXXX")
readonly bn LOGERR

readonly -a BIN_REQUIRED=(gawk ip)
# CONSTANTS END

main() {
    local fn=${FUNCNAME[0]}

    trap 'except $LINENO' ERR
    trap _exit EXIT

    if (( ! DEBUG ))
    then
	exec 4>&2		# Link file descriptor #4 with stderr. Preserve stderr
	exec 2>>"$LOGERR"	# stderr replaced with file $LOGERR
    fi

    checks
    # Read settings
    source "/etc/${bn%\.*}/interface.conf"
    source "/etc/${bn%\.*}/routes.conf"

    (( DEBUG )) && echo "${ROUTES[@]}"

    # Get google &b facebook routes
    typeset -a GoogleRoutes=() FacebookRoutes=()
    mapfile -t GoogleRoutes < <(curl -sS $GOOGLE_URL | grep -P '(\d{1,3}\.){3}\d{1,3}/\d{1,2}')
    mapfile -t FacebookRoutes < <(curl -sS $FACEBOOK_URL | grep -P '(\d{1,3}\.){3}\d{1,3}/\d{1,2}')

    ROUTES+=( "${GoogleRoutes[@]}" )
    ROUTES+=( "${FacebookRoutes[@]}" )

    typeset -a AllRoutesList=() AllRoutesListShort=()
    mapfile -t AllRoutesList < <(ip route show | sed 's/[[:space:]]*$//')
    # shellcheck disable=SC2034
    mapfile -t AllRoutesListShort < <(ip route show | gawk '{ print $1 }')

    for (( i = 0; i < ${#ROUTES[@]}; i++ ))
    do
	local route="${ROUTES[i]} via $GATEWAY dev $IF metric $METRIC"

	if _inarray AllRoutesListShort "${ROUTES[i]}"
	then
	    if ! _inarray AllRoutesList "$route"
	    then
		for (( e = 0; e < ${#AllRoutesList[@]}; e++ ))
		do
		    if [[ ${AllRoutesList[e]} == "${ROUTES[i]}"* ]]
		    then
			_log notice "Delete malformed route '${AllRoutesList[e]}'"
			eval "ip route del ${AllRoutesList[e]}"
		    fi
		done

		_log notice "Add replacement route '$route'"
		eval "ip route add $route"
	    fi
	else
	    _log info "Add missing route '$route'"
	    eval "ip route add $route"
	fi

	unset route
    done

    exit 0
}

checks() {
    local fn=${FUNCNAME[0]}
    # Required binaries check
    for i in "${BIN_REQUIRED[@]}"
    do
        if ! command -v "$i" >/dev/null
        then
            echo "Required binary '$i' is not installed" >&2
            false
        fi
    done
}

except() {
    local -i ret=$?
    local no=${1:-no_line}

    logger -p user.err -t logger "* FATAL: error occured in function '$fn' near line ${no}. Stderr: '$(awk '$1=$1' ORS=' ' "${LOGERR}")'"
    exit "$ret"
}

_log() {
    local fn=${FUNCNAME[0]}

    logger -p "user.$1" -t logger "$2"
}

_inarray() {
    local array="$1[@]"
    local seeking=$2
    local -i in=1

    if [[ ${!array:-nop} == "nop" ]]; then
	# shellcheck disable=SC2086
	return $in
    fi

    for e in ${!array}; do
        if [[ $e == "$seeking" ]]; then
            in=0
            break
        fi
    done

    # shellcheck disable=SC2086
    return $in
}

_exit() {
    local -i ret=$?

    if (( ! DEBUG ))
    then
	exec 2>&4 4>&-	# Restore stderr and close file descriptor #4
    fi

    [[ -f $LOGERR ]] && rm "$LOGERR"
    exit "$ret"
}

usage() {
    echo -e "\\n    Usage: $bn [OPTIONS]\\n
    Options:

    -d, --debug			debug mode
    -h, --help			print help
"
}
# Getopts
getopt -T; (( $? == 4 )) || { echo "incompatible getopt version" >&2; exit 4; }

if ! TEMP=$(getopt -o dh --longoptions debug,help -n "$bn" -- "$@")
then
    echo "Terminating..." >&2
    exit 1
fi

eval set -- "$TEMP"
unset TEMP

while true
do
    case $1 in
	-d|--debug)		DEBUG=1 ;	shift	;;
	-h|--help)		usage ;		exit 0	;;
	--)			shift ;		break	;;
	*)			usage ;		exit 1
    esac
done

main

## EOF ##

