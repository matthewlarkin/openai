#!/usr/bin/env bash

cd "$(dirname "$0")" || exit 1


# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

# HELPER FUNCTIONS

function getInput() {
	[[ -t 0 ]] || cat
}

function runBareTerminal() {
	exec bash --rcfile <(cat << EOF
# tell Macs to be quiet about their zsh default
export BASH_SILENCE_DEPRECATION_WARNING=1

source ./bare.sh

if [[ "$BARE_COLOR" == 1 ]]; then
	GREEN='\\033[0;32m'
	YELLOW='\\033[0;33m'
	GRAY='\\033[2;37m'
	RESET='\\033[0m'
fi

PS1="🐻 \[\${GREEN}\]\$(basename \$(pwd)) \[\${YELLOW}\]> \[\${RESET}\]"

printf "\n\${GRAY}entering bare terminal. type exit to leave.\${RESET}\n"
EOF
)
}

function refresh() {
	source ./bare.sh
}

function renew() { # alias for refresh, quicker to type
	refresh
}


# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

# BARE FUNCTIONS

function interpret() {

    local input
    local temp_script

    input=$1 && shift

    [[ ! -f ".var/scripts/$input" ]] && echo "No script by that title found: $input" && exit 1

	temp_script=$(mktemp) && {
		printf '#!/usr/bin/env bash\nset -e\nsource ./bare.sh\n'
		cat ".var/scripts/$input"
	} > "$temp_script"
	
	chmod +x "$temp_script"
	
	# Save the original stdin to file descriptor 3
	exec 3<&0
	
	# Run the temp script with stdin redirected to /dev/null
	"$temp_script" "$@" < /dev/null
	
	# Restore the original stdin
	exec 0<&3
	
	# Close file descriptor 3
	exec 3<&-
	
	rm "$temp_script"
}

function run() {

	local args
	local script
	local csv

	args=() && while [[ $# -gt 0 ]]; do
		case $1 in
			:over) csv=$2 && shift 2 ;;
			*) args+=("$1") && shift ;;
		esac
	done && set -- "${args[@]}"

	script="$1" && shift

	if [[ -n $csv && -f $csv ]]; then

		csv=$(cat "$csv")

		IFS=',' read -r -a fields <<< "$(echo "$csv" | head -n 1)"

		echo "$csv" | tail -n +2 | while IFS=',' read -r line; do

			IFS=',' read -r -a values <<< "$line"
			
			for ((i=0; i<${#fields[@]}; i++)); do
				field_name="${fields[$i]}"
				field_value="${values[$i]}"
				field_value=$(echo "$field_value" | xargs | sed 's/^"\|"$//g')
				export "$field_name"="$field_value"
			done

			interpret "$script" "$@"

		done

	else

		interpret "$script" "$@"

	fi
}

function random() {

	local input
	local command
	local length
	local constraint

	input=$(getInput)
	command='text'
	length=${input:-16}

	while [[ $# -gt 0 ]]; do
		case $1 in
			string|alpha|number) command=$1 ;;
			*) length=$1 ;;
		esac && shift
	done

	# Validate the length
	if [[ ! $length =~ ^[0-9]+$ ]]; then
		echo "Invalid length: $length. Must be a positive integer."
		exit 1
	fi

	# Character sets for each command
	case $command in
		string) constraint='a-zA-Z0-9' ;;
		alpha) constraint='a-zA-Z' ;;
		number) constraint='0-9' ;;
		*) echo "Invalid command: $command" && exit 1 ;;
	esac

	# Generate random string
	LC_ALL=C tr -dc "$constraint" < /dev/urandom | head -c "$length"; echo
	
}


function sub() {

    local replacing
    local replacement
    local input
    local args

    replacing=$1 && shift
    input=$(getInput)

    args=() && while [[ $# -gt 0 ]]; do
        case $1 in
            with) replacement="$2"; shift 2 ;;
            in) input=$2; shift 2 ;;
            *) args+=("$1"); shift ;;
        esac
    done && set -- "${args[@]}"

	echo "${input//$replacing/$replacement}"

}


function transform() {

	local input
	local format
	local variant
	local all
	local args

	input=$(getInput)
	format='text' # Default format
	variant='hyphens' # Default phone format variant
	all=0

	# Parse arguments
	args=() && while [[ $# -gt 0 ]]; do
		case $1 in
			--phone|--telephone|:phone) format='phone' ;;
			--parentheses|--parenthetical|--paren|:parentheses) variant='parentheses' ;;
			--hyphens|--hyphenated|--dashes|--dashed|:hyphens) variant='hyphens' ;;
			--dots|--dotted|--periods|:dots) variant='dots' ;;
			--spaces|--spaced|:spaces) variant='spaces' ;;
			--plain|--raw|--none|--clean|:raw) variant='plain' ;;
			--uppercase|--upper|--caps|:uppercase) variant='uppercase' ;;
			--lowercase|--lower|:lowercase) variant='lowercase' ;;
			--capitalize|--capitalized|:capitalized) variant='capitalize' ;;
			--space-collapse|--squish|:squish) variant='squish' ;;
			--trim|:trim) variant='trim' ;;
			--all) all=1 ;;
			*) args+=("$1") ;;
		esac && shift
	done && set -- "${args[@]}"

	# Check if input is left over
	[[ $# -eq 1 ]] && input=$1

	case $format in

		phone)

			phone=$(echo "$input" | tr -cd '[:digit:]')

			# Check if the phone number is a valid NANP number
			if [[ $phone =~ ^1?([2-9][0-9]{2}[2-9][0-9]{2}[0-9]{4})$ ]]; then
				phone="${BASH_REMATCH[1]}"
			else
				echo "Invalid phone number: Must be a valid NANP number"
				exit 1
			fi

			case $variant in
				parentheses) echo "(${phone:0:3}) ${phone:3:3}-${phone:6:4}" ;;
				hyphens) echo "${phone:0:3}-${phone:3:3}-${phone:6:4}" ;;
				dots) echo "${phone:0:3}.${phone:3:3}.${phone:6:4}" ;;
				spaces) echo "${phone:0:3} ${phone:3:3} ${phone:6:4}" ;;
				plain) echo "$phone" ;;
			esac

			;;

		text)
			case $variant in
				squish) echo "$input" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' ;;
				uppercase) echo "$input" | tr '[:lower:]' '[:upper:]' ;;
				lowercase) echo "$input" | tr '[:upper:]' '[:lower:]' ;;
				capitalize)
					if [[ $all -eq 1 ]]; then
						echo "$input" | awk '{for(i=1;i<=NF;i++) $i=toupper(substr($i,1,1)) tolower(substr($i,2)); print}'
					else
						echo "$input" | awk '{first=toupper(substr($1,1,1)) tolower(substr($1,2)); $1=""; print first $0}'
					fi
					;;
					trim) echo "$input" | awk '{$1=$1; printf "%s", $0}' ;;
			esac
			;;
	esac
}



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

case $1 in

	-t) runBareTerminal && exit 0 ;;
	--version|-v) cat .var/sync ;;
	--upgrade) git pull origin root ;;
	--setup) bash .lib/setup ;;
	*)
		mapfile -t function_names < <(declare -F | awk '{print $3}')

		is_valid_function() {
			local command=$1
			for func in "${function_names[@]}"; do
				if [[ "$func" == "$command" ]]; then
					return 0
				fi
			done
			return 1
		}

		if is_valid_function "$1"; then
			"$@"
		fi
		;;
esac
