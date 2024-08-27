#!/usr/bin/env bash

if [ "$(basename "$0")" = "bare.sh" ]; then
    cd "$(dirname "$0")" || return 1
    BARE_DIR=$(pwd) && export BARE_DIR
fi

function bareHealthCheck() {

	[[ ! -f bare.sh ]] && { echo "Error: not in bare directory"; return 1; }

	local item

	mkdir -p home && cd home || return 1
	mkdir -p .cache .lib .logs desktop downloads recfiles scripts && cd .. || return 1
	touch home/.barerc
	for item in document openai; do
		mkdir -p home/recfiles/$item; done
	for item in list tags; do
		touch home/recfiles/document/$item.rec; done;
	for item in assistants messages threads; do
		touch home/recfiles/openai/$item.rec; done

}



function bareRunCommands() {

	# Detect macOS, Ubuntu, or Other
	local OS
	OS=$({
		[[ $(uname) == 'Linux' ]] \
			&& grep -q 'Ubuntu' /etc/os-release \
			&& echo "Ubuntu"
		[[ $(uname) == 'Darwin' ]] && echo "macOS"
	} || echo "Other") && export OS

	# Set the values in the associative array
	local -A BASE_CONFIG
	BASE_CONFIG=(
		["BARE_VERSION"]=$(git log -1 --format=%ct)
		["BARE_DIR"]=$(pwd)
		["BARE_TIMEZONE"]=UTC
		["BARE_COLOR"]=0
		["BARE_DEBUG"]=0
		["BARE_REMOTE"]=''
		["HETZNER_API_TOKEN"]=''
		["DIGITALOCEAN_API_TOKEN"]=''
		["LINODE_API_TOKEN"]=''
		["VULTR_API_TOKEN"]=''
		["OPENAI_API_KEY"]=''
		["STRIPE_SECRET_KEY"]=''
		["POSTMARK_SERVER_TOKEN"]=''
		["TOMORROW_WEATHER_API_KEY"]=''
	) && for key in "${!BASE_CONFIG[@]}"; do
		export "$key"="${BASE_CONFIG[$key]}"
	done

	# Colors for script output
	local RED GREEN YELLOW BLUE GRAY RESET
	[[ $BARE_COLOR == 1 ]] && {
		RED=$'\e[31m'
		GREEN=$'\e[32m'
		YELLOW=$'\e[33m'
		BLUE=$'\e[34m'
		GRAY=$'\e[2;37m'
		RESET=$'\e[0m'
		export RED GREEN YELLOW BLUE GRAY RESET
	}

	bareHealthCheck

	# shellcheck disable=SC1091
	source "$BARE_DIR/home/.barerc"

}




function setup() {

	function setCoreVariables() {

		local variables logfile steps_required

		steps_required='false'

		variables=(
			"OPENAI_API_KEY"
			"POSTMARK_API_TOKEN"
			"BARE_EMAIL_FROM"
			"STRIPE_SECRET_KEY"
			"EDITOR"
		)

		logfile="$BARE_DIR/home/.logs/system-report.$(date +%Y-%m-%d).md"

		echo ""
		echo "${BLUE}Checking core variables ...${RESET}"
		echo ""
		sleep 0.2

		echo "System Report $(date)" > "$logfile"
		echo "- - - - -" >> "$logfile"

		# Verify that core variables exist in $BARE_DIR/home/.barerc
		for var in "${variables[@]}"; do
			if ! grep -q "^$var=" "$BARE_DIR/home/.barerc"; then
				echo "$var=''" >> "$BARE_DIR/home/.barerc"
				sleep 0.2
				echo "- Variable *'$var'* is missing. It has been added with an empty value to *$BARE_DIR/home/.barerc*." >> "$logfile"
				steps_required='true'
			fi
		done

		sleep 0.2

		if [[ "$steps_required" == 'true' ]]; then
			echo " | ${RED}Extra steps required${RESET}: a system report with missing variables was written to:"
			echo " | ${GRAY}$logfile${RESET}."
		else
			echo -e " | ${GREEN}All core variables are set!${RESET}"
		fi
	}

	function checkDependencies() {

		local dependencies logfile steps_required

		steps_required='false'

		declare -A dependencies=(
			["jq"]="jq"
			["yq"]="yq"
			["yt-dlp"]="yt-dlp"
			["curl"]="curl"
			["ffmpeg"]="ffmpeg"
			["recsel"]="recutils"
			["sqlite3"]="sqlite3"
			["httpd"]="apache2"
			["pandoc"]="pandoc"
			["xxd"]="xxd"
			["php"]="php"
			["awk"]="awk"
			["perl"]="perl"
			["openssl"]="openssl"
			["magick"]="imagemagick"
			["qrencode"]="qrencode"
			["csvcut"]="csvkit"
		)

		# Only add gdate for macOS
		if [[ "$OS" != "Ubuntu" ]]; then
			dependencies["gdate"]="coreutils"
		fi

		logfile="$BARE_DIR/home/.logs/system-report.$(date +%Y-%m-%d).md"

		echo ""
		echo "${BLUE}Checking dependencies ...${RESET}"
		echo ""
		sleep 0.2

		echo "System Report $(date)" > "$logfile"
		echo "- - - - -" >> "$logfile"

		# Check and log missing dependencies
		for package in "${!dependencies[@]}"; do
			if ! command -v "$package" &> /dev/null; then
				sleep 0.2
				echo "- Dependency *'$package'* not found. Please install *'${dependencies[$package]}'* manually." >> "$logfile"
				steps_required='true'
			fi
		done

		sleep 0.2

		if [[ "$steps_required" == 'true' ]]; then
			echo " | ${RED}Extra steps required${RESET}: a system report with recommendations was written to:"
			echo " | ${GRAY}$logfile${RESET}."
		else
			echo -e " | ${GREEN}All good!${RESET}"
		fi
	}

	checkDependencies
	setCoreVariables

	echo ""
	echo "${GREEN}System check complete.${RESET}"
	echo ""

	unset -f checkDependencies
	unset -f setCoreVariables

}




# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

# HELPER FUNCTIONS


function isValidFunc() {

	local command function_names func

	command="$1"
	mapfile -t function_names < <(declare -F | awk '{print $3}')

	for func in "${function_names[@]}"; do
		if [[ "$func" == "$command" ]]; then
			echo 'true' && return 0
		fi
	done

	return 1

}



function runBareTerminal() {
	# shellcheck disable=SC2028
	exec bash --rcfile <({
		echo "# tell Macs to be quiet about their zsh default"
		echo "export BASH_SILENCE_DEPRECATION_WARNING=1"
		echo "source ./bare.sh"
		echo "if [[ \"\$BARE_COLOR\" == 1 ]]; then"
		echo "    GREEN='\\033[0;32m'"
		echo "    YELLOW='\\033[0;33m'"
		echo "    GRAY='\\033[2;37m'"
		echo "    RESET='\\033[0m'"
		echo "fi"
		echo "PS1=\"🐻 \[\${GREEN}\]\$(basename \$(pwd)) \[\${YELLOW}\]> \[\${RESET}\]\""
		echo "printf \"\n\${GRAY}entering bare terminal. type exit to leave.\${RESET}\n\""
	})
}



function bareSync() {

	# sync www
	rsync -a --ignore-existing .lib/.var/ .var >> /dev/null
	mkdir -p ".var/www" && rsync -av ".lib/.var/www/" ".var/www/" >> /dev/null

	# touch and secure profiles and database
	touch .var/sync
	touch ~/.barerc && chmod 600 ~/.barerc
	touch .var/bare.rec && chmod 600 .var/bare.rec

	if [[ "$OS" == "macOS" ]]; then
		touch ~/.bash_profile
	else
		touch ~/.bashrc
	fi

	# sync recfiles
	local recdefs recfile recdefs_blocks recfile_trimmed output rec_type block

	# Read the content of .etc/bare.rec and .var/bare.rec
	recdefs=$(cat .etc/bare.rec)
	recfile=$(cat .var/bare.rec)

	# Extract and prepare %rec: blocks from recdefs
	recdefs_blocks=$(echo "$recdefs" | awk '/^%rec:/ {if (rec) print rec; rec=$0; next} /^%/ {rec=rec"\n"$0} END {print rec}')

	# Function to get a block from recdefs by type
	get_rec_block() {
		local type=$1
		echo "$recdefs_blocks" | awk -v type="$type" '
		$1 == "%rec:" && $2 == type {
			rec=$0
			while (getline > 0) {
				if ($1 == "%rec:") break
				rec=rec"\n"$0
			}
			print rec
			exit
		}'
	}

	# Trim the recfile to remove any lines that start with % (except those that start with %rec:)
	recfile_trimmed=$(echo "$recfile" | sed '/^%[^r]/d')

	# Process recfile_trimmed to insert corresponding %rec: blocks
	output=""
	while IFS= read -r line; do
		if [[ $line =~ ^%rec: ]]; then
			rec_type=$(echo "$line" | cut -d' ' -f2)
			block=$(get_rec_block "$rec_type")
			output+="$block"$'\n'
		else
			output+="$line"$'\n'
		fi
	done <<< "$recfile_trimmed"

	echo "$output" > .var/bare.rec

	# clean up
	unset -f get_rec_block

}



function refresh() {
	# shellcheck disable=SC1091
	source ./bare.sh
}



function renew() { # alias for refresh, quicker to type
	refresh
}



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

# BARE FUNCTIONS



function age() {

	local input date_cmd stat_cmd output in variant

	[[ -p /dev/stdin ]] && input=$(cat) || input=$1 && shift

	[[ -z "$input" ]] && echo "No input provided"

	# Check if gdate and gstat are available, otherwise use date and stat
	if command -v gdate &> /dev/null; then
		date_cmd="gdate"
	else
		date_cmd="date"
	fi

	if command -v gstat &> /dev/null; then
		stat_cmd="gstat"
	else
		stat_cmd="stat"
	fi

	# Function to validate date input strictly for yyyy-mm-dd or yyyy-mm-dd hh:mm:ss
	validate_date() {
		local date_input="$1"
		if [[ "$date_input" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]] || [[ "$date_input" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}\ [0-9]{2}:[0-9]{2}:[0-9]{2}$ ]]; then
			"$date_cmd" -d "$date_input" +"%Y-%m-%d %H:%M:%S" >/dev/null 2>&1
			return $?
		else
			return 1
		fi
	}

	# Function to get the timestamp from a date string
	get_date_timestamp() {
		local date_input="$1"
		"$date_cmd" -d "$date_input" +%s
	}

	# Function to get the file's creation or modification timestamp
	get_file_timestamp() {
		local file_path="$1" variant="$2"
		
		if [[ $variant == "modified" ]]; then
			"$stat_cmd" -c %Y "$file_path"
		else
			# Some systems don't have birth time (%W), fallback to %Y if not available
			birth_time=$($stat_cmd -c %W "$file_path" 2>/dev/null)
			[[ -z "$birth_time" || "$birth_time" == "0" ]] && birth_time=$($stat_cmd -c %Y "$file_path")
			echo "$birth_time"
		fi
	}

	# Default values
	output="0"
	in="seconds"
	variant="birth"

	# Gather flags
	for arg in "$@"; do
	    case "$arg" in
	        --modified) variant="modified" ;;
	        --years) in="years" ;;
	        --months) in="months" ;;
	        --weeks) in="weeks" ;;
	        --days) in="days" ;;
	        --hours) in="hours" ;;
	        --minutes) in="minutes" ;;
	        --date|--birth) in="date" ;;
	        *) echo "Unknown option: $arg" && return 0 ;;
	    esac
	done

	# Determine if the input is a file or a date
	if [[ -f "$input" ]]; then
		# It's a file, get the appropriate timestamp
		file_timestamp=$(get_file_timestamp "$input" "$variant")
		current_timestamp=$($date_cmd +%s)
		output=$((current_timestamp - file_timestamp))
	elif validate_date "$input"; then
		# It's a date string, convert to timestamp
		date_timestamp=$(get_date_timestamp "$input")
		current_timestamp=$($date_cmd +%s)
		output=$((current_timestamp - date_timestamp))
	else
		echo "Invalid input: expected file or date format (yyyy-mm-dd or yyyy-mm-dd hh:mm:ss)"
	fi

	# Function to convert time based on the selected unit
	convert_time() {
		local unit_seconds=$1
		echo "scale=2; $output / $unit_seconds" | bc
	}

	# Define time units in seconds
	declare -A time_units=(
		[years]=31536000
		[months]=2592000
		[weeks]=604800
		[days]=86400
		[hours]=3600
		[minutes]=60
	)

	# Convert the output if needed
	if [[ -n ${time_units[$in]} ]]; then
		output=$(convert_time "${time_units[$in]}")
	fi

	# Handle --date option to display the file's modification or creation date
	if [[ $in == "date" ]]; then
		if [[ "$OS" == "macOS" ]]; then
			output=$(stat -f %Sm -t "%Y-%m-%d %H:%M:%S" "$input")
		else
			output=$(stat -c %y "$input" | cut -d'.' -f1)
		fi
	fi

	echo "$output"

	unset -f validate_date
	unset -f get_date_timestamp
	unset -f get_file_timestamp
	unset -f convert_time

}


function capitalize() {

	local all input args

	args=() && while [[ $# -gt 0 ]]; do
		case $1 in
			--all) all=1 && shift ;;
			*) args+=("$1") && shift ;;
		esac
	done && set -- "${args[@]}"

	[[ -p /dev/stdin ]] && input=$(cat) || input=$*

	# if 'all', capitalize all words
	if [[ -n "$all" ]]; then
		transform "$input" --capitalize --all
	else
		transform "$input" --capitalize
	fi

}


function cloud() {

	function getCloudProvider() {

		[[ -n "$HETZNER_API_TOKEN" ]] && echo "hetzner" && exit 0
		[[ -n "$DIGITALOCEAN_API_TOKEN" ]] && echo "digitalocean" && exit 0
		[[ -n "$LINODE_API_TOKEN" ]] && echo "linode" && exit 0
		[[ -n "$VULTR_API_TOKEN" ]] && echo "vultr" && exit 0
		{
			echo "Error: no cloud provider set."
			echo ""
			echo "Requires one of:"
			echo -e "  - HETZNER_API_TOKEN\n  - DIGITALOCEAN_API_TOKEN\n  - LINODE_API_TOKEN\n  - VULTR_API_TOKEN"
		} >&2

	}

	# shellcheck disable=SC2317
	function hetzner_info() {
		
		local json
		json=$(curl -sL -H "Authorization: Bearer $HETZNER_API_TOKEN" \
		https://api.hetzner.cloud/v1/servers | jq '[.servers[] | {
			status,
			ip: .public_net.ipv4.ip,
			description: .server_type.description,
			cores: .server_type.cores,
			memory: (.server_type.memory | tostring + " GB"),
			disk: (.server_type.disk | tostring + " GB"),
			location: .datacenter.location.name,
			city: .datacenter.location.city,
			os: .image.description
		}]')
		echo "$json" | jq | rec --from-json

	}

	# shellcheck disable=SC2317
	function hetzner_createSSH() {

		local public_key name response

		public_key=${1-""}
		name=${2-"$(random string)"}

		if [[ -z $public_key ]]; then
			echo "Error: public_key is required." >&2
		fi

		response=$(curl -sL -X POST \
			-H "Authorization: Bearer $HETZNER_API_TOKEN" \
			-H "Content-Type: application/json" \
			-d '{
				"name": "'"$name"'",
				"public_key": "'"$public_key"'"
			}' "https://api.hetzner.cloud/v1/ssh_keys")

		if [[ $(echo "$response" | jq -r '.error') == "null" ]]; then
			echo "$response" | jq -r '.ssh_key.id'
		else
			echo "Error: $(echo "$response" | jq -r '.error.message')."
		fi

	}

	# shellcheck disable=SC2317
	function hetzner_listSSH() {
		# only return: .ssh_keys[], and .id, .public_key
		curl -sL -H "Authorization: Bearer $HETZNER_API_TOKEN" \
			"https://api.hetzner.cloud/v1/ssh_keys" | jq '[.ssh_keys[] | {id: .id, name: .name, pub: .public_key}]' | rec --from-json
	}

	# shellcheck disable=SC2317
	function hetzner_createFirewall() {

		local name rules response

		name=$1
		rules=$2

		response=$(
			curl -sL -X POST \
				-H "Authorization: Bearer $HETZNER_API_TOKEN" \
				-H "Content-Type: application/json" \
				-d '{
					"name": "'"$name"'",
					"rules": '"$rules"'
				}' "https://api.hetzner.cloud/v1/firewalls"
		)

		if [[ $(echo "$response" | jq -r '.error') != "null" ]]; then
			echo "Error: $(echo "$response" | jq -r '.error.message')"
		fi

		echo "$response" | jq '.firewall | {id, name, rules: .rules[].direction + " " + .rules[].protocol + " " + .rules[].port + " " + .rules[].source_ips}' | rec --from-json

	}

	# shellcheck disable=SC2317
	function hetzner_listFirewalls() {
		:
	}

	# shellcheck disable=SC2317
	function hetzner_createServer() {

		local name key response

		name=$1
		key=$2

		response=$(
			curl -sL -X POST \
				-H "Authorization: Bearer $HETZNER_API_TOKEN" \
				-H "Content-Type: application/json" \
				-d '{
					"image" : "ubuntu-22.04",
					"location" : "ash",
					"name" : "'"$name"'",
					"server_type" : "cpx11",
					"ssh_keys" : [ '"$key"' ],
					"start_after_create" : true
				}' "https://api.hetzner.cloud/v1/servers"
		)

		if [[ $(echo "$response" | jq -r '.error') != "null" ]]; then
			echo "Error: $(echo "$response" | jq -r '.error.message')"
		fi

		# return only the vital details about server as recfile
		echo "$response" | jq '.server | {
			id,
			name,
			ip: .public_net.ipv4.ip,
			type: .server_type.description,
			location: .datacenter.location.name,
			city: .datacenter.location.city,
			os: .image.description
		}' | rec --from-json

	}

	local cloud_provider command name key

	cloud_provider=$(getCloudProvider)
	command=$1
	shift

	case $command in
		info) "${cloud_provider}_info" ;;
		create)
			while [[ $# -gt 0 ]]; do
				case $1 in
					--name|-N) name="$2" && shift 2 ;;
					--key|-K)
						if [[ $(validate integer "$2") == 'true' ]]; then
							key="$2" && shift 2
						else
							echo "Error: invalid key ID (not an integer)"
						fi
						;;
					*) echo "Invalid argument: $1" ;;
				esac
			done
			"${cloud_provider}_createServer" "$name" "$key"
			;;
		ssh)
			case $1 in
				create) "${cloud_provider}_createSSH" "${@:2}" ;;
				list) "${cloud_provider}_listSSH" ;;
				*) echo "Invalid argument: $1" ;;
			esac

	esac

	# Unset private functions
	unset -f getCloudProvider
	unset -f hetzner_info
	unset -f hetzner_createSSH
	unset -f hetzner_listSSH
	unset -f hetzner_createFirewall
	unset -f hetzner_listFirewalls
	unset -f hetzner_createServer

}




function codec() {

	local input command index json_array output lines start end reverse_flag

	command=$1 && shift

	[[ -p /dev/stdin ]] && input=$(cat) || input=$1 && shift

	case $command in

		hash)
			# shellcheck disable=2005
			echo "$(php -r "
				\$password = '$input';
				\$hash = password_hash(\$password, PASSWORD_ARGON2ID, ['time_cost' => 3, 'memory_cost' => 65540, 'threads' => 4]);
				echo \$hash;
			")"
			;;

		hash.verify)
			# shellcheck disable=2005
			echo "$(php -r "
				\$password = '$1';
				\$hash = '$input';
				if (password_verify(\$password, \$hash)) {
					echo 'true';
				} else {
					echo 'false';
				}
			")"
			;;

		lines.json)
			# Function to convert a list of items into a JSON array
			convert_to_json_array() {
				local input_data
				input_data="$1"
				jq -R -s -c 'split("\n") | map(select(length > 0) | gsub("^\\s+|\\s+$"; ""))' <<< "$input_data"
			}

			# Function to handle JSON string input
			handle_json_string() {
				local input_data
				input_data="$1"
				jq -s -c '.' <<< "$input_data"
			}

			# Check if the input is a JSON string or a list of items
			if echo -n "$1" | jq empty 2>/dev/null; then
				handle_json_string "$1"
			else
				convert_to_json_array "$1"
			fi
			;;

		items.index)

			index=$1

			json_array=$(echo -n "$input" | sed 's/ /", "/g; s/^/["/; s/$/"]/')
			
			output=""
			if [[ -z "$index" ]]; then
				# No index given, return all items
				echo -n "$json_array" | jq -r '.[]'
			else
				local indices array_length
				IFS=',' read -ra indices <<< "$index"
				array_length=$(echo -n "$json_array" | jq 'length')

				for idx in "${indices[@]}"; do
					reverse_flag=false
					if [[ "$idx" =~ ^- ]]; then
						reverse_flag=true
						idx="${idx#-}"
						json_array=$(echo -n "$json_array" | jq 'reverse')
					fi

					if [[ "$idx" =~ ^[0-9]+$ ]]; then
						output+=$(echo -n "$json_array" | jq -r --argjson n "$idx" '.[$n]')$'\n'
					elif [[ "$idx" =~ ^[0-9]+-[0-9]+$ ]]; then
						start=$(echo -n "$idx" | cut -d'-' -f1)
						end=$(echo -n "$idx" | cut -d'-' -f2)
						output+=$(echo -n "$json_array" | jq -r --argjson start "$start" --argjson end "$end" '.['"$start"':'"$end"'+1][]')$'\n'
					else
						echo -n "Invalid index format: $idx"
					fi

					if $reverse_flag; then
						json_array=$(echo -n "$json_array" | jq 'reverse')
					fi
				done

				# Trim the trailing newline from the final output
				echo "${output%"${output##*[![:space:]]}"}"
			fi
			;;

		lines.index)

			index=$1

			lines=$(echo -n "$input" | awk '{$1=$1;print}' | jq -R -s -c 'split("\n") | map(select(length > 0))')

			output=""
			
			if [[ -z "$index" ]]; then
				# No index given, return all lines
				echo -n "$lines" | jq -r '.[]' | codec newlines.decode
			else
				IFS=',' read -ra indices <<< "$index"

				for idx in "${indices[@]}"; do
					reverse_flag=false
					if [[ "$idx" =~ ^- ]]; then
						reverse_flag=true
						idx="${idx#-}"
						lines=$(echo -n "$lines" | jq 'reverse')
					fi

					if [[ "$idx" =~ ^[0-9]+$ ]]; then
						output+=$(echo -n "$lines" | jq -r --argjson n "$idx" '.[$n]')$'\n'
					elif [[ "$idx" =~ ^[0-9]+-[0-9]+$ ]]; then
						start=$(echo -n "$idx" | cut -d'-' -f1)
						end=$(echo -n "$idx" | cut -d'-' -f2)
						output+=$(echo -n "$lines" | jq -r --argjson start "$start" --argjson end "$end" '.['"$start"':'"$end"'+1][]')$'\n'
					else
						echo -n "Invalid index format: $idx"
					fi

					if $reverse_flag; then
						lines=$(echo -n "$lines" | jq 'reverse')
					fi
				done

				# Trim the trailing newline from the final output
				echo "${output%"${output##*[![:space:]]}"}"
			fi
			;;

		item.raw)
			jq -r <<< "$input"
			;;

		lines.markdown)
			echo "${input//$'\n'/$'  \n'}"
			;;

		lines.items)
			echo "$input" | awk '{$1=$1;print}' | jq -R -s -c 'split("\n") | map(select(length > 0) | @json) | join(" ")' | sed 's/\\\"/\"/g' | sed 's/^"//;s/"$//'
			;;

		text.filesafe)
			sed 's/ /-/g; s/[^a-zA-Z0-9._-]//g' <<< "$input"
			;;

		json.encode)
			jq -s -R -r @json <<< "$input"
			;;

		json.decode)
			jq -r . <<< "$input"
			;;

		newlines.encode)
			while IFS= read -r line || [[ -n "$line" ]]; do
				printf '%s\\n' "$line"
			done <<< "$input"
			;;

		newlines.decode)
			echo -e "$input"
			;;

		url.encode)
			echo -n "$input" | jq -s -R -r @uri
			;;

		url.decode)
			perl -pe 'chomp; s/%([0-9a-f]{2})/sprintf("%s", pack("H2",$1))/eig' <<< "$input" && echo ""
			;;

		form-data.encode)
			python3 - <<END
import json
import urllib.parse

def flatten(d, parent_key=''):
	items = []
	for k, v in d.items():
		new_key = f"{parent_key}[{k}]" if parent_key else k
		if isinstance(v, dict):
			items.extend(flatten(v, new_key).items())
		elif isinstance(v, list):
			for i, sub_v in enumerate(v):
				items.extend(flatten({str(i): sub_v}, new_key).items())
		else:
			items.append((new_key, v))
	return dict(items)

# Load JSON from input string
input_string = """$input"""
json_obj = json.loads(input_string)

# Flatten the JSON
flat_json = flatten(json_obj)

# Encode as form-data
encoded = "&".join(f"{k}={urllib.parse.quote_plus(str(v))}" for k, v in flat_json.items())
print(encoded)
END
			;;

		form-data.decode)
			# Use Python to parse the input and convert it to JSON
			python3 - <<END
import urllib.parse
import json
import re

# Input string from Bash
input_string = "$input"

# Parse the query string
parsed = urllib.parse.parse_qsl(input_string)

# Initialize a dictionary to hold the final JSON structure
json_obj = {}

# Function to set nested keys in the dictionary
def set_nested_value(d, keys, value):
	for key in keys[:-1]:
		if key.isdigit():
			key = int(key)
		if isinstance(d, list) and isinstance(key, int):
			while len(d) <= key:
				d.append({})
			d = d[key]
		else:
			d = d.setdefault(key, {})
	final_key = keys[-1]
	if final_key.isdigit():
		final_key = int(final_key)
	if isinstance(d, list) and isinstance(final_key, int):
		while len(d) <= final_key:
			d.append({})
		d[final_key] = value
	else:
		d[final_key] = value

# Loop through the parsed key-value pairs and structure them into nested JSON
for key, value in parsed:
	# Split the key into parts based on bracket notation
	parts = re.findall(r'\w+', key)
	set_nested_value(json_obj, parts, value)

# Convert dictionaries with integer keys into lists
def convert_to_list(obj):
	if isinstance(obj, dict):
		keys = obj.keys()
		if all(isinstance(k, int) for k in keys):
			max_index = max(keys)
			lst = [obj.get(i, {}) for i in range(max_index + 1)]
			return [convert_to_list(v) for v in lst]
		else:
			return {k: convert_to_list(v) for k, v in obj.items()}
	elif isinstance(obj, list):
		return [convert_to_list(v) for v in obj]
	else:
		return obj

# Convert and print the final JSON output
final_json = convert_to_list(json_obj)
print(json.dumps(final_json, indent=2))
END
			;;

		base64.encode)
			perl -MMIME::Base64 -ne 'print encode_base64($_)' <<< "$input"
			;;

		base64.decode)
			perl -MMIME::Base64 -ne 'print decode_base64($_)' <<< "$input"
			;;

		hex.encode)
			xxd -ps <<< "$input"
			;;

		hex.decode) 
			xxd -r -p <<< "$input"
			;;

		html.encode)
			# shellcheck disable=SC2016
			php -R 'echo htmlentities($argn, ENT_QUOTES|ENT_HTML5) . "\n";' <<< "$input"
			;;

		html.decode) 
			# shellcheck disable=SC2016
			php -R 'echo html_entity_decode($argn, ENT_QUOTES|ENT_HTML5) . "\n";' <<< "$input"
			;;

	esac

}




function copy() {

	local file destination

	[[ -p /dev/stdin ]] && file=$(cat) || file=$1

	while [[ $# -gt 1 ]]; do shift; done;
	destination=$1


	[[ ! -f "$file" ]] && { echo "Error: file '$file' does not exist."; return 1; }
	[[ -z $destination ]] && { echo "Error: destination not provided."; return 1; }

	cp "$file" "$destination"

}



function date() {
    local input
    local args
    local date_cmd
    local date_format
    local input_format
    local custom_format
    local format_parts

    # set system timezone temporarily
    TZ="$BARE_TIMEZONE"

    # Determine the correct date command based on the operating system
    if [[ "$OS" == "macOS" ]]; then
        date_cmd="gdate"
    else
        date_cmd="date"
    fi

    date_format="%Y-%m-%d %H:%M:%S"
    input_format="%Y-%m-%d %H:%M:%S"

    # Process arguments
    args=() && while [[ $# -gt 0 ]]; do
        case $1 in
            as|format|-F|--format|--formatted) # can't do -f here since native date relies on this
                custom_format=1 && shift
                read -r -a format_parts <<< "$1"  # Allows us to handle date and time dynamically as parts
                date_format=""
                for part in "${format_parts[@]}"; do
                    case $part in
                        'U') date_format+="%s " ;;  # 1628841600
                        'Y-M-D') date_format+="%Y-%m-%d " ;;  # 2024-08-13
                        'M-D-Y') date_format+="%m-%d-%Y " ;;  # 08-13-2024
                        'M/D/Y') date_format+="%m/%d/%Y " ;;  # 08/13/2024
                        'Y-m-d') date_format+="%Y-%-m-%-d " ;; # 2024-8-13
                        'm-d-Y') date_format+="%-m-%-d-%Y " ;;  # 8-13-2024
                        'm/d/Y') date_format+="%-m/%-d/%Y " ;;  # 8/13/2024
                        # times
                        'H:M:S'|'H:m:s') date_format+="%H:%M:%S " ;; # 14:30:00
                        'H:M'|'H:m') date_format+="%H:%M " ;; # 14:30
                        'h:m:s'|'h:M:S'|'h:M:s'|'h:m:S') date_format+="%-I:%M:%S %p " ;; # 2:30:00 PM
                        'h:m'|'h:M') date_format+="%-I:%M %p " ;; # 2:30 PM
                        *) date_format+="$part " ;;
                    esac
                done
                date_format="${date_format% }"  # Remove trailing space
                shift
                ;;
            *)
                args+=("$1")
                shift
                ;;
        esac
    done

    # Set the remaining arguments
    set -- "${args[@]}"

	[[ -p /dev/stdin ]] && input=$(cat) || input=$1

    # If no arguments or input, default to today's date
    [[ -z $input && $# -eq 0 ]] && input=$(TZ=$TZ $date_cmd +"%Y-%m-%d %H:%M:%S")
    [[ -z $input ]] && input="$1"

    # Detect the operating system
    os_type=$(uname)

    # Get today's date in yyyy-mm-dd format
    if [ "$os_type" = "Darwin" ] && command -v gdate &> /dev/null; then
        today=$(TZ=$TZ gdate +"%Y-%m-%d")
    else
        today=$(TZ=$TZ date +"%Y-%m-%d")
    fi

    # condition yyyy-mm-dd
    if [[ $(validate date "$input" --format 'Y-m-d') == 'true' ]]; then
        input="$input 00:00:00"
    # yyyy-mm-dd hh:mm:ss
    elif [[ $(validate date "$input" --format 'Y-m-d hh:mm:ss') == 'true' ]]; then
        # input is already in the correct format
        :
    # yyyy-mm-dd hh:mm
    elif [[ $(validate date "$input" --format 'Y-m-d hh:mm') == 'true' ]]; then
        input="$input:00"
    # hh:mm
    elif [[ $(validate date "$input" --format 'hh:mm') == 'true' ]]; then
        input="$today $input:00"
    # hh:mm:ss
    elif [[ $(validate date "$input" --format 'hh:mm:ss') == 'true' ]]; then
        input="$today $input"
    # yyyy-mm-ddThh:mm:ssZ
    elif [[ $(validate date "$input" --format 'Y-m-d\Thh:mm:ss\Z') == 'true' ]]; then
        :
    fi

    # Validate the date and time
    if [[ $# -eq 1 ]]; then
        if [ "$OS" = "macOS" ]; then
            gdate -d "$input_format" "$input" &> /dev/null
        else
            gdate -d "$input" &> /dev/null
        fi
    fi

    # Format and print the date using the specified format, or default to standard
    if [[ $custom_format == 1 ]]; then
        if [[ "$OS" == "macOS" ]]; then
            formatted_date=$(TZ=$TZ gdate -d "$input" +"$date_format")
        else
            formatted_date=$(TZ=$TZ gdate -d "$input" +"$date_format")
        fi
        echo "$formatted_date"
    else
        TZ=$TZ /bin/date "$@"
    fi
}



function deps() {

	local missing_deps
	
	# check each dependency
	missing_deps=()
	for dep in "$@"; do
		if ! command -v "$dep" &> /dev/null; then
			missing_deps+=("$dep")
		fi
	done

	# if there are any missing dependencies, print them
	if [ ${#missing_deps[@]} -gt 0 ]; then
		echo "ERROR >> The following dependencies are missing and need to be installed: "
		for i in "${!missing_deps[@]}"; do
			dep=${missing_deps[$i]}
			if (( i == ${#missing_deps[@]}-1 )); then
				printf '%s' "$dep"
			else
				printf '%s, ' "$dep"
			fi
		done && echo "."
	fi

}



function download() {

	local url
	local output_name
	local temp_file
	local mime_type
	local extension
	local is_youtube

	deps curl

	[[ -t 0 ]] && url=$1 && shift || url=$(cat)

	[[ -z $url ]] && echo "No URL provided"

	[[ $(validate url "$url") == 'false' ]] && echo "Invalid URL"

	# check if this is a YouTube link
	[[ "$(youtube id "$url")" = 'Invalid YouTube URL' ]] && is_youtube=0 || is_youtube=1

	# setup environment
	output_name="$(random string 32)"
	temp_file=".var/downloads/${output_name}"

	if [[ "$is_youtube" = 1 ]]; then

		youtube download "$url" "$@"

	else

		# Download the file to a temporary location
		request "$url" --output "$temp_file"

		# Determine the MIME type
		mime_type=$(file --mime-type -b "$temp_file")

		# Map MIME type to extension
		declare -A mime_extension_map=(
			["image/png"]="png"
			["image/jpeg"]="jpg"
			["image/gif"]="gif"
			["image/webp"]="webp"
			["audio/mpeg"]="mp3"
			["video/mp4"]="mp4"
			["application/pdf"]="pdf"
			["application/json"]="json"
			["text/markdown"]="md"
			["text/plain"]="txt"
			["text/csv"]="csv"
			["application/zip"]="zip"
			["text/html"]="html"
		)

		extension="${mime_extension_map[$mime_type]}"

		[[ -z "$extension" ]] && echo "Unsupported MIME type: $mime_type"

		# Construct the final output file name with the correct extension
		output_file=".var/downloads/${output_name}.${extension}"

		# Rename the file
		mv "$temp_file" "$output_file"

		echo "$output_file"
	fi

}



function email() {

	deps jq

	[[ -z "$POSTMARK_SERVER_TOKEN" ]] && {
		echo "POSTMARK_SERVER_TOKEN is not set"
	}

	# set default from to BARE_EMAIL_FROM
	from=$BARE_EMAIL_FROM

	while [[ $# -gt 0 ]]; do
		case $1 in
			--to) to="$2"; shift 2 ;;
			--subject) subject="$2"; shift 2 ;;
			--body) body="$2"; shift 2 ;;
			--cc) cc="$2"; shift 2 ;;
			--bcc) bcc="$2"; shift 2 ;;
			--from) from="$2"; shift 2 ;;
			--reply-to) reply_to="$2"; shift 2 ;;
			--template) template="$2"; shift 2 ;;
			*) break ;;
		esac
	done

	[[ -n "$template" ]] && body=$(render "$template" "$@" --to-html);

	# Single email mode
	[[ -z "$to" ]] && echo "No recipient specified, use --to to specify a recipient"
	[[ -z "$subject" ]] && echo "No subject specified, use --subject to specify a subject"
	[[ -z "$body" ]] && echo "No body specified, use --body to specify a body"

	# if .var/email/signature.md exists, append it to the end of the email body
	[[ -f ".var/email/signature.md" ]] && body="$body<p>- - -</p>$(render email/signature.md --to-html)";

	payload=$(jq -n \
		--arg from "$from" \
		--arg to "$to" \
		--arg subject "$subject" \
		--arg body "$body" \
		--arg cc "$cc" \
		--arg bcc "$bcc" \
		--arg reply_to "$reply_to" \
		'{
			"From": $from,
			"To": $to,
			"Subject": $subject,
			"HtmlBody": $body,
			"Cc": $cc,
			"Bcc": $bcc,
			"ReplyTo": $reply_to
		}'
	)

	response=$(request https://api.postmarkapp.com/email \
		--json "$payload" \
		--header "X-Postmark-Server-Token: $POSTMARK_SERVER_TOKEN");

	# else
	echo "$response" | jq -r '.MessageID'

}




function filter() {

	local input

	while [[ "$#" -gt 0 ]]; do
		case $1 in
			empty-lines) command="empty-lines"; shift ;;
		esac
	done && set -- "$@"

	input="${1:-$(cat)}"

	case $command in

		empty-lines) 

			echo "$input" | sed '/^$/d'

			;;

		*) echo "Invalid filter: $command" ;;

	esac

}



function geo() {

	deps curl jq
	touch home/.cache/geo.txt

	format_location() {
		local loc="$1"

		if [[ -z "$loc" ]]; then
			loc=$(curl -sL https://ipinfo.io/ip)
		else
			loc=${loc//, /+}
		fi

		echo "$loc"
	}

	local location
	local type
	local decimals
	local coordinates
	local args

	args=() && while [[ $# -gt 0 ]]; do
		case $1 in
			--decimals) decimals="$2"; shift 2 ;;
			--type) type="$2"; shift 2 ;;
			--location) location="$2"; shift 2 ;;
			*) args+=("$1"); shift ;;
		esac
	done && set -- "${args[@]}"

	# Set defaults
	[[ -z "$location" ]] && location=${1:-asheville-nc}
	[[ -z "$type" ]] && type="city"
	[[ -z "$decimals" ]] && decimals=2

	location=$(format_location "$location")
	[[ $location =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && type="ip" || type="city"

	# Check if the location is in the geo.txt file
	if grep -q "^$location " home/.cache/geo.txt; then
		# If the location is in the file, get the coordinates from the file
		coordinates=$(grep "^$location " home/.cache/geo.txt | cut -d ' ' -f 2)
	else
		# If the location is not in the file, fetch the coordinates from the API
		if [[ "$type" == "city" ]]; then
			coordinates=$(curl -s "https://nominatim.openstreetmap.org/search?format=json&q=$location" | jq -r '.[0].lat + "," + .[0].lon' | awk -F, '{printf "%.6f,%.6f\n", $1, $2}')
		else
			coordinates=$(curl -s "https://ipinfo.io/$location" | jq -r '.loc' | awk -F, '{printf "%.6f,%.6f\n", $1, $2}')
		fi

		# Add the location and coordinates to the geo.txt file
		echo "$location $coordinates" >> home/.cache/geo.txt
	fi

	# Format the coordinates to the requested number of decimal places
	coordinates=$(echo "$coordinates" | awk -v decimals="$decimals" -F, '{printf "%.*f,%.*f\n", decimals, $1, decimals, $2}')

	# Output the coordinates
	echo "$coordinates"

	unset -f format_location

}



function image() {

	local command
	local input
	local output_filename
	local aspect_ratio
	local focal_orientation
	local overwrite_mode
	local gravity
	local height
	local blur_radius
	local degrees
	local option
	local output_extension

	deps magick

	command=$1 && shift
	
	[[ -p /dev/stdin ]] && input=$(cat) || input=$1 && shift

	case $command in

		create)

			local color dimensions filename

			color=$input
			dimensions=${1:-250x250}
			filename=${2:-${color}_$dimensions.webp}

			magick -size "$dimensions" "xc:${color}" "$filename"

			;;

		crop )

			aspect_ratio=${1:-3:2}
			focal_orientation=${2:-center}
			overwrite_mode=$3

			# Validate aspect ratio format (e.g., 16:9)
			if ! [[ "$aspect_ratio" =~ ^[0-9]+:[0-9]+$ ]]; then
				echo "Aspect ratio must be in the format W:H (e.g., 16:9)"
				return 1
			fi 

			# Validate focal orientation
			case $focal_orientation in
				north|south|east|west|center|northwest|northeast|southwest|southeast) ;;
				*)
					echo "Focal orientation must be one of: north, south, east, west, center, northwest, northeast, southwest, southeast" >&2
					return 1
				;;
			esac

			# Generate a semantic file name
			output_filename="${input%.*}_${aspect_ratio//:/x}_${focal_orientation}.${input##*.}"

			# Check if file exists and overwrite mode is not set to "overwrite"
			[ -f "$output_filename" ] && [ "$overwrite_mode" != "overwrite" ] && return 1

			# Determine new dimensions and crop position based on aspect ratio and focal orientation
			case $focal_orientation in
				northwest) gravity="NorthWest" ;;
				north) gravity="North" ;;
				northeast) gravity="NorthEast" ;;
				west) gravity="West" ;;
				center) gravity="Center" ;;
				east) gravity="East" ;;
				southwest) gravity="SouthWest" ;;
				south) gravity="South" ;;
				southeast) gravity="SouthEast" ;;
			esac

			# Crop input using ImageMagick's convert tool
			magick "$input" -gravity "$gravity" -crop "$aspect_ratio" +repage "$output_filename" && echo "$output_filename" || echo "Failed to process $input"

			;;

		convert )

			option=$1 && shift

			[[ -z "$input" ]] && echo "Error: input file not provided" >&2 && return 1

			case $option in
				jpg-to-png | png-to-jpg | png-to-webp | heic-to-jpg | heic-to-webp | jpg-to-webp )
					output_extension="${option#*-to-}"
					output_filename="${input%.*}.$output_extension"
					magick "$input" "$output_filename" && echo "$output_filename" || echo "Failed to process $input"
					;;
				*) echo "Invalid conversion: $option" >&2 && return 1 ;;
			esac
		
			;;

		resize)

			height=$1
			output_filename="${input%.*}_resized.${input##*.}"
			
			[[ -f "$input" ]] || { echo "Error: File '$input' not found." >&2; return 1; }
			
			extension=${input##*.}
			base_name=${input%.*}
			
			# Semantic filename
			output_filename="${base_name}_${height}px.${extension}"
			
			if magick "$input" -resize x"$height" "$output_filename"; then
				echo "$output_filename"
			else
				echo "Failed to process $input" >&2 && return 1
			fi

			;;

		thumbnail )

			image resize "$input" 300

			;;

		geo )

			if [ ! -f "$input" ]; then
				echo "Error: File '$input' not found." >&2
				return 1
			fi

			# Extract GPS coordinates using ImageMagick's identify tool
			gps_info=$(magick identify -verbose "$input" | grep "exif:GPS")

			if [ -n "$gps_info" ]; then
				echo "GPS Information for $input:"
				echo "$gps_info"
			else
				echo "No GPS data found in $input."
			fi

			;;

		describe ) ;; # pending

		rotate )
		
			degrees=$1
			output_filename="${input%.*}_rotated.${input##*.}"
			
			if [ ! -f "$input" ]; then
				echo "Error: File '$input' not found." >&2
				return 1
			fi
			
			if magick "$input" -rotate "$degrees" "$output_filename"; then
				echo "$output_filename"
			else
				echo "Failed to process $input" >&2
				return 1
			fi
		
			;;

		blur )

			blur_radius="${1:-5}"  # Default blur radius is 5 if not provided
			output_filename="${input%.*}_blurred.${input##*.}"

			if [ ! -f "$input" ]; then
				echo "Error: File '$input' not found." >&2
				return 1
			fi

			if magick "$input" -blur 0x"$blur_radius" "$output_filename"; then
				echo "$output_filename"
			else
				echo "Failed to process $input" >&2
				return 1
			fi

			;;

		* ) echo "Invalid command: $command" ;;

	esac

}



function interpret() {

    local input user_script args env_file

    args=() && while [[ $# -gt 0 ]]; do
		case $1 in
			--env) env_file=$2; shift 2 ;;
			*) args+=("$1"); shift ;;
		esac
	done && set -- "${args[@]}"

    input=$1 && shift

    [[ ! -f "home/scripts/$input" ]] && \
        echo "No script by that name found: $input" && return 1

    user_script="./$(random string 30)"

    {
        echo '#!/usr/bin/env bash'
        echo 'set -e'
        echo "cd $BARE_DIR"
        echo 'source ./bare.sh'
        [[ -n "$env_file" ]] && cat "$env_file"
        cat "home/scripts/$input"
    } > "$user_script"
    
    chmod +x "$user_script"

    bash -c "$user_script" "$@" < /dev/null
    
    rm "$user_script"

}



function lowercase() {

	[[ -p /dev/stdin ]] && input=$(cat) || input=$1
	transform "$input" --lowercase

}



function math() {

	local operation
	local output

	remaining_args=() && while [[ $# -gt 0 ]]; do
		case $1 in
			round|floor|ceiling|ceil) operation=$1 && shift ;;
			*) remaining_args+=("$1") && shift ;;
		esac
	done && set -- "${remaining_args[@]}"

	[[ -p /dev/stdin ]] && input=$(cat) || input=$1 && shift

	case $operation in

		round)
		
			case $input in
				up) math ceiling "$1" ;;
				down) math floor "$1" ;;
				*)
					decimals=${1:-0}
				
					if [[ $(validate number "$input") == 'false' ]] || [[ $(validate number "$decimals") == 'false' ]]; then
						echo "Error: invalid number"
						return 1
					fi
				
					php -r "echo number_format((float)$input, (int)$decimals, '.', ''), PHP_EOL;"
					;;
			esac
		
			;;
		
		floor)
		
			if [[ $(validate number "$input") == 'false' ]]; then
				echo "Error: invalid number"
				return 1
			fi
		
			php -r "echo floor((float)$input), PHP_EOL;"
		
			;;
		
		ceil|ceiling)
		
			if [[ $(validate number "$input") == 'false' ]]; then
				echo "Error: invalid number"
				return 1
			fi
		
			php -r "echo ceil((float)$input), PHP_EOL;"
		
			;;

		*)

			# Use PHP to sanitize and evaluate the math operation
			php -r "\$math_operation = '$input'; if (preg_match('/^[0-9+\-.*\/() ]+$/', \$math_operation)) { echo eval('return ' . \$math_operation . ';'), PHP_EOL; } else { echo 'Invalid input', PHP_EOL; }"

			;;

	esac

}



function media() {

	local command
	local input
	local remaining_args
	local tmp_dir
	local cover_image_path
	local metadata
	local title
	local album
	local artist
	local output
	local year
	local track
	local cover
	local remove_original
	local ffmpeg_command

	deps ffmpeg

	command=$1 && shift

	[[ -p /dev/stdin ]] && input=$(cat) || input=$1 && shift

	remaining_args=() && while [[ $# -gt 0 ]]; do
		case $1 in
			--cleanup) remove_original=1 && shift ;;
			*) remaining_args+=("$1") && shift ;;
		esac
	done && set -- "${remaining_args[@]}"

	case $command in

			examine)
		
			# Check if the input file exists
			[[ ! -f $input ]] && echo "Error: expected file input"
		
			# Create a temporary directory for the extracted image
			tmp_dir=$(mktemp -d)
			
			# Extract the cover image from the MP3 file
			cover_image_path="$tmp_dir/cover.jpg"
			ffmpeg -i "$input" -an -vcodec copy "$cover_image_path" -y 2>/dev/null
		
			# Check if the cover image was successfully extracted
			[[ ! -f "$cover_image_path" ]] && cover_image_path="null"
		
			# Extract basic metadata using ffprobe and format as a single JSON object
			metadata=$(ffprobe -v quiet -print_format json -show_format "$input" | jq -r \
			--arg cover_image_path "$cover_image_path" \
				'{
					title: .format.tags.title,
					artist: .format.tags.artist,
					album: .format.tags.album,
					track: .format.tags.track,
					year: .format.tags.date,
					cover: $cover_image_path
				}'
			)
		
			# Output the metadata as a JSON object
			echo "$metadata" | rec --from-json
		
			;;
		
		detail)
		
			# takes a given mp3 file and adds metadata (album artwork, title, composer, etc) via ffmpeg
			[[ ! -f $input ]] && echo "Error: expected file input"
		
			# now, examine the file in case some of these
			# are already set and use those as default
			title=$(media examine "$input" | recsel -P title)
			album=$(media examine "$input" | recsel -P album)
			artist=$(media examine "$input" | recsel -P artist)
			output=$input
		
			remaining_args=() && while [[ $# -gt 0 ]]; do
				case $1 in
					--title) title="$2" && shift 2 ;;
					--album) album="$2" && shift 2 ;;
					--year) year="$2" && shift 2 ;;
					--artist) artist="$2" && shift 2 ;;
					--cover) cover="$2" && shift 2 ;;
					--track) track="$2" && shift 2 ;;
					--output) output="$2" && shift 2 ;;
					*) remaining_args+=("$1") && shift ;;
				esac
			done && set -- "${remaining_args[@]}"
			
			[[ -z $title ]] && echo "Error: title is required"
			[[ -z $album ]] && echo "Error: album is required"
			[[ -z $artist ]] && echo "Error: artist is required"
			
			ffmpeg_command=("ffmpeg" "-y" "-i" "$input")
			
			[[ -n $cover ]] && ffmpeg_command+=("-i" "$cover" "-map" "0:0" "-map" "1:0")
			
			ffmpeg_command+=("-c" "copy" "-id3v2_version" "3" \
				"-metadata" "title=$title" \
				"-metadata" "album=$album" \
				"-metadata" "artist=$artist")
			
			[[ -n $year ]] && ffmpeg_command+=("-metadata" "year=$year")
			
			[[ -n $track ]] && ffmpeg_command+=("-metadata" "track=$track")
			
			[[ -n $cover ]] && ffmpeg_command+=("-metadata:s:v" "title=Album cover" "-metadata:s:v" "comment=Cover (front)")
			
			ffmpeg_command+=("$output.tmp.mp3")
			
			"${ffmpeg_command[@]}" > /dev/null 2>&1
		
			# Move the temporary output file to the original input file location
			mv "$output.tmp.mp3" "$output"
		
			echo "$output"
		
			;;

		convert)

			output_extension="$1"
			output=".var/downloads/$(random string 32).$1"
			
			# Check if input file exists
			if [[ ! -f "$input" ]]; then
				echo "Error: Input file does not exist."
			fi
			
			if [[ "$output_extension" == "mp3" ]]; then
				# Extract audio and convert to MP3
				ffmpeg -y -i "$input" -vn -acodec libmp3lame "$output" -hide_banner -loglevel error
			else
				# Convert the input file to the desired output format
				ffmpeg -y -i "$input" -c:v libx264 -crf 28 -preset fast -c:a copy "$output" -hide_banner -loglevel error
			fi
			
			# Check if the output file was created
			if [[ ! -f "$output" ]]; then
				echo "Conversion failed."
			fi
			
			echo "$output"

			;;

		cut)
					
			extension="${input##*.}"
			start_time="$1"
			end_time="$2"
			output="${3:-.var/downloads/$(random string 32).$extension}"
			
			# Determine the output format based on the file extension
			extension="${input##*.}"
			
			case "$extension" in
				mp3)
					# Extract audio and cut to MP3
					ffmpeg -y -ss "$start_time" -to "$end_time" -i "$input" -q:a 0 -map a "$output" -hide_banner -loglevel error
					;;
				m4a)
					# Extract audio and cut to M4A
					ffmpeg -y -ss "$start_time" -to "$end_time" -i "$input" -c:a aac -b:a 192k -map a "$output" -hide_banner -loglevel error
					;;
				wav)
					# Extract audio and cut to WAV
					ffmpeg -y -ss "$start_time" -to "$end_time" -i "$input" -c:a pcm_s16le -map a "$output" -hide_banner -loglevel error
					;;
				flac)
					# Extract audio and cut to FLAC
					ffmpeg -y -ss "$start_time" -to "$end_time" -i "$input" -c:a flac -map a "$output" -hide_banner -loglevel error
					;;
				*)
					# Cut the input file to the desired output format
					ffmpeg -y -ss "$start_time" -to "$end_time" -i "$input" -c copy "$output" -hide_banner -loglevel error
					;;
			esac
			
			# Check if the output file was created
			if [[ ! -f "$output" ]]; then
				echo "Cut failed."
			fi
			
			echo "$output"

			;;

		*) : ;;
	esac

	if [[ "$remove_original" == '1' ]]; then
		rm "$input"
	fi

}



function move() {

	[[ -t 0 ]] && file=$1 || file=$(cat)

	[[ $# == 2 ]] && destination="$2" || destination="$1"

	[[ ! -f "$file" ]] && echo "Error: file '$file' does not exist."
	[[ -z $destination ]] && echo "Error: destination not provided."

	mv "$file" "$destination"

}



function open() {

	[ -z "$EDITOR" ] && echo "EDITOR is not set"

	# Check if $1 is provided
	if [ -n "$1" ]; then
		file="$1"
	else
		# Read from stdin
		file=$(cat)
	fi

	"$EDITOR" "$file"

}



function openai() {

	[[ -z "$OPENAI_API_KEY" ]] && {
		echo ""
		echo -e " ${RED}Error${RESET}: OPENAI_API_KEY is not set"
		read -r -p " ⚙️ Set now? (y/n): " response
		[[ $response == 'y' ]] && {
			read -r -s -p " ⚙️ Enter your OpenAI API key: " OPENAI_API_KEY
			echo ""
			echo "OPENAI_API_KEY=$OPENAI_API_KEY" >> $BARE_DIR/home/.barerc && sleep 0.4
			echo " ⚙️ OPENAI_API_KEY set! You can now use OpenAI in bare."
			echo ""
			return 0
		}
	}

	local args command input
	local assistant_name list_assistants list_threads json_mode debug mode thread_title

	# capture assistant name
	args=() && while [[ "$#" -gt 0 ]]; do
		case $1 in
			@*) assistant_name="${1#@}"; shift ;;
			--assistant) assistant_name="$2"; shift 2 ;;
			--assistants) list_assistants=1 && shift ;;
			--thread) thread_title="$2"; shift 2 ;;
			--threads) list_threads=1 && shift ;;
			--json) json_mode=1 && shift ;;
			--debug) debug='true' && shift ;;
			--high-powered) mode='high-powered'; shift 2 ;;
			*) args+=("$1"); shift ;;
		esac
	done && set -- "${args[@]}"

	# set system prompt (according to assistant name)
	assistant_prompt="You are a helpful assistant.";
	[[ -n $assistant_name ]] && {
		assistant_introduction="In this conversation thread you are '$assistant_name'."
		assistant_instructions="$(recsel home/recfiles/openai/assistants.rec -e "Name = '$assistant_name'" -P Contents)"
		assistant_background="Take into consideration the conversation thread (even if some messages are not your own, as you may be entering the chat mid-conversation and should catch yourself up)."
		assistant_prompt="%YOUR_NAME: $assistant_introduction - - - %YOUR_INSTRUCTIONS: $assistant_instructions - - - %BACKGROUND: $assistant_background - - - %YOUR TASK: Now, you have just been addressed, so respond to the last thing said in a manner consistent with %YOUR_INSTRUCTIONS."
	}

	# if --threads, just list thread title and exit
	[[ -n $list_threads ]] && recsel home/recfiles/openai/threads.rec -P Title && return 0

	# if --assistants, just list assistants and their instructions and exit
	[[ -n $list_assistants ]] && recsel home/recfiles/openai/assistants.rec -p Name,Contents | awk '{
	while (length($0) > 60) {
		space_index = 60
		while (substr($0, space_index, 1) != " " && space_index > 1) space_index--
		if (space_index == 1) space_index = 60
		print substr($0, 1, space_index)
		$0 = substr($0, space_index + 1)
	}
	print
	}' && return 0

	command="chat"

	args=() && for arg in "$@"; do
		case $arg in
			chat|voice|listen|transcribe) command=$arg && shift ;;
			*) args+=("$arg") && shift ;;
		esac
	done && set -- "${args[@]}"

	[[ -p /dev/stdin ]] && input=$(cat) || input=$1 && shift

	[[ -z "$input" ]] && echo "Error: no input provided" >&2 && return 1

	case $command in 

		chat )

			local model system_prompt user_messages assistant_messages messages thread_contents thread_title payload response

			# Initialize variables
			if [[ $mode == 'high-powered' ]]; then
				model="gpt-4o"
			else
				model=${OPENAI_DEFAULT_MODEL:-'gpt-4o-mini'}
			fi
			system_prompt="$assistant_prompt"
			user_messages=()
			assistant_messages=()

			while IFS= read -r line; do
				user_messages+=("$line")
				break
			done <<< "$input"
			
			# Parse command-line arguments
			while [[ "$#" -gt 0 ]]; do
				case $1 in
					--model) model="$2" && shift 2 ;;
					--system_prompt) system_prompt="$2" && shift 2 ;;
					--user_messages) user_messages+=("$2") && shift 2 ;;
					--assistant_messages) assistant_messages+=("$2") && shift 2 ;;
					--messages) messages=$(echo "$2" | jq -c .) && shift 2 ;;
					*) echo "Invalid option: $1" >&2 ;;
				esac
			done

			if [[ -n $thread_title ]]; then

				[[ "$(recsel home/recfiles/openai/threads.rec -e "Title = '$thread_title'")" ]] || recins home/recfiles/openai/threads.rec -f Title -v "$thread_title"

				thread_contents=$(recsel home/recfiles/openai/messages.rec -p Created,Author,Contents -e "Thread = '$thread_title'")

				recins home/recfiles/openai/messages.rec -f Thread -v "$thread_title" -f Author -v "User" -f Contents -v "$user_messages"

			fi

			[[ -n $json_mode ]] && system_prompt="$system_prompt. Return as a raw JSON object (not a json code block). If the user does not specify a property to put the response in, put the response in a property named 'response'. IMPORTANT: DO NOT RETURN A MARKDOWN CODE BLOCK; RETURN A VALID JSON STRING."
			
			# Construct the messages array if not provided
			if [ -z "$messages" ]; then
				
				# Initialize the messages array with the system prompt
				messages=$(jq -n --arg system_prompt "$system_prompt" '[
				{
					"role": "system",
					"content": $system_prompt
				}
				]')
				
				if [[ -n $thread_title ]]; then
					# Fetch the message thread and convert it to a JSON array
					message_thread=$(recsel home/recfiles/openai/messages.rec -p Created,Author,Contents -e "Thread = '$thread_title'" | rec --json)
					
					# Format the message_thread JSON array using jq
					formatted_message_thread=$(echo "$message_thread" | jq '[.[] | {role: (if .Author == "User" then "user" else "assistant" end), name: (if .Author != "User" then .Author else null end), content: .Contents}]')
				else
					# put single value of "$user_messages" and format that as a single message
					formatted_message_thread=$(jq -n --arg user_message "${user_messages[0]}" '[{role: "user", content: $user_message}]')
				fi
					
				# Append the formatted_message_thread array to the messages array
				messages=$(jq --argjson thread "$formatted_message_thread" '. + $thread' <<< "$messages")

			fi
			
			# Construct the final JSON string using jq
			payload=$(jq -n --arg model "$model" --argjson messages "$messages" '{
				model: $model,
				messages: $messages
			}')

			# if json_mode append "response_format": { "type": "json_object" } to payload
			[[ -n $json_mode ]] && payload=$(echo "$payload" | jq '. + {response_format: {type: "json_object"}}')

			[[ $debug == 'true' ]] && {
				request "https://api.openai.com/v1/chat/completions" --token "$OPENAI_API_KEY" --json "$payload" | jq
			}
			
			response=$(request "https://api.openai.com/v1/chat/completions" --token "$OPENAI_API_KEY" --json "$payload" | jq -r '.choices[0].message.content');

			[[ -n $thread_title ]] && {
				recins home/recfiles/openai/messages.rec -f Thread -v "$thread_title" -f Author -v "${assistant_name-Assistant}" -f Contents -v "$response"
			}

			echo "$response"

			;;


		voice )
			
			local model voice response_format speed output

			model='tts-1'
			voice='alloy'
			response_format='mp3'
			speed=1
			output="$(random string 32).mp3"

			while getopts "m:i:v:f:s:o:" opt; do
				case $opt in
					m ) model=$OPTARG ;;
					i ) input=$OPTARG ;;
					v ) voice=$OPTARG ;;
					f ) response_format=$OPTARG ;;
					s ) speed=$OPTARG ;;
					o ) output=$OPTARG ;;
					\? ) echo "Invalid option: $OPTARG" >&2 ;;
					: ) echo "Option -$OPTARG requires an argument." >&2 ;;
				esac
			done

			payload=$(jq -n \
				--arg model "$model" \
				--arg input "$input" \
				--arg voice "$voice" \
				--arg response_format "$response_format" \
				--arg speed "$speed" \
			'{
				model: $model,
				input: $input,
				voice: $voice,
				response_format: $response_format,
				speed: $speed
			}')

			curl -s https://api.openai.com/v1/audio/speech \
				-H "Authorization: Bearer $OPENAI_API_KEY" \
				-H "Content-Type: application/json" \
				-d "$payload" \
				-o ".var/downloads/$output"

			# Check if the file was created and is not empty
			if [ ! -s ".var/downloads/$output" ]; then
				echo "Error: File $output was not created or is empty" >&2
			fi

			echo ".var/downloads/$output"

			;;
		listen )

			# Coming soon. OpenAI only accepts text and image as of now.

			;;


		transcribe )

			local language model prompt response_format temperature timestamp_granularities file max_size file_size response

			model='whisper-1'
			language='en'
			prompt=''
			response_format='json'
			temperature=0
			timestamp_granularities='segment'
			file="$1" && shift

			while [[ "$#" -gt 0 ]]; do
				case $1 in
					--model) model="$2"; shift ;;
					--language) language="$2"; shift ;;
					--prompt) prompt="$2"; shift ;;
					--response_format) response_format="$2"; shift ;;
					--temperature) temperature="$2"; shift ;;
					--timestamp_granularities) timestamp_granularities="$2"; shift ;;
					*) echo "Invalid option: $1" >&2 ;;
				esac
				shift
			done

			if [ -z "$file" ]; then
				read -r file
				if [ -z "$file" ]; then
					echo "Error: No file path provided" >&2
				fi
			fi
			
			if [ ! -f "$file" ]; then
				echo "Error: File '$file' not found" >&2
			fi

			# Check if the file size is greater than 20MB (20 * 1024 * 1024 bytes)
			file_size=$(stat -f%z "$file")
			max_size=$((20 * 1024 * 1024))
			if [ "$file_size" -gt "$max_size" ]; then
				echo "Warning: Files larger than 20MB are not supported. The transcription may fail." >&2
			fi
			
			response=$(curl -s https://api.openai.com/v1/audio/transcriptions \
				-H "Authorization: Bearer $OPENAI_API_KEY" \
				-H "Content-Type: multipart/form-data" \
				-F file="@$file" \
				-F model="$model" \
				-F language="$language" \
				-F prompt="$prompt" \
				-F response_format="$response_format" \
				-F temperature="$temperature" \
				-F timestamp_granularities="$timestamp_granularities")
			
			# Extract the text property from the JSON response and print it
			echo "$response" | jq -r '.text'
			;;

		* ) echo "Invalid command" ;;

	esac

}



function pretty() {

	[[ -p /dev/stdin ]] && input=$(cat) || input=$1 && shift
	
	deps glow
	echo "$input" | glow

}



function qr() {

	deps qrencode

	local link output

	[[ -t 0 ]] && link=$1 || link=$(cat)
	output=".var/downloads/$(random string 30).png"

	qrencode -o "$output" "$link"

	echo "$output"

}



function random() {

	local input command length constraint

	[[ -p /dev/stdin ]] && input=$(cat)

	command='string'
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
	fi

	# Character sets for each command
	case $command in
		string) constraint='a-zA-Z0-9' ;;
		alpha) constraint='a-zA-Z' ;;
		number) constraint='0-9' ;;
		*) echo "Invalid command: $command" ;;
	esac

	# Generate random string
	LC_ALL=C tr -dc "$constraint" < /dev/urandom | head -c "$length"; echo
	
}



function rec() {

	deps rec2csv csvlook

	local input
	local command
	local output

	if [[ -f $1 ]]; then
		input=$(cat "$1") && shift;
	else
		[[ -p /dev/stdin ]] && input=$(cat)
	fi

	[[ -z $input ]] && echo "Error: no input provided" && return 1

	command=$1 && shift

	remaining_args=() && while [[ "$#" -gt 0 ]]; do
		case $1 in
			random|-m|--random) remaining_args+=(-m) && shift ;;
			*) remaining_args+=("$1") && shift ;;
		esac
	done && set -- "${remaining_args[@]}"

	case $command in

		schema) echo "$input" | recinf -d ;;

		tables|types) echo "$input" | recinf -d | sed -n '/^%rec/s/^%rec: //p' ;;

		insert|create)

			[[ $# -eq 0 ]] && echo "Error: expected at least one argument"

			output=$(echo "$input" | recins "$@")
			[[ $? -ne 0 ]] && echo "$output"
			echo "$output" > .var/bare.rec

			;;

		delete|remove)

			[[ $# -eq 0 ]] && echo "Error: expected at least one argument"

			output=$(echo "$input" | recdel "$@")
			[[ $? -ne 0 ]] && echo "$output"
			echo "$output" > .var/bare.rec

			;;

		select)

			echo "$input" | recsel "$@"

			;;

		list)

			case $1 in

				[dD]ocuments) echo "$input" | recsel -t Document -P Title -C ;;

				[aA]ssistants) echo "$input" | recsel -t Assistant -P Name -C ;;

				[sS]cripts) find .var/scripts -maxdepth 1 -print0 | xargs -0 -I {} basename {} ;;

				[tT]hreads) echo "$input" | recsel -t Thread -P Title -C ;;

				[tT]ags) echo "$input" | recsel -t Tag -P Title -C ;;

			esac

			;;

		import)

			case $1 in

				from)

					shift

					file="$1" && shift
					[[ ! -f "$file" ]] && echo "ERROR: no such file: $1"
					# if file is .csv file pipe to --from-csv, if .json pipe to --from-json
					destination="$2" && shift
					[[ $2 == 'to' ]] && destination="$3"
					[[ $file == *.csv ]] && rec --from-csv "$file" "$destination"
					[[ $file == *.json ]] && rec --from-json "$file" "$destination"

					;;

			esac

			;;

		--csv|--to-csv)

			echo "$input" | rec2csv

			;;

		--json|--to-json)

			# Convert recsel output to CSV, then to JSON, and format with jq
			json_output=$(echo "$input" | rec2csv 2>/dev/null | python3 -c 'import csv, json, sys; print(json.dumps([dict(r) for r in csv.DictReader(sys.stdin)]))' 2>/dev/null | jq 2>/dev/null)

			# Check if the conversion was successful
			if [[ $? -eq 0 ]]; then
				echo "$json_output" | jq
			else
				echo "Error: Conversion failed" >&2
				
			fi

			;;

		--from-json)
			
			[[ -f "$1" ]] && input="$(cat "$1")" && shift
			[[ -z $input ]] && echo "ERROR: no input provided"
			
			# Check if the input is an object or an array
			if echo "$input" | jq -e 'type == "object"' > /dev/null; then
				input="[$input]"
			fi
			
			# Convert given input to CSV
			output=$(echo "$input" | jq -r '(.[0] | keys_unsorted) as $keys | $keys, map([.[ $keys[] ]])[] | @csv' | csv2rec)
			[[ -n $1 ]] && echo "$output" >> "$1" || echo "$output"

			;;

		--from-csv)

			[[ -f "$1" ]] && input="$(cat "$1")" && shift
			[[ -z $input ]] && echo "ERROR: no input provided"
			output="$(echo "$input" | sed '1s/^\xEF\xBB\xBF//' | csv2rec)"
			[[ -n $1 ]] && echo "$output" >> "$1" || echo "$output"

			;;

		sync)

			if ! recinf "$1" > /dev/null 2>&1; then
				echo "Error: invalid source recfile"
			else
				recfile="$1"
			fi
			
			if ! recinf "$2" > /dev/null 2>&1; then
				echo "Error: invalid schema recfile"
			else
				schema_file="$2"
			fi
			
			# Extract and prepare %rec: blocks from schema
			schema_blocks=$(awk '/^%rec:/ {if (rec) print rec; rec=$0; next} /^%/ {rec=rec"\n"$0} END {print rec}' < "$schema_file")
			
			# Function to get a block from schema by type
			get_rec_block() {
				local type=$1
				echo "$schema_blocks" | awk -v type="$type" '
				$1 == "%rec:" && $2 == type {
					rec=$0
					while (getline > 0) {
						if ($1 == "%rec:") break
						rec=rec"\n"$0
					}
					print rec
					exit
				}'
			}
			
			# Trim the recfile to remove any lines that start with % (except those that start with %rec:)
			recfile_trimmed=$(sed '/^%[^r]/d' < "$recfile")
			
			# Process recfile_trimmed to insert corresponding %rec: blocks
			output=""
			processed_types=()
			while IFS= read -r line; do
				if [[ $line =~ ^%rec: ]]; then
					rec_type=$(echo "$line" | cut -d' ' -f2)
					block=$(get_rec_block "$rec_type")
					output+=$'\n'"$block"$'\n'
					processed_types+=("$rec_type")
				else
					output+="$line"$'\n'
				fi
			done <<< "$recfile_trimmed"
			
			# Add any missing schema blocks that were not in the original recfile
			while IFS= read -r line; do
				if [[ $line =~ ^%rec: ]]; then
					rec_type=$(echo "$line" | cut -d' ' -f2)
					found=false
					for type in "${processed_types[@]}"; do
						if [[ "$type" == "$rec_type" ]]; then
							found=true
							break
						fi
					done
					if [[ "$found" == false ]]; then
						block=$(get_rec_block "$rec_type")
						output+=$'\n'"$block"$'\n'
					fi
				fi
			done <<< "$schema_blocks"

			# trim any newlines that has a newline directly after it with sed
			echo "$output" | sed '/^$/N;/^\n$/D' > "$recfile"

			uset -f get_rec_block

			;;

	esac

}



function render() {

	local input
	local command
	local to_html
	local pretty

	[[ -p /dev/stdin ]] && input=$(cat) || input=$1

	# Process arguments to handle flags and content
	args=() && for arg in "$@"; do
		case "$arg" in
			--to-html|--as-html)
				to_html=1 && shift
				;;
			--pretty)
				deps glow
				pretty=1 && shift
				;;
			*) args+=("$arg") && shift ;;
		esac
	done && set -- "${args[@]}"

	if [[ $to_html -eq 1 ]]; then
		echo "$input" | pandoc
	elif [[ $pretty -eq 1 ]]; then
		echo "$input" | glow
	else
		echo "$input"
	fi

}



function request() {

	local url
	declare -a curl_cmd

	url=$1 && shift

	curl_cmd=("curl" "-s" "-L" "$url")

	# Function to split --data into multiple -F fields
	split_data_into_form_fields() {
		local data=$1
		local IFS='&'
		local key_value_pairs=("$data")
		
		for pair in "${key_value_pairs[@]}"; do
			IFS='=' read -r key value <<< "$pair"
			curl_cmd+=("-F" "$key=$value")
		done
	}

	# Loop through all arguments
	while [ "$#" -gt 0 ]; do
		case "$1" in
			
			--json) curl_cmd+=("--json" "$2") && shift 2 ;;
			--data) split_data_into_form_fields "$2" && shift 2 ;;
			--file) curl_cmd+=("-F" "@$2") && shift 2 ;;
			--header) curl_cmd+=("-H" "$2") && shift 2 ;;
			--token) curl_cmd+=("-H" "Authorization: Bearer $2") && shift 2 ;;
			--auth) curl_cmd+=("--user" "$2") && shift 2 ;;
			--output) curl_cmd+=("-o" "$2") && shift 2 ;;
			# *) echo "Unknown option: $1" ;;
			
		esac
	done

	"${curl_cmd[@]}"

	unset -f split_data_into_form_fields

}



function reveal() {

	local input

	[[ -t 0 ]] && input="$1" || input=$(cat)

	[[ "$#" -eq 0 && -z $input ]] && echo "No file given"

	for file in "$@"; do
		[[ ! -f "$file" ]] && echo "File '$file' not found"
		cat "$file"
	done

}



function round() {

	math round "$@"

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

        while IFS=',' read -r line; do

            IFS=',' read -r -a values <<< "$line"

			# Create or truncate the variables file
			env_file="home/.cache/env.tmp"
			
			for ((i=0; i<${#fields[@]}; i++)); do
				field_name="${fields[$i]}"
				field_value="${values[$i]}"
				field_value=$(echo "$field_value" | xargs | sed 's/^"\|"$//g')
				echo "$field_name=\"$field_value\"" >> "$env_file"
			done

            interpret "$script" --env "$env_file" "$@" < /dev/null

			rm "$env_file"

        done < <(echo "$csv" | tail -n +2)

    else

        interpret "$script" "$@"

    fi
}



function serve() {

	local command

	deps sqlpage

	export PORT=8282
	export allow_exec=true
	export max_uploaded_file_size=50000000

	[[ -n $1 ]] && command=$1

	case "$command" in

		--briefly )
			serve "$@" > /dev/null 2>&1 &
			service_pid=$!

			# Give the service some time to start
			sleep 0.2

			if ps -p $service_pid > /dev/null; then
				kill $service_pid
				wait $service_pid 2>/dev/null
			fi
			;;

		* )
			cd .var/www && sqlpage
			;;
	esac

	unset PORT
	unset allow_exec
	unset max_uploaded_file_size

}



function show() {

	local input

	[[ -p /dev/stdin ]] && input=$(cat) || input=$1
	[[ -n $input ]] || { echo "No input provided"; }
	echo "$input"

}



function silence() {

	local input

	[[ -p /dev/stdin ]] && input=$(cat) || input=$1
	echo "$input" >> /dev/null

}



function size() {

	local input stat_cmd

	[[ -p /dev/stdin ]] && input=$(cat) || input=$1

	# Check the OS type and set the appropriate stat command
	if [[ "$(uname)" == "Darwin" ]]; then
		stat_cmd="stat -f%z"
	else
		stat_cmd="stat --format=%s"
	fi

	# Calculate the total size
	# shellcheck disable=SC2086 # (we want word splitting here)
	find "$input" -type f -exec $stat_cmd {} + | awk '{
		total += $1
	}
	END {
		if (total >= 1073741824) 
			printf "%.2f GB\n", total / 1073741824
		else if (total >= 1048576) 
			printf "%.2f MB\n", total / 1048576
		else if (total >= 1024) 
			printf "%.2f KB\n", total / 1024
		else 
			printf "%d bytes\n", total
	}'

}



function speed() {

	deps ffmpeg openssl

	local speed_factor input_file output_file is_video extension

	# Default values
	speed_factor=${1:-'0.5'}
	input_file="$2"
	output_file=${3:-".var/downloads/$(openssl rand -hex 16).mp3"}

	if [ -z "$input_file" ]; then
		echo "Error: Input file is not provided" >&2
	fi

	# Parse command line options
	while getopts s:i:o: option
	do
		case "${option}"
		in
			s) speed_factor=${OPTARG};;
			i) input_file=${OPTARG};;
			o) output_file=${OPTARG};;
			\?) echo "Usage: $0 [-s speed_factor] [-i input_file] [-o output_file]" >&2 ;;
		esac
	done

	# Get the extension of the source file
	extension="${input_file##*.}"

	# Determine if the input file is a video file
	is_video=$(ffprobe -v error -select_streams v:0 -show_entries stream=codec_name -of default=noprint_wrappers=1:nokey=1 "$input_file")

	# If the speed factor is negative, slow down the audio and video
	if (( $(echo "$speed_factor < 0" | bc -l) )); then
		speed_factor=${speed_factor#-} # Remove the negative sign
		if [ -z "$is_video" ]; then
			ffmpeg -y -loglevel panic -i "$input_file" -filter:a "atempo=$speed_factor" "$output_file"
		else
			ffmpeg -y -loglevel panic -i "$input_file" -filter:v "setpts=$speed_factor*PTS" -filter:a "atempo=$speed_factor" "$output_file"
		fi
	# If the speed factor is positive, speed up the audio and video
	elif (( $(echo "$speed_factor > 0" | bc -l) )); then
		if [ -z "$is_video" ]; then
			ffmpeg -y -loglevel panic -i "$input_file" -filter:a "atempo=$speed_factor" "$output_file"
		else
			ffmpeg -y -loglevel panic -i "$input_file" -filter:v "setpts=1/$speed_factor*PTS" -filter:a "atempo=$speed_factor" "$output_file"
		fi
	else
		echo "Error: Speed factor must be non-zero" >&2
	fi

	echo "$output_file"

}



function squish() {

	local input

	[[ -p /dev/stdin ]] && input=$(cat) || input=$1
	transform "$input" --squish

}



function sub() {

    local replacing replacement input args

    replacing=$1 && shift
	[[ -p /dev/stdin ]] && input=$(cat) || input=$1 && shift

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

	local input format variant all args

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

	[[ -p /dev/stdin ]] && input=$(cat) || input=$1 && shift

	case $format in

		phone)

			phone=$(echo "$input" | tr -cd '[:digit:]')

			# Check if the phone number is a valid NANP number
			if [[ $phone =~ ^1?([2-9][0-9]{2}[2-9][0-9]{2}[0-9]{4})$ ]]; then
				phone="${BASH_REMATCH[1]}"
			else
				echo "Invalid phone number: Must be a valid NANP number"
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



function translate() {

	deps dig

	local input output_format explain_reasoning model remaining_args

	output_format="english"
	model=${OPENAI_DEFAULT_MODEL:-'gpt-4o'}

	remaining_args=() && while [[ $# -gt 0 ]]; do
		case $1 in
			to|--to) output_format=$2 && shift 2 ;;
			--explain) explain_reasoning='true' && shift ;;
			--model) model="$2" && shift 2 ;;
			--*) output_format="${1#--}" && shift ;;
			*) remaining_args+=("$1") && shift ;;
		esac
	done && set -- "${remaining_args[@]}"

	if [[ -z $input ]]; then
		[[ -t 0 ]] && input="$1" && shift || input=$(cat);
	fi

	[[ -z $input ]] && echo "Error: requires input"

	case $output_format in

		# measurements

		kg|kilograms) 

			input_format=$1 && shift

			[[ $(validate number "$input") == 'false' ]] && echo "Error: invalid number"

			case $input_format in

				grams|g) echo "$input * 1000" | bc -l ;;

				pounds|lbs) echo "$input * 2.20462" | bc -l ;;

				ounces|oz) echo "$input * 35.274" | bc -l ;;

				tons) echo "$input * 0.00110231" | bc -l ;;

				*) echo "Error: invalid input format" ;;

			esac

			;;


		ip|IP|ip-address)

			[[ $(validate domain "$input") == 'false' ]] && echo "Error: invalid domain name"

			dig +short "$input"

			;;

		*)

			runs_remaining=3

			while [ $runs_remaining -gt 0 ]; do

				message="You are an expert translator. Your task is to translate, reword, or otherwise transform the source material into the requested output format. Respond with one JSON object containing two properties: 'reasoning <string>' and 'translation <string>' where 'reasoning' contains your reasoning for the translation (what choices you made and why you chose to interpret it this way plus any caveats or gotchas) and 'translation' is your translation of the source material.\n- - - \n######\n - - -\n OUTPUT_FORMAT: {{ $output_format }} - - - SOURCE MATERIAL: {{ $input }}\n - - - \n######\n - - -\n Remember, return a raw, one dimensional JSON object, containing only the 'reasoning' and 'translation' properties. DO NOT return a markdown code block."

				response="$(openai chat "$message" --model "$model" --json)"

				# Validate that response JSON object contains just two properties (reasoning and translation)
				if [[
					$(echo "$response" | jq 'keys | length') -eq 2 && \
					$(echo "$response" | jq -r 'has("reasoning")') == 'true' && \
					$(echo "$response" | jq -r 'has("translation")') == 'true'
				]]; then
					runs_remaining=0  # Valid response, exit the loop
				else
					runs_remaining=$((runs_remaining - 1))  # Invalid response, decrement runs_remaining
					if [ $runs_remaining -eq 0 ]; then
						echo "Sorry, we're having a hard time responding to this request. Maybe try rephrasing."
					fi
				fi

			done

			[[ $explain_reasoning == 'true' ]] && echo "$response" | jq -r '.reasoning'

			echo "$response" | jq -r '.translation'

			;;

	esac

}



function trim() {

	[[ -p /dev/stdin ]] && input=$(cat) || input=$1
	transform "$input" --trim

}



function uppercase() {

	[[ -p /dev/stdin ]] && input=$(cat) || input=$1
	transform "$input" --uppercase

}



function validate() {

	local input type output runs_remaining response explain condition source_material model precision digits regex date_format os_type parsed_date time_format normalized_input parsed_time country

	type=$1 && shift
	[[ -z $input ]] && input=$1 && shift
	output="false"

	case $type in

		json|json-format)

			[[ -f $input ]] && input=$(cat "$input")

			if jq . <<< "$input" &>/dev/null; then
				output="true"
			fi

			;;

		csv|csv-format)

			[[ -f $input ]] && input=$(cat "$input")

			if [[ $(echo "$input" | csvclean --dry-run) == 'No errors.' ]]; then
				output="true"
			fi

			;;

		dir|directory|folder)

			if [[ -d $input ]]; then
				output="true"
			fi

			;;

		file)

			if [[ -f $input ]]; then
				output="true"
			fi

			;;

		ai)

			runs_remaining=3
			condition="$input"
			source_material="$1" && shift
			model=${OPENAI_DEFAULT_MODEL:-'gpt-4o-mini'}

			while true; do
				case $1 in
					--explain) explain=true && shift ;;
					--high-powered) model='gpt-4o' && shift ;;
					--model) model="$2" && shift 2 ;;
					''|*) break ;;
				esac
			done
			
			while [ $runs_remaining -gt 0 ]; do
				response="$(openai chat "You are an expert validator. I will provide a condition and a source material. Your task is to determine if the source material satisfies the condition. Respond with one JSON object containing two properties: 'reasoning <string>' and 'answer <true/false boolean>' where 'reasoning' contains your reasoning and 'answer' is either true or false, indicating whether the source material satisfies the condition. - - - ###--### - - - CONDITION: $condition - - - SOURCE MATERIAL: $source_material - - - ###--### - - - So... what do you say? True or false; does the source material satisfy the condition? Remember, respond only with a one dimensional JSON object (containing just the 'reasoning' and 'answer' properties)." --model "$model" --json)"
			
				if [[ $(echo "$response" | jq 'keys | length') -eq 2 && ( $(echo "$response" | jq -r '.answer') == 'true' || $(echo "$response" | jq -r '.answer') == 'false' ) ]]; then
					runs_remaining=0
				else
					runs_remaining=$((runs_remaining - 1))
					if [ $runs_remaining -eq 0 ]; then
						echo "Sorry, we're having a hard time responding to this request. Maybe try rephrasing."
					fi
				fi
			done

			[[ -n $explain ]] && echo "$response" | jq -r '.reasoning'
			echo "$response" | jq -r '.answer'
			
			;;

		alpha|alphabetic)
			if echo "$input" | grep -Eq '^[a-zA-Z]+$'; then
				output="true"
			fi
			;;

		alpha-underscore|alphabetic-underscore)
			if echo "$input" | grep -Eq '^[a-zA-Z_]+$'; then
				output="true"
			fi
			;;

		alpha-hyphen|alphabetic-hyphen)
			if echo "$input" | grep -Eq '^[a-zA-Z-]+$'; then
				output="true"
			fi
			;;

		alphanumeric)
			if echo "$input" | grep -Eq '^[a-zA-Z0-9]+$'; then
				output="true"
			fi
			;;

		uppercase|uppercased)
			if echo "$input" | grep -Eq '^[A-Z]+$'; then
				output="true"
			fi
			;;

		lowercase|lowercased)
			if echo "$input" | grep -Eq '^[a-z]+$'; then
				output="true"
			fi
			;;

		url|web-address|link)
			if echo "$input" | grep -Eq '^(https?:\/\/)?([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(\/.*)?$'; then
				output="true"
			fi
			;;

		domain)
			if echo "$input" | grep -Eq '^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$|^([a-zA-Z0-9-]+\.)+[a-zA-Z0-9-]{2,}$'; then
				output="true"
			fi
			;;

		ip)
			if echo "$input" | grep -Eq '^([0-9]{1,3}\.){3}[0-9]{1,3}$'; then
				output="true"
			fi
			;;

		number|numeric|num)
			if echo "$input" | grep -Eq '^-?[0-9]+(\.[0-9]+)?$'; then
				output="true"
			fi
			;;

		integer|int|digit)
			if echo "$input" | grep -Eq '^-?[0-9]+$'; then
				output="true"
			else
				output='false'
			fi
			;;

		email|email-address)
			if echo "$input" | grep -Eq '^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'; then
				output="true"
			fi
			;;

		uuid)
			if echo "$input" | grep -Eq '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'; then
				output="true"
			fi
			;;

		decimal|float|floating-point)

			precision=""
			digits=""

			while true; do
				case $1 in
					--places|--decimals|--precision) precision="$2" && shift 2 ;;
					--digits|--length) digits="$2" && shift 2 ;;
					'') break ;;
					*) shift ;;
				esac
			done

			regex="^[0-9]+\.[0-9]{${precision:-1},}$"

			if [[ -n $digits ]]; then
				regex="^[0-9]{${digits}}\.[0-9]{${precision:-1},}$"
			fi

			if echo "$input" | grep -Eq "$regex"; then
				output="true"
			else
				output="false"
			fi
			;;
		
		date)

			date_format="%Y-%m-%d"

			case $1 in
				--format)
					case $1 in
						"mm-dd-yyyy"|"mm-dd-Y") date_format="%m-%d-%Y" ;;
						"mm/dd/yyyy"|"mm/dd/Y") date_format="%m/%d/%Y" ;;
						"mm.dd.yyyy"|"mm.dd.Y") date_format="%m.%d.%Y" ;;
						"dd-mm-yyyy"|"dd-mm-Y") date_format="%d-%m-%Y" ;;
						"dd/mm/yyyy"|"dd/mm/Y") date_format="%d/%m/%Y" ;;
						"dd.mm.yyyy"|"dd.mm.Y") date_format="%d.%m.%Y" ;;
						"yyyy-mm-dd"|"Y-mm-dd"|"Y-m-d") date_format="%Y-%m-%d" ;;
						"yyyy/mm/dd"|"Y/mm/dd") date_format="%Y/%m/%d" ;;
						"yyyy.mm.dd"|"Y.mm.dd") date_format="%Y.%m.%d" ;;
						"yyyy-mm-ddThh:mm:ss"|"Y-mm-ddThh:mm:ss") date_format="%Y-%m-%dT%H:%M:%S" ;;
						"yyyy-mm-ddThh:mm:ssZ"|"Y-mm-ddThh:mm:ssZ") date_format="%Y-%m-%dT%H:%M:%SZ" ;;
						"yyyy-mm-dd hh:mm"|"Y-mm-dd hh:mm") date_format="%Y-%m-%d %H:%M" ;;
						"yyyy-mm-dd hh:mm am/pm"|"Y-mm-dd hh:mm am/pm") date_format="%Y-%m-%d %I:%M %p" ;;
						"yyyy-mm-dd hh:mm:ss"|"Y-mm-dd hh:mm:ss"|"Y-m-d hh:mm:ss") date_format="%Y-%m-%d %H:%M:%S" ;;
						"mm-dd-yyyy hh:mm:ss"|"mm-dd-Y hh:mm:ss") date_format="%m-%d-%Y %H:%M:%S" ;;
						"mm/dd/yyyy hh:mm:ss"|"mm/dd/Y hh:mm:ss") date_format="%m/%d/%Y %H:%M:%S" ;;
						"dd-mm-yyyy hh:mm:ss"|"dd-mm-Y hh:mm:ss") date_format="%d-%m-%Y %H:%M:%S" ;;
						"dd/mm/yyyy hh:mm:ss"|"dd/mm/Y hh:mm:ss") date_format="%d/%m/%Y %H:%M:%S" ;;
						"mm/dd/yyyy hh:mm am/pm"|"mm/dd/Y hh:mm am/pm") date_format="%m/%d/%Y %I:%M %p" ;;
						"m/d/yyyy"|"m/d/Y") date_format="%-m/%-d/%Y" ;;
						"m/d/yyyy hh:mm am/pm"|"m/d/Y hh:mm am/pm") date_format="%-m/%-d/%Y %I:%M %p" ;;
						"m/d/yyyy h:mm am/pm"|"m/d/Y h:mm am/pm") date_format="%-m/%-d/%Y %-I:%M %p" ;;
						"yyyy-mm-dd hh:mm:ss Z"|"Y-mm-dd hh:mm:ss Z") date_format="%Y-%m-%d %H:%M:%S %z" ;;
						"yyyy-mm-ddThh:mm:ss+hh:mm"|"Y-mm-ddThh:mm:ss+hh:mm") date_format="%Y-%m-%dT%H:%M:%S%z" ;;
						"yyyy-mm-dd hh:mm:ss z"|"Y-mm-dd hh:mm:ss z") date_format="%Y-%m-%d %H:%M:%S %Z" ;;
						"yyyy/mm/dd hh:mm:ss Z"|"Y/mm/dd hh:mm:ss Z") date_format="%Y/%m/%d %H:%M:%S %z" ;;
						"yyyy.mm.dd hh:mm:ss Z"|"Y.mm.dd hh:mm:ss Z") date_format="%Y.%m.%d %H:%M:%S %z" ;;
						"dd.mm.yyyy hh:mm:ss"|"dd.mm.Y hh:mm:ss") date_format="%d.%m.%Y %H:%M:%S" ;;
						"dd/mm/yyyy hh:mm:ss Z"|"dd/mm/Y hh:mm:ss Z") date_format="%d/%m/%Y %H:%M:%S %z" ;;
						"yy/mm/dd") date_format="%y/%m/%d" ;;
						"yy-mm-dd") date_format="%y-%m-%d" ;;
						"dd/mm/yy") date_format="%d/%m/%y" ;;
						"mm/dd/yy") date_format="%m/%d/%y" ;;
						"m/d/yy") date_format="%-m/%-d/%y" ;;
						"yyyy-Www-d"|"Y-Www-d") date_format="%G-W%V-%u" ;;
						"yyyy-ww"|"Y-ww") date_format="%G-%V" ;;
						"yyyy-ww-d"|"Y-ww-d") date_format="%G-%V-%u" ;;
						"yyyy-mm-dd (ddd)"|"Y-mm-dd (ddd)") date_format="%Y-%m-%d (%a)" ;;
						"ddd, yyyy-mm-dd"|"ddd, Y-mm-dd") date_format="%a, %Y-%m-%d" ;;
						"ddd mm/dd/yyyy"|"ddd mm/dd/Y") date_format="%a %m/%d/%Y" ;;
						"hh:mm") date_format="%H:%M" ;;
						"hh:mm:ss") date_format="%H:%M:%S" ;;
						"h:mm:ss am/pm") date_format="%-I:%M:%S %p" ;;
						"hh:mm am/pm") date_format="%I:%M %p" ;;
						"h:mm am/pm") date_format="%-I:%M %p" ;;
						*) date_format="$2" ;; # Default to the provided format
					esac
					shift 2
					;;
			esac

			os_type=$(uname)

			if [ "$os_type" = "Darwin" ]; then
				parsed_date=$(gdate -d "$input" +"$date_format" 2>/dev/null)
			else
				parsed_date=$(gdate -d "$input" +"$date_format" 2>/dev/null)
			fi

			if [[ "$parsed_date" == "$input" ]]; then
				output="true"
			fi

			;;

		time)

			time_format="%H:%M"  # Default time format

			case $1 in
				--format)
					case $1 in
						"24-hour"|"hh:mm") time_format="%H:%M" ;;
						"24-hour-seconds"|"hh:mm:ss") time_format="%H:%M:%S" ;;
						"12-hour"|"hh:mm am/pm") time_format="%I:%M %p" ;;
						"12-hour-seconds"|"hh:mm:ss am/pm") time_format="%I:%M:%S %p" ;;
						*) time_format="$2" ;; # Use provided format
					esac
					shift 2
					;;
			esac

			normalized_input=$(echo "$input" | tr '[:lower:]' '[:upper:]')
				
			os_type=$(uname)
				
			if [ "$os_type" = "Darwin" ]; then
				parsed_time=$(gdate -j -f "$time_format" "$normalized_input" +"$time_format" 2>/dev/null)
			else
				parsed_time=$(gdate -d "$normalized_input" +"$time_format" 2>/dev/null)
			fi

			if [[ "$parsed_time" == "$normalized_input" ]]; then
				output="true"
			fi

			;;

		true-false|true/false)

			if [[ $input == "true" || $input == "false" ]]; then
				output="true"
			fi
			;;

		yes-no|yes/no)

			if [[ $input == "yes" || $input == "no" ]]; then
				output="true"
			fi
			;;

		0-1|0/1)

			if [[ $input == "0" || $input == "1" ]]; then
				output="true"
			fi
			;;

		boolean)

			if [[ $input == "true" || $input == "false" || $input == "yes" || $input == "no" || $input == "y" || $input == "n" || $input == "0" || $input == "1" ]]; then
				output="true"
			fi

			;;

		phone|phone-number)

			country="US"

			while true; do
				case $1 in
					--country) country="$2" && shift 2 ;;
					'') break ;;
					*) shift ;;
				esac
			done

			case $country in
				US) if echo "$input" | grep -Eq '^\+?1?[ -]?\(?\d{3}\)?[ -]?\d{3}[ -]?\d{4}$'; then output="true"; fi ;;
				CA) if echo "$input" | grep -Eq '^\+?1?[ -]?\(?\d{3}\)?[ -]?\d{3}[ -]?\d{4}$'; then output="true"; fi ;;
				*) echo "Unsupported country code: $country" ;;
			esac
			
			;;

		zip|zip-code|postal-code)

			country="US"  # Default country
			while true; do
				case $1 in
					--country) country="$2" && shift 2 ;;
					'') break ;;
					*) shift ;;
				esac
			done

			case $country in
				US) if echo "$input" | grep -Eq '^[0-9]{5}(-[0-9]{4})?$'; then output="true"; fi ;;
				CA) if echo "$input" | grep -Eq '^[A-Za-z]\d[A-Za-z] \d[A-Za-z]\d$'; then output="true"; fi ;;
				GB) if echo "$input" | grep -Eq '^(GIR 0AA|[A-Z]{1,2}[0-9R][0-9A-Z]? [0-9][A-Z]{2})$'; then output="true"; fi ;;
				*) echo "Unsupported country code: $country" ;;
			esac
			;;

		*)
			echo "Invalid type: $type"
			;;

	esac

	echo "$output"

}



function weather() {

	[[ -p /dev/stdin ]] && input=$(cat) || input="$1" && shift

	# detect if input is a lat,long
	if [[ $input =~ ^-?[0-9]+\.[0-9]+,-?[0-9]+\.[0-9]+$ ]]; then
		location=$input
	else
		location=$(geo "$input")
	fi

	cache_path="home/.cache/weather/$(codec text.filesafe "$location")"

	[[ $BARE_COLOR == '0' ]] && color='0' || color='1'

	remaining_args=() && while [[ $# -gt 0 ]]; do
		case $1 in
			--no-color|no-color) color='0' && shift ;;
			--concise|concise) json_requested='1'; concise='1' && shift ;;
			--json|json) json_requested='1'; json='1' && shift ;;
			--sunrise|sunrise) json_requested='1'; sunrise='1' && shift ;;
			--sunset|sunset) json_requested='1'; sunset='1' && shift ;;
			--moonrise|moonrise) json_requested='1'; moonrise='1' && shift ;;
			--moonset|moonset) json_requested='1'; moonset='1' && shift ;;
			--cloud-cover|--cloud-coverage|cloud-cover) json_requested='1'; cloud_cover='1' && shift ;;
			--at|at) json_requested='1'; time="$(date "$2" --format 'hh:mm')" && shift 2 ;;
			*) remaining_args+=("$1") && shift ;;
		esac
	done && set -- "${remaining_args[@]}"

	[[ $color == '0' ]] && color_code='T'

	[[ $json_requested == '1' ]] && {

		function cacheJSON() {
			json=$(curl -sL "wttr.in/$location?format=j1")
			mkdir -p home/.cache/weather
			echo "$json" > "$cache_path.json"
		}

		# check cache for json
		if [[ ! -f "$cache_path.json" ]]; then
			cacheJSON;
		else
			cache_age=$(age "$cache_path.json" --hours)
			if (( $(echo "$cache_age > 1" | bc -l) )); then
				cacheJSON;
			fi
		fi
		json=$(< "$cache_path.json")

		[[ $concise == '1' ]] && {
			echo "$json" | jq -r '.current_condition[0].weatherDesc[0].value'
		}

		[[ $sunrise == '1' ]] && {
			echo "$json" | jq -r '.weather[0].astronomy[0].sunrise'
		}

		[[ $sunset == '1' ]] && {
			echo "$json" | jq -r '.weather[0].astronomy[0].sunset'
		}

		[[ $moonrise == '1' ]] && {
			echo "$json" | jq -r '.weather[0].astronomy[0].moonrise'
		}

		[[ $moonset == '1' ]] && {
			echo "$json" | jq -r '.weather[0].astronomy[0].moonset'
		}

		[[ $cloud_cover == '1' ]] && {
			echo "$json" | jq -r '.current_condition[0].cloudcover'
		}

	}

	case $1 in
		today|--today)
			response=$(curl -sL "wttr.in/${location}?uQ${color_code}F1" | sed -n '/┌─────────────┐/,/└─────────────┘/p')
			cache_append=".today"
			;;
		tomorrow|--tomorrow)
			response=$(curl -sL "wttr.in/${location}?uQ${color_code}F2" | sed -n '/┌─────────────┐/,/└─────────────┘/p' | tail -n 10)
			cache_append=".tomorrow"
			;;
		forecast|--forecast)
			response=$(curl -sL "wttr.in/${location}?uQ${color_code}F3" | sed -n '/┌─────────────┐/,/└─────────────┘/p')
			cache_append=".forecast"
			;;
		* )
			response=$(curl -sL "wttr.in/${location}?uQ${color_code}F" | head -n 5)
			cache_append=".now"
	esac

	# if simple request, cache and respond now
	[[ -n $response ]] && {
		if [[ ! -f "${cache_path}${cache_append}" ]]; then
			mkdir -p home/.cache/weather
			echo "$response" > "${cache_path}${cache_append}"
		fi
	}

	# if no response, check cache
	[[ -z $response ]] && {
		if [[ -f "${cache_path}${cache_append}" ]]; then
			cat "${cache_path}${cache_append}"
		fi
	}

	echo "$response"

}



function write() {

	local contents args file

	# Read from stdin if not a terminal
	[[ -p /dev/stdin ]] && contents=$(cat)

	# Parse arguments
	args=() && while [[ $# -gt 0 ]]; do
		case $1 in
			--to) file="$2" && shift 2 ;;
			--contents) contents="$2" && shift 2 ;;
			*) args+=("$1") && shift ;;
		esac
	done && set -- "${args[@]}"

	# Handle positional arguments
	[[ $# -eq 1 && -n $file ]] && contents="$1"
	[[ $# -eq 1 && -n $contents ]] && file="$1"
	[[ $# -eq 2 ]] && { contents="$1"; file="$2"; }

	# Check for missing arguments
	[[ -z $contents ]] && echo "Error: Missing contents" >&2
	[[ -z $file ]] && echo "Error: Missing file" >&2

	# Clean carriage return characters from contents
	contents=$(echo "$contents" | tr -d '\r')

	# Write contents to the specified file
	echo "$contents" > "$file"

}



function youtube() {

	local command quality thumbnail_quality url

	command=$1 && shift

	[[ -t 0 ]] && url="$1" && shift || url=$(cat)

	quality="720" # Default quality for videos
	thumbnail_quality="0" # Default quality for thumbnails (0 for default hd)

	if [[ ! "$url" =~ ^(https?://)?(www\.)?(m\.)?(youtube\.com|youtu\.be|youtube-nocookie\.com) ]]; then
		echo "Invalid YouTube URL"
	fi

	# Ensure .downloads directory exists
	mkdir -p .var/downloads

	# Function to download video
	download_video() {

		local random_filename
		local output_path
		local final_output
		local relative_output

		random_filename=$(random string 32)
		output_path=".var/downloads/$random_filename"
		
		if [[ "$format" == "mp3" ]]; then
			final_output=$(yt-dlp --no-part -x --audio-format mp3 -o "$output_path.%(ext)s" --print after_move:filepath "$url" 2>/dev/null)
		else
			final_output=$(yt-dlp -f "bestvideo[height<=$quality]+bestaudio/best" -o "$output_path.%(ext)s" --print after_move:filepath "$url" 2>/dev/null)
		fi
		
		# Convert the full path to a relative path
		relative_output="${final_output#"$(pwd)/"}"
		
		if [ -f "$relative_output" ]; then
			echo "$relative_output"
		else
			echo "Error downloading video"
		fi

	}

	# Function to extract YouTube video ID
	function extract_id() {

		local url

		url=$1

		echo "$url" | awk -F'[?&/=]' '{
			for(i=1;i<=NF;i++) {
				if ($i == "v") {
					print $(i+1);
					exit
				}
				if ($i == "embed" || $i == "shorts" || $i == "youtu.be") {
					print $(i+1);
					exit
				}
			}
		}'

	}

	# Function to download thumbnail
	download_thumbnail() {

		local url
		local video_id
		local thumbnail_url
		local random_filename
		local output

		video_id=$(extract_id "$url")

		case "$thumbnail_quality" in
			"md") thumbnail_url="https://i.ytimg.com/vi/${video_id}/mqdefault.jpg" ;;
			"max") thumbnail_url="https://i.ytimg.com/vi/${video_id}/maxresdefault.jpg" ;;
			*) thumbnail_url="https://i.ytimg.com/vi/${video_id}/hqdefault.jpg" ;;
		esac

		random_filename=$(random string 32).jpg
		output_path=".var/downloads/$random_filename"
		curl -sL "$thumbnail_url" -o "$output_path"
		echo "$output_path"

	}

	case $command in
		download)
			while [[ $# -gt 0 ]]; do
				case $1 in
					--quality) quality=$2 && shift 2 ;;
					--mp3) format="mp3" && shift ;;
					--thumbnail|--thumb)
						shift && while [[ $# -gt 0 ]]; do
							case $1 in
								--md) thumbnail_quality="md" && shift ;;
								--max) thumbnail_quality="max" && shift ;;
								# *) echo "Unknown option: $1" >&2 ;;
							esac
						done && download_thumbnail "$url"
						;;
					# *) echo "Unknown option: $1" >&2 ;;
				esac
			done
			download_video
			;;

		id) extract_id ;;

		thumbnail)
			shift 2 # Remove the first two arguments
			while [[ $# -gt 0 ]]; do
				case $1 in
					--md) thumbnail_quality="md" && shift ;;
					--max) thumbnail_quality="max" && shift ;;
					# *) echo "Unknown option: $1" >&2 ;;
				esac
			done
			download_thumbnail
			;;

		*) echo "Unknown command: $command" >&2 ;;
		
	esac

	unset -f download_video
	unset -f extract_id
	unset -f download_thumbnail

}



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #


bareRunCommands

case $1 in

	'') : ;;
	-t|-i) runBareTerminal ;;
	--version|-v) cat .var/sync ;;
	--upgrade) git pull origin root ;;
	--setup) setup ;;
	*) [[ $(isValidFunc "$1") == 'true' ]] && "$@" ;;

esac
