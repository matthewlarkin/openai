#!/usr/bin/env bash

__deps() {

	local dep missing_deps i
	
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



__getOS() {

	OS="Other"
	case $(uname) in
		Linux) grep -q 'Ubuntu' /etc/os-release && OS="Ubuntu" ;;
		Darwin) OS="macOS";;
	esac
	export OS

}



__bareStartUp() {

	# Set the values in the associative array
	local -A BASE_CONFIG
	BASE_CONFIG=(
		
		# bare
		["BARE_VERSION"]=$(git log -1 --format=%ct)
		["BARE_TIMEZONE"]="${BARE_TIMEZONE:-UTC}"
		["BARE_COLOR"]="${BARE_COLOR:-0}"
		["BARE_DEBUG"]="${BARE_DEBUG:-0}"
		["BARE_STORAGE_PROVIDER"]="${BARE_STORAGE_PROVIDER:-digitalocean}"
		["EDITOR"]="${EDITOR:-code}"
		
		# Email via SMTP
		["SMTP_HOST"]="${SMTP_HOST:-}"
		["SMTP_PORT"]="${SMTP_PORT:-}"
		["SMTP_USERNAME"]="${SMTP_USERNAME:-}"
		["SMTP_PASSWORD"]="${SMTP_PASSWORD:-}"
		
		# Email via Postmark
		["POSTMARK_API_KEY"]="${POSTMARK_API_KEY:-}"

		# Misc APIs
		["OPENAI_API_KEY"]="${OPENAI_API_KEY:-}"
		["STRIPE_SECRET_KEY"]="${STRIPE_SECRET_KEY:-}"
		["AIRTABLE_ACCESS_TOKEN"]="${AIRTABLE_ACCESS_TOKEN:-}"
		["AIRTABLE_BASE_ID"]="${AIRTABLE_BASE_ID:-}"
		["TOMORROW_WEATHER_API_KEY"]="${TOMORROW_WEATHER_API_KEY:-}"
		["TINIFY_API_KEY"]="${TINIFY_API_KEY:-}" # Tiny PNG
		["DO_SPACES_ACCESS_KEY"]="${DO_SPACES_ACCESS_KEY:-}"
		["DO_SPACES_SECRET_KEY"]="${DO_SPACES_SECRET_KEY:-}"
		["DO_SPACES_ENDPOINT"]="${DO_SPACES_ENDPOINT:-}"
		["AWS_S3_API_KEY"]="${AWS_S3_API_KEY:-}"
		
		# remote sync server
		["BARE_REMOTE"]="${BARE_REMOTE:-}"
		["HETZNER_API_KEY"]="${HETZNER_API_KEY:-}"
		["DIGITALOCEAN_API_KEY"]="${DIGITALOCEAN_API_KEY:-}"
		["LINODE_API_KEY"]="${LINODE_API_KEY:-}"
		["VULTR_API_KEY"]="${VULTR_API_KEY:-}"
		
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

	# shellcheck disable=SC1090
	{
		[[ -f ~/.bash_profile ]] && source ~/.bash_profile
		[[ -f ~/.bashrc ]] && source ~/.bashrc
		[[ -f ~/.barerc ]] && source ~/.barerc
	}

	__getOS

	# shellcheck disable=SC1091
	source "$HOME/.barerc"

}


__checkVariables() {

	local variables logfile steps_required variables var

	steps_required='false'

	variables=(
		"OPENAI_API_KEY"
		"POSTMARK_API_KEY"
		"BARE_EMAIL_FROM"
		"STRIPE_SECRET_KEY"
		"EDITOR"
	)

	logfile="$BARE_DIR/.bare/.logs/system-report.$(date +%Y-%m-%d).md"

	echo ""
	echo "${BLUE}Checking core variables ...${RESET}"
	echo ""
	sleep 0.2

	echo "System Report $(date)" > "$logfile"
	echo "- - - - -" >> "$logfile"

	# Verify that core variables exist in $BARE_HOME/.barerc
	for var in "${variables[@]}"; do
		if ! grep -q "^$var=" "$BARE_HOME/.barerc"; then
			echo "$var=''" >> "$BARE_HOME/.barerc"
			sleep 0.2
			echo "- Variable *'$var'* is missing. It has been added with an empty value to *$BARE_HOME/.barerc*." >> "$logfile"
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



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

# HELPER FUNCTIONS


__isBareCommand() {

	local command function_names func

	command=$1
	mapfile -t function_names < <(declare -F | awk '{print $3}')

	for func in "${function_names[@]}"; do
		if [[ "$func" == "$command" ]]; then
			return 0
		fi
	done

	return 1

}



# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

# BARE FUNCTIONS



age() {
    # Determine if GNU date is available
    if date --version >/dev/null 2>&1; then
        date_cmd="date"
    elif command -v gdate >/dev/null 2>&1; then
        date_cmd="gdate"
    else
        echo "GNU date is required."
        return 1
    fi

    # Default values
    unit="seconds"
    variant="birth"
    display_date=false

    # Parse options
    while [[ $# -gt 0 ]]; do
        case "$1" in
			last|when|in|of) shift ;; # permits more lyrical commands
            --modified|modified) variant="modified"; shift ;;
            --years|years|--months|months|--weeks|weeks|--days|days|--hours|hours|--minutes|minutes|--seconds|seconds)
                unit="${1#--}"; shift ;;
            --date|date|--birth|birth) display_date=true; shift ;;
            *) input="$1"; shift ;;
        esac
    done

    # Check input
    if [[ -z "$input" ]]; then
        echo "Error: no input provided."
        return 1
    fi

    # Try to get timestamp from date input
    date_timestamp=$($date_cmd -d "$input" +%s 2>/dev/null)

    if [[ $? -eq 0 ]]; then
        # Input is a date string
        timestamp=$date_timestamp
    elif [[ -f "$input" ]]; then
        # Input is a file
        if [[ "$variant" == "modified" ]]; then
            timestamp=$(stat -c %Y "$input" 2>/dev/null || stat -f %m "$input")
        else
            # Try to get birth time, fallback to modified time
            timestamp=$(stat -c %W "$input" 2>/dev/null)
            if [[ -z "$timestamp" || "$timestamp" == "0" ]]; then
                timestamp=$(stat -c %Y "$input" 2>/dev/null || stat -f %B "$input")
            fi
        fi
    else
        echo "Invalid input: expected file or date."
        return 1
    fi

    if [[ "$display_date" == true ]]; then
        output=$($date_cmd -d "@$timestamp" +"%Y-%m-%d %H:%M:%S")
    else
        current_timestamp=$($date_cmd +%s)
        diff=$((current_timestamp - timestamp))
        case "$unit" in
            years)    output=$(awk "BEGIN {printf \"%.2f\", $diff/31536000}") ;;
            months)   output=$(awk "BEGIN {printf \"%.2f\", $diff/2592000}") ;;
            weeks)    output=$(awk "BEGIN {printf \"%.2f\", $diff/604800}") ;;
            days)     output=$(awk "BEGIN {printf \"%.2f\", $diff/86400}") ;;
            hours)    output=$(awk "BEGIN {printf \"%.2f\", $diff/3600}") ;;
            minutes)  output=$(awk "BEGIN {printf \"%.2f\", $diff/60}") ;;
            seconds)  output="$diff" ;;
        esac
    fi

    echo "$output"
}



airtable() {

	[[ -z $AIRTABLE_ACCESS_TOKEN ]] && echo "Error: AIRTABLE_ACCESS_TOKEN is not set." && return 1

	local input command subcommand args base_id table_name api_key command record_id filter limit offset response records new_records url view

	api_key=$AIRTABLE_ACCESS_TOKEN
	base_id=$AIRTABLE_BASE_ID

	args=() && while [[ $# -gt 0 ]]; do
		case $1 in
			--base-id|-b) base_id=$2 && shift 2 ;;
			--table|-t) table_name=$2 && shift 2 ;;
			--api-key|-k) api_key=$2 && shift 2 ;;
			--filter|-f) filter=$2 && shift 2 ;;
			--view|-v) view=$2 && shift 2 ;;
			--id|-i) record_id=$2 && shift 2 ;;
			--limit|-l) limit=$2 && shift 2 ;;
			--offset|-o) offset=$2 && shift 2 ;;
			*) args+=("$1") && shift ;;
		esac
	done
	set -- "${args[@]}"

	[[ -z $base_id ]] && echo "Error: base_id is required." && return 1
	[[ -z $table_name ]] && echo "Error: table_name is required." && return 1
	[[ -z $api_key ]] && echo "Error: api_key is required." && return 1

	command=$1 && shift

	if [[ -p /dev/stdin ]]; then input=$(cat); else input=$1 && shift; fi
	[[ -f $input ]] && input=$(cat "$input")

	case $command in

		list)

			limit=${limit-100}
			offset=""
			records=()
			
			while :; do
				url="https://api.airtable.com/v0/$base_id/$(codec url.encode "$table_name")?limit=$limit&offset=$offset"
				[[ -n "$filter" ]] && url="$url&filterByFormula=$(codec url.encode "$filter")"
				[[ -n "$view" ]] && url="$url&view=$(codec url.encode "$view")"
			
				response=$(curl -sL "$url" -H "Authorization: Bearer $api_key")
			
				# Check if the response contains records
				if [[ $(echo "$response" | jq '.records') != "null" ]]; then
					# Extract records and add to the array
					new_records=$(echo "$response" | jq -c '.records[] | {id: .id} + .fields | with_entries(.key |= gsub("[^a-zA-Z0-9_]"; "_"))')
					if [[ -n "$new_records" ]]; then
						records+=("$new_records")
					else
						break
					fi
				else
					break
				fi
			
				# Check if there's more data to fetch
				offset=$(echo "$response" | jq -r '.offset // empty')
				[[ -z "$offset" ]] && break
			
				# Rate limit: wait for 0.2 seconds before the next request
				sleep 0.2
			done
			
			# Output all records as a JSON array
			if [[ ${#records[@]} -gt 0 ]]; then
				echo "${records[@]}" | jq -s '.'
			else
				echo "[]"
			fi
		
			;;

		create)

			[[ -z $input ]] && echo "Error: no data provided." && return 1
		
			# Convert the input to the format expected by the Airtable API
			formatted_input=$(echo "$input" | jq -c '{records: map({fields: .})}')
		
			response=$(curl -sL "https://api.airtable.com/v0/$base_id/$(codec url.encode "$table_name")" \
				-H "Authorization: Bearer $api_key" \
				--json "$formatted_input")
		
			if [[ $(echo "$response" | jq -r '.error') == "null" ]]; then
				# Extract the record IDs
				echo "$response" | jq -r '.records[].id'
				return 0
			else
				echo "Error: $(echo "$response" | jq -r '.error')"
				return 1
			fi
			
			;;

		update|edit)
		
			[[ -z $input ]] && echo "Error: no data provided." && return 1
		
			# Convert the input to the format expected by the Airtable API
			formatted_input=$(echo "$input" | jq -c '.[0] | {fields: .}')
		
			[[ -z $record_id ]] && echo "Error: record_id is required." && return 1
		
			response=$(curl -sL -X PATCH "https://api.airtable.com/v0/$base_id/$(codec url.encode "$table_name")/$record_id" \
				-H "Authorization: Bearer $api_key" \
				-H "Content-Type: application/json" \
				--data "$formatted_input")
		
			if [[ $(echo "$response" | jq -r '.error') == "null" ]]; then
				echo "$response" | jq -r '.id'
				return 0
			else
				echo "Error: $(echo "$response" | jq -r '.error')"
				return 1
			fi
		
			;;

		delete)
		
			[[ -z $record_id ]] && echo "Error: record_id is required." && return 1

			response=$(
				curl -sL "https://api.airtable.com/v0/$base_id/$(codec url.encode "$table_name")/$record_id" \
					-X DELETE \
					-H "Authorization: Bearer $api_key"
			)

			if [[ $(echo "$response" | jq -r '.error') == "null" ]]; then
				echo "Record deleted successfully."
				return 0
			else
				echo "Error: $(echo "$response" | jq -r '.error')"
				return 1
			fi

			;;

		*) echo "Invalid command: $command" && return 1 ;;
	
	esac

}



cloud() {

	getCloudProvider() {

		[[ -n "$HETZNER_API_KEY" ]] && echo "hetzner" && exit 0
		[[ -n "$DIGITALOCEAN_API_KEY" ]] && echo "digitalocean" && exit 0
		[[ -n "$LINODE_API_KEY" ]] && echo "linode" && exit 0
		[[ -n "$VULTR_API_KEY" ]] && echo "vultr" && exit 0
		{
			echo "Error: no cloud provider set."
			echo ""
			echo "Requires one of:"
			echo -e "  - HETZNER_API_KEY\n  - DIGITALOCEAN_API_KEY\n  - LINODE_API_KEY\n  - VULTR_API_KEY"
		} >&2

	}

	# shellcheck disable=SC2317
	hetzner_info() {
		
		local json
		json=$(curl -sL -H "Authorization: Bearer $HETZNER_API_KEY" \
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
	hetzner_createSSH() {

		local public_key name response

		public_key=${1-""}
		name=${2-"$(random string)"}

		if [[ -z $public_key ]]; then
			echo "Error: public_key is required." >&2
		fi

		response=$(curl -sL -X POST \
			-H "Authorization: Bearer $HETZNER_API_KEY" \
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
	hetzner_listSSH() {
		# only return: .ssh_keys[], and .id, .public_key
		curl -sL -H "Authorization: Bearer $HETZNER_API_KEY" \
			"https://api.hetzner.cloud/v1/ssh_keys" | jq '[.ssh_keys[] | {id: .id, name: .name, pub: .public_key}]' | rec --from-json
	}

	# shellcheck disable=SC2317
	hetzner_createFirewall() {

		local name rules response

		name=$1
		rules=$2

		response=$(
			curl -sL -X POST \
				-H "Authorization: Bearer $HETZNER_API_KEY" \
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
	hetzner_listFirewalls() {
		:
	}

	# shellcheck disable=SC2317
	hetzner_createServer() {

		local name key response

		name=$1
		key=$2

		response=$(
			curl -sL -X POST \
				-H "Authorization: Bearer $HETZNER_API_KEY" \
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




codec() {

	local input command index json_array output lines line start end reverse_flag

	command=$1 && shift

	if [[ -p /dev/stdin ]]; then input=$(cat); else input=$1 && shift; fi

	case $command in

		encrypt)

			local pass output_file
			# Parse arguments
			args=()
			{
				while [[ $# -gt 0 ]]; do
					case $1 in
						with|and|to) shift ;; # permits more lyrical commands
						--pass|-p|pass|password) pass=$2; shift 2 ;;
						--output|-o|output) output_file=$2; shift 2 ;;
						*) args+=("$1") && shift ;;
					esac
				done
			}
			set -- "${args[@]}"

			# Check if the input is a file
			[[ -f $input ]] && input=$(cat "$input")

			[[ -z $pass ]] && echo "Error: --pass is required." && return 1

			# Encrypt using OpenSSL and base64 encode the result
			encrypted=$(echo -n "$input" | openssl enc -aes-256-cbc -pbkdf2 -pass pass:"$pass" -base64)

			# Output the encrypted data
			if [[ -n $output_file ]]; then
				echo "$encrypted" > "$output_file"
			else
				echo "$encrypted"
			fi

			;;

		decrypt)

			local pass output_file
			# Parse arguments
			args=()
			{
				while [[ $# -gt 0 ]]; do
					case $1 in
						with|and|to) shift ;; # permits more lyrical commands
						--pass|-p|pass|password) pass=$2; shift 2 ;;
						--output|-o|output) output_file=$2; shift 2 ;;
						*) args+=("$1") && shift ;;
					esac
				done
			}
			set -- "${args[@]}"

			# if $input is a file, read the file
			[[ -f $input ]] && input=$(cat "$input")

			[[ -z $pass ]] && echo "Error: --pass is required." && return 1

			# Decode from base64 and decrypt using OpenSSL
			decrypted=$(echo -n "$input" | base64 -d | openssl enc -d -aes-256-cbc -pbkdf2 -pass pass:"$pass")

			# Output the decrypted data
			if [[ -n $output_file ]]; then
				echo "$decrypted" > "$output_file"
			else
				echo "$decrypted"
			fi
			;;


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
			if echo -n "$input" | jq empty 2>/dev/null; then
				handle_json_string "$input"
			else
				convert_to_json_array "$input"
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



color() {

    local input hue saturation=100 lightness=50 output_format output_style

    # Capture input
    [[ -p /dev/stdin ]] && input=$(cat)

    # Parse arguments
	args=() && while [[ $# -gt 0 ]]; do
        case $1 in
            --hue|-h) hue=$2; shift 2 ;;
            --saturation|-s) saturation=$2; shift 2 ;;
            --lightness|-l) lightness=$2; shift 2 ;;
            --hsl) output_format="hsl"; shift ;;
            --hex) output_format="hex"; shift ;;
            --rgb) output_format="rgb"; shift ;;
            --raw) output_style="raw"; shift ;;
			*) args+=("$1") && shift ;;
        esac
    done
	set -- "${args[@]}"

	# Use the input if no arguments are provided
	[[ -z $input ]] && input=$1

    # Map color aliases to hue values if hue is not provided and input is not empty
	case $input in
		red) hue=0 ;;
		vermilion) hue=15 ;;
		orange) hue=30 ;;
		amber) hue=45 ;;
		yellow) hue=60 ;;
		lime) hue=75 ;;
		chartreuse) hue=90 ;;
		harlequin ) hue=105 ;;
		green) hue=120 ;;
		teal) hue=135 ;;
		springgreen) hue=150 ;;
		turquoise) hue=165 ;;
		cyan) hue=180 ;;
		skyblue) hue=195 ;;
		azure) hue=210 ;;
		blue) hue=235 ;;
		hanblue) hue=250 ;;
		indigo) hue=265 ;;
		violet) hue=280 ;;
		purple) hue=295 ;;
		magenta) hue=310 ;;
		cerise) hue=325 ;;
		rose) hue=340 ;;
		white) hue=0; saturation=0; lightness=100 ;;
		black) hue=0; saturation=0; lightness=0 ;;
		gray) hue=0; saturation=0; lightness=50 ;;
		lightgray|silver) hue=0; saturation=0; lightness=75 ;;
		darkgray|stone|tundora) hue=0; saturation=0; lightness=25 ;;
	esac

    # Function to convert HSL to RGB using awk
    hsl_to_rgb() {
        awk -v H="$1" -v S="$2" -v L="$3" '
        function hue2rgb(p, q, t) {
            if (t < 0) t += 1
            if (t > 1) t -= 1
            if (t < 1/6) return p + (q - p) * 6 * t
            if (t < 1/2) return q
            if (t < 2/3) return p + (q - p) * (2/3 - t) * 6
            return p
        }
        BEGIN {
            h = H / 360
            s = S / 100
            l = L / 100

            if (s == 0) {
                r = g = b = l
            } else {
                if (l < 0.5)
                    q = l * (1 + s)
                else
                    q = l + s - l * s
                p = 2 * l - q
                r = hue2rgb(p, q, h + 1/3)
                g = hue2rgb(p, q, h)
                b = hue2rgb(p, q, h - 1/3)
            }

            printf "%d %d %d\n", int(r * 255 + 0.5), int(g * 255 + 0.5), int(b * 255 + 0.5)
        }'
    }

    # Function to convert RGB to HEX
    rgb_to_hex() {
        if [[ $output_style == "raw" ]]; then
            printf "%02x %02x %02x\n" "$1" "$2" "$3"
        else
            printf "#%02X%02X%02X\n" "$1" "$2" "$3"
        fi
    }

    # Output based on the specified format
    if [[ "$output_format" == "hex" ]]; then
        read -r R G B <<< "$(hsl_to_rgb "$hue" "$saturation" "$lightness")"
        rgb_to_hex "$R" "$G" "$B"
    elif [[ "$output_format" == "rgb" ]]; then
        read -r R G B <<< "$(hsl_to_rgb "$hue" "$saturation" "$lightness")"
        if [[ "$output_style" == "raw" ]]; then
            echo "$R $G $B"
        else
            echo "rgb($R, $G, $B)"
        fi
    elif [[ "$output_format" == "hsl" ]]; then
        if [[ "$output_style" == "raw" ]]; then
            echo "$hue $saturation $lightness"
        else
            echo "hsl($hue, $saturation%, $lightness%)"
        fi
    else
        read -r R G B <<< "$(hsl_to_rgb "$hue" "$saturation" "$lightness")"
        rgb_to_hex "$R" "$G" "$B"
    fi
}



date() {
    local input args date_cmd date_format input_format custom_format format_parts timezone

    date_cmd="date"

    # Default timezone
    timezone="$BARE_TIMEZONE"

    # Determine the correct date command based on the operating system
    [[ "$OS" == "macOS" ]] && date_cmd="gdate"

    date_format="%Y-%m-%d %H:%M:%S"
    input_format="%Y-%m-%d %H:%M:%S"

    # Timezone abbreviation to full timezone mapping
    declare -A timezone_map=(
		["GMT"]="GMT"
		["UTC"]="UTC"
		["BST"]="Europe/London"
		["IST"]="Asia/Kolkata"
		["CET"]="Europe/Paris"
		["CEST"]="Europe/Paris"
		["EASTERN"]="America/New_York"
        ["EST"]="America/New_York"
        ["EDT"]="America/New_York"
		["CENTRAL"]="America/Chicago"
        ["CST"]="America/Chicago"
        ["CDT"]="America/Chicago"
		["MOUNTAIN"]="America/Denver"
        ["MST"]="America/Denver"
        ["MDT"]="America/Denver"
		["PACIFIC"]="America/Los_Angeles"
        ["PST"]="America/Los_Angeles"
        ["PDT"]="America/Los_Angeles"
		["New York"]="America/New_York"
		["Chicago"]="America/Chicago"
		["Denver"]="America/Denver"
		["Los Angeles"]="America/Los_Angeles"
		["Anchorage"]="America/Anchorage"
		["Honolulu"]="Pacific/Honolulu"
    )

    # Process arguments
    args=() && while [[ $# -gt 0 ]]; do
        case $1 in
            as|format|-F|--format|--formatted)
                custom_format=1 && shift
                read -r -a format_parts <<< "$1"
                date_format=""
                for part in "${format_parts[@]}"; do
                    case $part in
                        'U') date_format+="%s " ;;  # 1628841600
                        'Y-M-D') date_format+="%Y-%m-%d " ;;  # 2024-08-13
                        'M-D-Y') date_format+="%m-%d-%Y " ;;  # 08-13-2024
                        'M/D/Y') date_format+="%m/%d/%Y " ;;  # 08/13/2024
                        'Y-m-d') date_format+="%Y-%-m-%-d " ;; # 2024-8-13
                        'y-m-d') date_format+="%y-%-m-%-d " ;; # 24-8-13
                        'm-d-Y') date_format+="%-m-%-d-%Y " ;;  # 8-13-2024
                        'm-d-y') date_format+="%-m-%-d-%y " ;;  # 8-13-24
                        'm/d/Y') date_format+="%-m/%-d/%Y " ;;  # 8/13/2024
                        'm/d/y') date_format+="%-m/%-d/%y " ;;  # 8/13/24
                        # times
                        'H:M:S'|'H:m:s') date_format+="%H:%M:%S " ;; # 14:30:00
                        'H:M'|'H:m') date_format+="%H:%M " ;; # 14:30
                        'h:m:s'|'h:M:S'|'h:M:s'|'h:m:S') date_format+="%-I:%M:%S %p " ;; # 2:30:00 PM
                        'h:m'|'h:M') date_format+="%-I:%M %p " ;; # 2:30 PM
                        *) date_format+="$part " ;;
                    esac
                done
                shift && date_format="${date_format% }"  # Remove trailing space
                ;;
            --timezone|-T)
                shift
                timezone="$1"
				timezone_upper=$(echo "$timezone" | tr '[:lower:]' '[:upper:]')
				if [[ -n "${timezone_map[$timezone_upper]}" ]]; then
					timezone="${timezone_map[$timezone_upper]}"
				fi
                shift
                ;;
            *) args+=("$1") && shift ;;
        esac
    done

    # Set the remaining arguments
    set -- "${args[@]}"
    
    if [[ -p /dev/stdin ]]; then input=$(cat); else input=$1; fi

    # If no arguments or input, default to today's date
    [[ -z $input && $# -eq 0 ]] && input=$(TZ=$timezone $date_cmd +"%Y-%m-%d %H:%M:%S")
    [[ -z $input ]] && input="$1"

    today=$(TZ=$timezone $date_cmd +"%Y-%m-%d")

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

    # Format and print the date using the specified format, or default to standard
    if [[ $custom_format == 1 ]]; then
        TZ=$timezone $date_cmd -d "$input" +"$date_format"
    else
        TZ=$timezone $date_cmd "$@"
    fi
}



download() {

	__deps curl

	local url args output

	[[  -p /dev/stdin ]] && url=$(cat) || { url=$1 && shift; }

	output=$(random)

	args=() && while [[ $# -gt 0 ]]; do
		case $1 in
			--output|-o) output=$2; shift 2 ;;
			*) url=$1 && shift ;;
		esac
	done
	set -- "${args[@]}"

	[[ -z $url ]] && echo "No URL provided" && return 1

	[[ $(validate url "$url") == 'false' ]] && echo "Invalid URL" && return 1

	curl -sL "$url" > "$output"

}



email() {

	__deps jq curl

	local args via from to subject body cc bcc reply_to template attachments

	via='smtp'
	attachments=()

	args=() && while [[ $# -gt 0 ]]; do
		case $1 in
			--via|-v) via="$2"; shift 2 ;;
			--to|-t|to) to="$2"; shift 2 ;;
			--subject|-s|regarding|subject) subject="$2"; shift 2 ;;
			--body|-b|body) body="$2"; shift 2 ;;
			--cc|cc) cc="$2"; shift 2 ;;
			--bcc|bcc) bcc="$2"; shift 2 ;;
			--from|-f|from) from="$2"; shift 2 ;;
			--reply-to|-r|reply-to) reply_to="$2"; shift 2 ;;
			--attachment|-a|attachment) [[ -f "$2" ]] && attachments+=($(realpath "$2")) && shift 2 ;;
			with|and) shift ;; # allows for more lyrical commands
			*) args+=("$1") && shift ;;
		esac
	done
	set -- "${args[@]}"

	attachments=$(IFS=','; echo "${attachments[*]}")

	# require to, from, subject, body
	[[ -z "$to" ]] && echo "No recipient specified, use --to to specify a recipient" && return 1
	[[ -z "$subject" ]] && echo "No subject specified, use --subject to specify a subject" && return 1
	[[ -z "$body" ]] && echo "No body specified, use --body to specify a body" && return 1

	case $via in

		smtp)
				
			[[ -z "$SMTP_SERVER" ]] && echo "SMTP_SERVER is not set" && return 1
			[[ -z "$SMTP_PORT" ]] && echo "SMTP_PORT is not set" && return 1
			[[ -z "$SMTP_USERNAME" ]] && echo "SMTP_USERNAME is not set" && return 1
			[[ -z "$SMTP_PASSWORD" ]] && echo "SMTP_PASSWORD is not set" && return 1
		
			# Setup mail txt file for curl
			mail_file=$(mktemp)
			chmod 600 "$mail_file"  # Restrict permissions for security
		
			# Create the email headers and body
			{
				echo "From: $SMTP_USERNAME"
				echo "To: $to"
				echo "Cc: $cc"
				echo "Bcc: $bcc"
				echo "Reply-To: $reply_to"
				echo "Subject: $subject"
				echo "MIME-Version: 1.0"
				echo "Content-Type: multipart/mixed; boundary=\"boundary42\""
				echo ""
				echo "--boundary42"
				echo "Content-Type: text/plain; charset=UTF-8"
				echo "Content-Transfer-Encoding: 7bit"
				echo ""
				echo "$body"
			} >> "$mail_file"
		
			# Add attachments if any
			if [[ -n "$attachments" ]]; then
				IFS=',' read -ra files <<< "$attachments"
				for file in "${files[@]}"; do
					if [[ -f "$file" ]]; then
						absolute_path=$(realpath "$file")
						{
							echo ""
							echo "--boundary42"
							echo "Content-Type: $(file --mime-type -b "$absolute_path")"
							echo "Content-Transfer-Encoding: base64"
							echo "Content-Disposition: attachment; filename=\"$(basename "$absolute_path")\""
							echo ""
							base64 -i "$absolute_path"
						} >> "$mail_file"
					else
						echo "Error: '$file' is not a valid file." >&2
						rm "$mail_file"
						return 1
					fi
				done
			fi
		
			# End the MIME message
			{
				echo ""
				echo "--boundary42--"
			} >> "$mail_file"
		
			# Send email and capture the exit status
			curl -s --url "smtp://$SMTP_SERVER:$SMTP_PORT" --ssl-reqd \
				--mail-from "$SMTP_USERNAME" --mail-rcpt "$to" \
				--upload-file "$mail_file" --user "$SMTP_USERNAME:$SMTP_PASSWORD"
			curl_exit_code=$?
		
			# Cleanup
			rm "$mail_file"
		
			# Check for curl success
			if [[ $curl_exit_code -ne 0 ]]; then
				echo "Failed to send email, curl returned exit code $curl_exit_code"
				return $curl_exit_code
			fi
		
			;;


		postmark)

			[[ -z "$POSTMARK_API_KEY" ]] && {
				echo "POSTMARK_API_KEY is not set"
			}

			[[ -n "$template" ]] && body=$(render "$template" "$@" --to-html);

			# Single email mode
			[[ -z "$to" ]] && echo "No recipient specified, use --to to specify a recipient"
			[[ -z "$subject" ]] && echo "No subject specified, use --subject to specify a subject"
			[[ -z "$body" ]] && echo "No body specified, use --body to specify a body"

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

			response=$(curl -s "https://api.postmarkapp.com/email" \
				-H "Accept: application/json" \
				-H "Content-Type: application/json" \
				-H "X-Postmark-Server-Token: $POSTMARK_API_KEY" \
				-d "$payload")

			echo "$response" | jq -r '.MessageID'
		
			;;

		*) echo "Invalid email service: $via" && return 1 ;;

	esac

}



examine() {

	__deps jq ffmpeg ffprobe file stat realpath

    local args input tmp_dir cover_image_path mime_type file_size_human metadata pick ffprobe_output
    local filepath filename basename extension file_size

	[[ -p /dev/stdin ]] && input=$(cat)

	args=() && while [[ $# -gt 0 ]]; do
		case $1 in
			--json) args+=("$1") && shift ;;
			--pick|-p) pick=$2 && shift 2 ;;
			*) input=$1 && shift ;;
		esac
	done
	set -- "${args[@]}"

	[[ -z "$input" ]] && input=$1
	[[ -z "$input" ]] && echo "No input file provided" && return 1
	[[ ! -f "$input" ]] && echo "File not found: $input" && return 1

    # Get basic file information
    filepath=$(realpath "$input")
    filename=$(basename "$input")
    extension="${filename##*.}"
    basename="${filename%.*}"

    # Get the MIME type of the file
    mime_type=$(file --mime-type -b "$input")

    # Get the file size in bytes
    if [[ "$OSTYPE" == "darwin"* ]]; then
        file_size=$(stat -f%z "$input")
    else
        file_size=$(stat -c%s "$input")
    fi

    # Convert file size to a human-readable format
    human_readable_size() {
        local size=$1
        local units=("B" "KB" "MB" "GB" "TB")
        local unit_index=0

        while (( size >= 1024 && unit_index < ${#units[@]} - 1 )); do
            size=$(( size / 1024 ))
            unit_index=$(( unit_index + 1 ))
        done

        echo "$size ${units[$unit_index]}"
    }

    file_size_human=$(human_readable_size "$file_size")

    # Initialize metadata JSON object
    metadata=$(jq -n \
        --arg filepath "$filepath" \
        --arg filename "$filename" \
        --arg basename "$basename" \
        --arg extension "$extension" \
        --arg type "$mime_type" \
        --arg size "$file_size_human" \
        '{
            filename: $filename,
            basename: $basename,
            ext: $extension,
            path: $filepath,
            type: $type,
            size: $size
        }'
    )

    # Try to extract media metadata if possible
    ffprobe_output=$(ffprobe -v quiet -print_format json -show_format "$input" 2>/dev/null)

    if [[ -n "$ffprobe_output" ]]; then
        # Extract metadata fields
        media_metadata=$(echo "$ffprobe_output" | jq -r '{
            title: .format.tags.title,
            artist: .format.tags.artist,
            album: .format.tags.album,
            track: .format.tags.track,
            year: .format.tags.date
        } | with_entries(select(.value != null and .value != ""))')

        # Merge media metadata into main metadata
        metadata=$(echo "$metadata" "$media_metadata" | jq -s '.[0] * .[1]')

        # Try to extract cover image
        tmp_dir=$(mktemp -d)
        cover_image_path="$tmp_dir/cover.jpg"
        ffmpeg -i "$input" -an -vcodec copy "$cover_image_path" -y -loglevel quiet

        if [[ -f "$cover_image_path" ]]; then
            metadata=$(echo "$metadata" | jq --arg cover "$cover_image_path" '. + {cover: $cover}')
        else
            rm -rf "$tmp_dir"
        fi
    fi

	output=$(echo "$metadata" | jq '.' | bare.sh rec --from-json)

	if [[ -n $pick ]]; then
		echo "$output" | recsel -P "$pick"
	else
		echo "$output"
	fi

    # Clean up temporary directory if it exists
    [[ -d "$tmp_dir" ]] && rm -rf "$tmp_dir"

}



geo() {

	__deps curl jq

	touch "$BARE_DIR/.bare/cache/geo.txt"

	format_location() {
		local loc="$1"

		if [[ -z "$loc" ]]; then
			loc=$(curl -sL https://ipinfo.io/ip)
		else
			loc=$(echo "$loc" | sed -e 's/, /+/g' -e 's/ /+/g')
		fi

		echo "$loc"
	}

	local location type decimals coordinates args

	args=() && while [[ $# -gt 0 ]]; do
		case $1 in
			--decimals) decimals="$2"; shift 2 ;;
			--type) type="$2"; shift 2 ;;
			--location) location="$2"; shift 2 ;;
			*) args+=("$1"); shift ;;
		esac
	done
	set -- "${args[@]}"

	# Set defaults
	[[ -z "$location" ]] && location=${1:-asheville-nc}
	[[ -z "$type" ]] && type="city"
	[[ -z "$decimals" ]] && decimals=2

	location=$(format_location "$location")
	[[ $location =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && type="ip" || type="city"

	# Check if the location is in the geo.txt file
	if grep -q "^$location " "$BARE_DIR/.bare/cache/geo.txt"; then
		# If the location is in the file, get the coordinates from the file
		coordinates=$(grep "^$location " "$BARE_DIR/.bare/cache/geo.txt" | cut -d ' ' -f 2)
	else
		# If the location is not in the file, fetch the coordinates from the API
		if [[ "$type" == "city" ]]; then
			coordinates=$(curl -s "https://nominatim.openstreetmap.org/search?format=json&q=$location" | jq -r '.[0].lat + "," + .[0].lon' | awk -F, '{printf "%.6f,%.6f\n", $1, $2}')
		else
			coordinates=$(curl -s "https://ipinfo.io/$location" | jq -r '.loc' | awk -F, '{printf "%.6f,%.6f\n", $1, $2}')
		fi

		# Add the location and coordinates to the geo.txt file
		echo "$location $coordinates" >> "$BARE_DIR/.bare/cache/geo.txt"
	fi

	# Format the coordinates to the requested number of decimal places
	coordinates=$(echo "$coordinates" | awk -v decimals="$decimals" -F, '{printf "%.*f,%.*f\n", decimals, $1, decimals, $2}')

	# Output the coordinates
	echo "$coordinates"

	unset -f format_location

}



image() {

	local command input output_filename aspect_ratio focal_orientation overwrite_mode gravity height blur_radius degrees option output_extension args arg to extension base_name return prompt

	__deps magick

	command=$1 && shift

	if [[ -p /dev/stdin ]]; then input=$(cat); else { input=$1; shift; }; fi

	[[ -f "$input" ]] || { echo "Error: File '$input' not found." >&2; return 1; }
		
	extension=${input##*.}
	base_name=${input%.*}

	return='filepath'

	output_filename="$(random string 30).$extension"

	args=() && while [[ $# -gt 0 ]]; do
		case $1 in
			--height|-h) height="$2" && shift 2 ;;
			--width|-w) width="$2" && shift 2 ;;
			--output|-o|to) output_filename="$2" && shift 2 ;;
			--return|-r) return="$2" && shift 2 ;; # can return 'filepath' or 'url'
			--focal) focal_orientation="$2" && shift 2 ;;
			--aspect) aspect_ratio="$2" && shift 2 ;;
			--prompt) prompt="$2" && shift 2 ;;
			*) args+=("$1") && shift ;;
		esac
	done
	set -- "${args[@]}"

	case $command in

		compress|minify|tinify )

			local url response file

			[[ -z "$TINIFY_API_KEY" ]] && echo "TINIFY_API_KEY is not set" && return 1

			# Check if the input is a file
			[[ ! -f "$input" ]] && echo "Error: File '$input' not found." && return 1

			# Compress the image using the TinyPNG API
			
			response=$(curl -sL https://api.tinify.com/shrink \
				--data-binary @"$input" \
				--user "api:$TINIFY_API_KEY")

			url=$(echo "$response" | jq -r '.output.url')

			if [[ $return == 'url' ]]; then
				
				echo "$url"
				return 0

			else

				file=$(download "$url" --output "$output_filename" < /dev/null)
			
				[[ -n $file ]] && echo "$file" && return 0
				
				echo "Failed to compress image: $response" && return 1

			fi

			;;

		create|yield )

			local color dimensions filename

			color=$input
			dimensions=${1:-250x250}
			filename=${2:-${color}_$dimensions.webp}

			magick -size "$dimensions" "xc:${color}" "$filename"

			;;

		crop )

			aspect_ratio=${aspect_ratio:-3:2}
			focal_orientation=${focal_orientation:-center}
			overwrite_mode=$1

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

			output_filename="$option"
			magick "$input" "$output_filename" && echo "$output_filename" || echo "Failed to process $input"
			;;

		resize )
		
			[[ -z "$height" && -z "$width" ]] && {
				if [[ -n $1 ]]; then
					height=$1;
				else
					echo "Error: Height or width must be provided." >&2;
					return 1;
				fi
			}
		
			# Resize the image based on the provided dimensions
			if [[ -n "$height" && -n "$width" ]]; then
				if magick "$input" -resize "${width}x${height}!" "$output_filename"; then
					echo "$output_filename"
				else
					echo "Failed to process $input" >&2 && return 1
				fi
			elif [[ -n "$height" ]]; then
				if magick "$input" -resize x"$height" "$output_filename"; then
					echo "$output_filename"
				else
					echo "Failed to process $input" >&2 && return 1
				fi
			elif [[ -n "$width" ]]; then
				if magick "$input" -resize "$width"x "$output_filename"; then
					echo "$output_filename"
				else
					echo "Failed to process $input" >&2 && return 1
				fi
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

		describe )

			# requires OPENAI_API_KEY
			[[ -z "$OPENAI_API_KEY" ]] && echo "OPENAI_API_KEY is not set" && return 1

			image_basename=$(basename "$input")

			# if input is a file, upload it to the storage service
			if [[ -f "$input" ]]; then
				image_url=$(bare.sh storage upload "$input" --to openai/descriptions/"$image_basename" < /dev/null)
			elif [[ $(validate url "$input") == 'true' ]]; then
				image_url="$input"
			else
				echo "Error: Invalid input" >&2
				return 1
			fi

			[[  -z "$image_url" ]] && echo "Error: Invalid image URL" && return 1

			prompt=${prompt:-"Briefly describe the image."}
		
			# Prepare the JSON payload
			json_payload=$(jq -n --arg image_url "$image_url" --arg prompt "$prompt" '{
				"model": "gpt-4o",
				"messages": [
					{
						"role": "user",
						"content": [
							{
								"type": "text",
								"text": $prompt
							},
							{
								"type": "image_url",
								"image_url": {
									"url": $image_url
								}
							}
						]
					}
				],
				"max_tokens": 500
			}')
		
			# Send the request to the API
			response=$(curl -s https://api.openai.com/v1/chat/completions \
				-H "Content-Type: application/json" \
				-H "Authorization: Bearer $OPENAI_API_KEY" \
				-d "$json_payload")

			echo "$response" | jq -r '.choices[0].message.content'

			;;

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

			# usage: image blur <input> [blur_radius]

			blur_radius="${1:-5}"  # Default blur radius is 5 if not provided

			args=()
			{
				while [[ $# -gt 0 ]]; do
					case $1 in
						--radius|-r) blur_radius="$2" && shift 2 ;;
						*) args+=("$1") && shift ;;
					esac
				done
			}
			set -- "${args[@]}"

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



math() {

	local operation
	local output

	remaining_args=() && while [[ $# -gt 0 ]]; do
		case $1 in
			round|floor|ceiling|ceil) operation=$1 && shift ;;
			*) remaining_args+=("$1") && shift ;;
		esac
	done
	set -- "${remaining_args[@]}"

	if [[ -p /dev/stdin ]]; then input=$(cat); else input=$1 && shift; fi

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



media() {

	local command input args tmp_dir cover_image_path metadata title album artist output year track cover remove_original ffmpeg_command

	__deps ffmpeg

	command=$1 && shift

	if [[ -p /dev/stdin ]]; then input=$(cat); else input=$1 && shift; fi

	args=() && while [[ $# -gt 0 ]]; do
		case $1 in
			--cleanup) remove_original=1 && shift ;;
			--input|-i|input) input_file="$2" && shift 2 ;;
			--output|-o|output|--to|-t|to) output_file="$2" && shift 2 ;;
			*) args+=("$1") && shift ;;
		esac
	done
	set -- "${args[@]}"

	case $command in
		
		detail)
		
			# takes a given mp3 file and adds metadata (album artwork, title, composer, etc) via ffmpeg
			[[ ! -f $input ]] && echo "Error: expected file input"
		
			# now, examine the file in case some of these
			# are already set and use those as default
			title=$(media examine "$input" | recsel -P title)
			album=$(media examine "$input" | recsel -P album)
			artist=$(media examine "$input" | recsel -P artist)
			output=$input
		
			args=() && while [[ $# -gt 0 ]]; do
				case $1 in
					--title) title="$2" && shift 2 ;;
					--album) album="$2" && shift 2 ;;
					--year) year="$2" && shift 2 ;;
					--artist) artist="$2" && shift 2 ;;
					--cover) cover="$2" && shift 2 ;;
					--track) track="$2" && shift 2 ;;
					--output) output="$2" && shift 2 ;;
					*) args+=("$1") && shift ;;
				esac
			done
			set -- "${args[@]}"
			
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
			output="$(random string 32).$1"
			
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
			output="${3:-$(random string 32).$extension}"
			
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



open() {

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



openai() {

	[[ -z "$OPENAI_API_KEY" ]] && {
		echo ""
		echo -e " ${RED}Error${RESET}: OPENAI_API_KEY is not set"
		read -r -p " ⚙️ Set now? (y/n): " response
		[[ $response == 'y' ]] && {
			read -r -s -p " ⚙️ Enter your OpenAI API key: " OPENAI_API_KEY
			echo ""
			echo "OPENAI_API_KEY=$OPENAI_API_KEY" >> "$BARE_HOME/.barerc" && sleep 0.4
			echo " ⚙️ OPENAI_API_KEY set! You can now use OpenAI in bare."
			echo ""
			return 0
		}
	}

	local args command input assistant_prompt
	local assistant_name json_mode debug mode thread_title

	[[ -p /dev/stdin ]] && input=$(cat)

	# set defaults
	command="chat"
	assistant_prompt="You are a helpful assistant. Unless told otherwise, you respond succinctfully yet informatively. You are a good listener and a good communicator.";

	# capture assistant name
	args=() && while [[ "$#" -gt 0 ]]; do
		case $1 in
			--json) json_mode=1 && shift ;;
			--debug) debug='true' && shift ;;
			--high-powered) mode='high-powered'; shift 2 ;;
			--system_prompt|--instructions) assistant_prompt="$2" && shift 2 ;;
			*) args+=("$1"); shift ;;
		esac
	done
	set -- "${args[@]}"

	args=() && for arg in "$@"; do
		case $arg in
			chat|voice|listen|transcribe) command=$arg && shift ;;
			*) args+=("$arg") && shift ;;
		esac
	done
	set -- "${args[@]}"

	[[ -z "$input" ]] && input=$1 && shift
	if [[ -z "$input" ]]; then echo "Error: no input provided" >&2 && return 1; fi

	case $command in 

		chat )

			local model system_prompt thread_title payload response

			# Initialize variables
			if [[ $mode == 'high-powered' ]]; then
				model="gpt-4o"
			else
				model=${OPENAI_DEFAULT_MODEL:-'gpt-4o-mini'}
			fi
			system_prompt="$assistant_prompt"
			
			# Parse command-line arguments
			while [[ "$#" -gt 0 ]]; do
				case $1 in
					--model) model="$2" && shift 2 ;;
					--system_prompt|--instructions) system_prompt="$2" && shift 2 ;;
					*) echo "Invalid option: $1" >&2 ;;
				esac
			done

			[[ -n $json_mode ]] && system_prompt="$system_prompt. Return as a raw JSON object (not a json code block). If the user does not specify a property to put the response in, put the response in a property named 'response'. IMPORTANT: DO NOT RETURN A MARKDOWN CODE BLOCK; RETURN A VALID JSON STRING."
			
			# Construct the final JSON string using jq
			payload=$(jq -n --arg model "$model" --arg system_prompt "$system_prompt" --arg input "$input" '{
				model: $model,
				messages: [
					{role: "system", content: $system_prompt},
					{role: "user", content: $input}
				]
			}')

			# if json_mode append "response_format": { "type": "json_object" } to payload
			[[ -n $json_mode ]] && payload=$(echo "$payload" | jq '. + {response_format: {type: "json_object"}}')

			[[ $debug == 'true' ]] && {
				# request "https://api.openai.com/v1/chat/completions" --token "$OPENAI_API_KEY" --json "$payload" | jq
				curl -s "https://api.openai.com/v1/chat/completions" \
					-H "Authorization: Bearer $OPENAI_API_KEY" \
					-H "Content-Type: application/json" \
					-d "$payload" | jq
			}

			response=$(curl -s -X POST "https://api.openai.com/v1/chat/completions" \
				-H "Authorization: Bearer $OPENAI_API_KEY" \
				-H "Content-Type: application/json" \
				-d "$payload" | jq -r '.choices[0].message.content')

			[[ -n $thread_title ]] && {
				recins "$BARE_HOME/recfiles/openai/messages.rec" -f Thread -v "$thread_title" -f Author -v "${assistant_name-Assistant}" -f Contents -v "$response"
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
				-o "$output"

			# Check if the file was created and is not empty
			if [ ! -s "$output" ]; then
				echo "Error: File $output was not created or is empty" >&2
			fi

			echo "$output"

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



pretty() {

	if [[ -p /dev/stdin ]]; then input=$(cat); else input=$1 && shift; fi
	
	__deps glow
	echo "$input" | glow

}



qr() {

	__deps qrencode

	local link output

	if [[ -p /dev/stdin ]]; then link=$(cat); else link=$1; fi

	output="$(bare.sh random string 30).png"

	qrencode -o "$output" "$link"

	echo "$output"

}



random() {
    local length=16
    local use_lowercase=true
    local use_uppercase=true
    local use_digits=true
    local use_symbols=false
    local custom_symbols=""
    local min_lowercase=0
    local min_uppercase=0
    local min_digits=0
    local min_symbols=0
    local chars_lower="abcdefghijklmnopqrstuvwxyz"
    local chars_upper="ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    local chars_digits="0123456789"
    local chars_symbols='!@#$%^&*+-='
    local chars=""

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            alpha)
                use_digits=false
                use_symbols=false
                shift ;;
            alphanumeric|string)
                use_symbols=false
                shift ;;
            number|numbers|digits)
                use_lowercase=false
                use_uppercase=false
                use_symbols=false
                use_digits=true
                shift ;;
            symbols)
                use_lowercase=false
                use_uppercase=false
                use_digits=false
                use_symbols=true
                shift ;;
			--custom-symbols)
				[[ -z $2 ]] && echo "Error: No custom symbols provided" && return 1
				custom_symbols="$2" && shift 2 ;;
            [0-9]*)
                length=$1
                shift ;;
            --include|include)
                shift
                while [[ $# -gt 0 ]]; do
                    case $1 in
                        lowercase) use_lowercase=true ;;
                        uppercase) use_uppercase=true ;;
                        digits|numbers) use_digits=true ;;
                        symbols) use_symbols=true ;;
                        and) ;;  # Ignore 'and'
                        *) break ;;
                    esac
                    shift
                done ;;
            --exclude|exclude)
                shift
                while [[ $# -gt 0 ]]; do
                    case $1 in
                        lowercase) use_lowercase=false ;;
                        uppercase) use_uppercase=false ;;
                        digits|numbers) use_digits=false ;;
                        symbols) use_symbols=false ;;
                        and) ;;  # Ignore 'and'
                        *) break ;;
                    esac
                    shift
                done ;;
            --require|require)
                shift
                while [[ $# -gt 0 ]]; do
                    case $1 in
                        lowercase) min_lowercase=1 ;;
                        uppercase) min_uppercase=1 ;;
                        digits|numbers) min_digits=1 ;;
                        symbols) min_symbols=1 ;;
                        and) ;;  # Ignore 'and'
                        *) break ;;
                    esac
                    shift
                done ;;
            --length)
                length=$2
                shift 2 ;;
            *)
                echo "Invalid argument: $1"
                return 1 ;;
        esac
    done

	[[ -n $custom_symbols ]] && chars_symbols="$custom_symbols"

    # Ensure required character types are included if they are required
    if (( min_lowercase > 0 )); then
        use_lowercase=true
    fi
    if (( min_uppercase > 0 )); then
        use_uppercase=true
    fi
    if (( min_digits > 0 )); then
        use_digits=true
    fi
    if (( min_symbols > 0 )); then
        use_symbols=true
    fi

    # Build the character set
    [[ $use_lowercase == true ]] && chars+="$chars_lower"
    [[ $use_uppercase == true ]] && chars+="$chars_upper"
    [[ $use_digits == true ]] && chars+="$chars_digits"
    [[ $use_symbols == true ]] && chars+="$chars_symbols"

    # Ensure the character set is not empty
    if [ -z "$chars" ]; then
        echo "Character set is empty. Cannot generate random string."
        return 1
    fi

    # Ensure required character types are included
    if [[ $min_lowercase -gt 0 && $use_lowercase == false ]]; then
        echo "Cannot require lowercase characters when they are excluded."
        return 1
    fi
    if [[ $min_uppercase -gt 0 && $use_uppercase == false ]]; then
        echo "Cannot require uppercase characters when they are excluded."
        return 1
    fi
    if [[ $min_digits -gt 0 && $use_digits == false ]]; then
        echo "Cannot require digits when they are excluded."
        return 1
    fi
    if [[ $min_symbols -gt 0 && $use_symbols == false ]]; then
        echo "Cannot require symbols when they are excluded."
        return 1
    fi

    # Calculate total required characters
    local total_required=$(( min_lowercase + min_uppercase + min_digits + min_symbols ))
    if (( total_required > length )); then
        echo "Total required characters ($total_required) exceed the desired length ($length)."
        return 1
    fi

    # Function to generate random characters from a character set
    get_random_chars() {
        local count=$1
        local char_set=$2
        local output=""
        local char_set_len=${#char_set}

        for _ in $(seq 1 $count); do
            local rand_index=$(( RANDOM % char_set_len ))
            output+=${char_set:rand_index:1}
        done

        echo "$output"
    }

    # Generate required characters
    local password=""
    local remaining_length=$length

    # Add required lowercase letters
    if (( min_lowercase > 0 )); then
        local lowercase_chars
        lowercase_chars=$(get_random_chars $min_lowercase "$chars_lower")
        password+="$lowercase_chars"
        remaining_length=$(( remaining_length - min_lowercase ))
    fi

    # Add required uppercase letters
    if (( min_uppercase > 0 )); then
        local uppercase_chars
        uppercase_chars=$(get_random_chars $min_uppercase "$chars_upper")
        password+="$uppercase_chars"
        remaining_length=$(( remaining_length - min_uppercase ))
    fi

    # Add required digits
    if (( min_digits > 0 )); then
        local digit_chars
        digit_chars=$(get_random_chars $min_digits "$chars_digits")
        password+="$digit_chars"
        remaining_length=$(( remaining_length - min_digits ))
    fi

    # Add required symbols
    if (( min_symbols > 0 )); then
        local symbol_chars
        symbol_chars=$(get_random_chars $min_symbols "$chars_symbols")
        password+="$symbol_chars"
        remaining_length=$(( remaining_length - min_symbols ))
    fi

    # Add remaining random characters
    if (( remaining_length > 0 )); then
        local random_chars
        random_chars=$(get_random_chars $remaining_length "$chars")
        password+="$random_chars"
    fi

    # Shuffle the password
    password=$(echo "$password" | fold -w1 | shuf | tr -d '\n')

    echo "$password"
}



rec() {

	# usage: rec <recfile||input> <command> <args>

	__deps rec2csv csvlook

	local input command output recfile

	if [[ -p /dev/stdin ]]; then input=$(cat); else input=$1 && shift; fi

	[[ -z $input ]] && echo "Error: no input provided" && return 1

	# check for either explicit <file> or implifict home/recfiles/<file>
	if [[ -f "$input" ]]; then
		input=$(cat "$input")
	elif [[ -f "$BARE_HOME/recfiles/$input" ]]; then
		input=$(cat "$BARE_HOME/recfiles/$input")
	fi

	command=$1 && shift

	case $command in

		list)

			echo "$input" | recsel "$@"

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
			[[ -z $input ]] && echo "ERROR: no input provided" && exit 1
			
			# Check if the input is an object or an array
			if echo "$input" | jq -e 'type == "object"' > /dev/null; then
				input="[$input]"
			fi
			
			# Function to sanitize keys
			sanitize_keys() {
				jq 'map(
					with_entries(
						.key |= gsub("[^a-zA-Z0-9_]"; "_")
					)
				)'
			}
			
			# Sanitize keys and check if the array is empty
			sanitized_input=$(echo "$input" | sanitize_keys)
			if [[ $(echo "$sanitized_input" | jq 'length') -eq 0 ]]; then
				exit 0
			fi
			
			# Convert given input to CSV
			output=$(echo "$sanitized_input" | jq -r '(.[0] | keys_unsorted) as $keys | $keys, map([.[ $keys[] ]])[] | @csv' | csv2rec)
			[[ -n $1 ]] && echo "$output" >> "$1" || echo "$output"
			
			;;

		--from-csv)

			[[ -f "$1" ]] && input="$(cat "$1")" && shift
			[[ -z $input ]] && echo "ERROR: no input provided"
			output="$(echo "$input" | sed '1s/^\xEF\xBB\xBF//' | csv2rec)"
			[[ -n $1 ]] && echo "$output" >> "$1" || echo "$output"

			;;

	esac

}



records() {

	__deps recsel recins recdel

	local input args command expression

	expression='1 = 1'; # so we can use expressions (defaults to 'true')

	args=() && while [[ $# -gt 0 ]]; do
		case $1 in
			select|delete|insert|update) command=$1 && shift ;;
			where) expression=$2 && shift 2 ;;
			*) args+=("$1") && shift ;;
		esac
	done
	set -- "${args[@]}"

	# capture $input
	if [[ -p /dev/stdin ]]; then input=$(cat); else { input=$1 && shift; } fi

	# require $input
	[[ -z $input ]] && echo "Error: no input provided" && return 1

	# coalesce $input
	[[ -f "$input" ]] && input=$(cat "$input")
	[[ -f "records/$input.rec" ]] && input=$(cat "records/$input.rec")

	case $command in

		select) echo "$input" | recsel "$@" -e "$expression" ;;
		delete) echo "$input" | recdel "$@" ;;
		insert) echo "$input" | recins "$@" ;;

		* ) echo "Invalid command: $command" ;;

	esac

}



relay() {

	local input var args arg

	args=() && for arg in "$@"; do
		case $arg in
			--var) var='true' && shift ;;
			*) args+=("$arg") && shift ;;
		esac
	done
	set -- "${args[@]}"

	[[ -p /dev/stdin ]] && input=$(cat) || input=$1

	[[ -z $input ]] && echo "Error: no input provided" && return 1

	[[ -n $var ]] && {
		echo "${!input}" && return 0
	}

	echo "$input"

}



render() {

	local input command args subargs

	# help
	[[ $1 == '--?' ]] && echo "|<file|markdown> (-p|--pretty|--to-html|--to-markdown|--to-md)" && return 0

	if [[ -p /dev/stdin ]]; then input=$(cat); else input=$1; fi
	[[ -f $input ]] && input=$(cat "$input")

	# Process arguments to handle flags and content
	args=() && for arg in "$@"; do
		case "$arg" in

			--to-html)
				echo "$input" | pandoc -o temp.html
				awk '{
					while (match($0, /<[^>]*><\/[^>]*>/)) {
						$0 = substr($0, 1, RSTART-1) substr($0, RSTART+RLENGTH)
					}
					print
				}' temp.html > temp_clean.html
				mv temp_clean.html temp.html
				{
					cat temp.html
				}
				rm temp.html
				return 0
				;;

			--pretty|-p)
				pretty "$input" && return 0
				;;

			--to-markdown|--to-md)

				local high_powered simple_mode prompt subargs

				simple_mode=1

				subargs=() && for subarg in "$@"; do
					case "$subarg" in
						--simple) simple_mode=1 && shift ;;
						--high-powerd) high_powered=1 && shift ;;
						*) subargs+=("$subarg") && shift ;;
					esac
				done
				set -- "${subargs[@]}"

				if [[ $simple_mode == 1 ]]; then

					echo "$input" | pandoc -f html -t markdown

				else

					local openai_args

					prompt="You are an expert transcoder from html and text content to neatly structured markdown content. Use your best judgement to convert the given INPUT as semantically and clean and simple markdown content that simplifies the output but doesn't leave out any content. Write it in JSON format with the raw markdown content in a property called 'markdown'.' \n\n - - - \n\n"
					input=$(echo "$input" | lynx -stdin -dump | codec json.encode)

					openai_args=("--json")
					[[ $high_powered == 1 ]] && openai_args+=("--high-powered")
					
					openai "$prompt: INPUT: $input" "${openai_args[@]}" < /dev/null | jq -r '.markdown'

				fi

				;;
		
		esac
	done
	set -- "${args[@]}"

}



request() {

	local url
	declare -a curl_cmd
	
	# help
	[[ $1 == '--?' ]] && echo "|<url> (--json <json>|--data <form-data>|--file <file>|--header <header>|--token <token>|--auth <user:pass>|--output <file>)" && return 0
	
	if [[ -p /dev/stdin ]]; then 
		url=$(cat | tr -d '\0') 
	else 
		url=$1 && shift 
	fi
	
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



routines() {

	# Ensure BARE_HOME is set
	if [[ -z $BARE_HOME ]]; then
		echo "BARE_HOME is not set"
		exit 1
	fi

	# Initialize variables
	command='list'
	args=()
	name=""
	description=""
	cron=""
	input=""
	bash_path=$(command -v bash)

	# Parse command-line arguments
	while [[ $# -gt 0 ]]; do
		case $1 in
			--name|-n) name=$2 && shift 2 ;;
			--description|--desc|-d) description=$2 && shift 2 ;;
			--cron|-c) cron=$2 && shift 2 ;;
			--add|--create|add|create) command='add' && shift ;;
			--update|--edit|update|edit) command='update' && shift ;;
			--remove|remove) command='remove' && shift ;;
			--list|list) command='list' && shift ;;
			*) args+=("$1") && shift ;;
		esac
	done
	set -- "${args[@]}"

	if [[ -p /dev/stdin ]]; then
		input=$(cat)
	else
		input=$1
	fi

	# Define the recfile path
	RECFILE="$BARE_HOME/recfiles/routines/list.rec"

	# Function to add or update a cron job
	add_or_update_cron() {
		[[ -z $name ]] && echo "Error: Name is required" && exit 1
		[[ -z $cron ]] && echo "Error: Cron is required" && exit 1
		[[ -z $input ]] && echo "Error: Script is required" && exit 1

		# Remove existing record with the same name (if updating)
		recdel "$RECFILE" -e "Name = '$name'" 2>/dev/null

		# Insert the new or updated record
		recins "$RECFILE" -f Name -v "$name" -f Script -v "$bash_path $BARE_DIR/bare.sh $input" -f Description -v "$description" -f Cron -v "$cron"

		# Add to crontab if it doesn't exist
		if ! (crontab -l 2>/dev/null | grep -q "$cron $bash_path $BARE_DIR/bare.sh $input"); then
			(crontab -l 2>/dev/null; echo "$cron $bash_path $BARE_DIR/bare.sh $input") | crontab -
		fi

		echo "success"
	}

	# Function to remove a cron job
	remove_cron() {
		[[ -z $name ]] && echo "Error: Name is required" && exit 1

		# Retrieve the cron timing and script name from the record
		cron_timing=$(recsel -e "Name = '$name'" -P Cron "$RECFILE")
		script_name=$(recsel -e "Name = '$name'" -P Script "$RECFILE")

		[[ -z $cron_timing || -z $script_name ]] && echo "Error: Record not found" && exit 1

		# Remove the record from the recfile
		recdel "$RECFILE" -e "Name = '$name'" 2>/dev/null

		# Remove the crontab entry
		crontab -l | grep -vF "$cron_timing $script_name" | crontab -

		echo "success"
	}

	# Execute the command based on the user's input
	case $command in
		list)
			recsel "$RECFILE" -p Name,Description,Cron,Script
			;;
		add|update)
			add_or_update_cron
			;;
		remove)
			remove_cron
			;;
		*)
			echo "Invalid command"
			exit 1
			;;
	esac

	unset -f add_or_update_cron
	unset -f remove_cron

}



list() { # alias for `bare.sh records select ...`

	# capture $input
	if [[ -p /dev/stdin ]]; then input=$(cat); else { input=$1 && shift; } fi

	# require $input
	[[ -z $input ]] && echo "Error: no input provided" && return 1

	# coalesce $input
	[[ -f "$input" ]] && input=$(cat "$input")
	[[ -f "records/$input" ]] && input=$(cat "records/$input")

	echo "$input" | records select "$@"

}



silence() {

	local input

	if [[ -p /dev/stdin ]]; then input=$(cat); else input=$1; fi
	echo "$input" >> /dev/null

}



size() {

	local input stat_cmd

	if [[ -p /dev/stdin ]]; then input=$(cat); else input=$1; fi

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



speed() {

	__deps ffmpeg openssl

	local speed_factor input_file output_file is_video extension

	# Default values
	speed_factor=${1:-'0.5'}
	input_file="$2"
	output_file=${3:-"$(openssl rand -hex 16).mp3"}

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



squish() {

	local input

	if [[ -p /dev/stdin ]]; then input=$(cat); else input=$1; fi
	transform "$input" --squish

}



storage() {

    local input command args arg privacy to

    command=$1 && shift

	privacy='public-read'
	to="/uploads/$(random string 32)"

    args=() && while [[ $# -gt 0 ]]; do
        case $1 in
            --to|-t) to=$2 && shift 2 ;;
			--private) privacy='private' && shift ;;
            *) args+=("$1") && shift ;;
        esac
    done
	set -- "${args[@]}"

    [[ -p /dev/stdin ]] && input=$(cat) || input=$1 && shift

    case $command in

        upload)

            SPACE=$(echo "$DO_SPACES_ENDPOINT" | awk -F[/:] '{print $4}' | awk -F. '{print $1}')
            REGION=$(echo "$DO_SPACES_ENDPOINT" | sed -n 's|.*\.\([^.]*\)\.digitaloceanspaces\.com|\1|p')
            STORAGETYPE="STANDARD"
            KEY="$DO_SPACES_ACCESS_KEY"
            SECRET="$DO_SPACES_SECRET_KEY"
            
            if [[ -z "$KEY" || -z "$SECRET" || -z "$SPACE" || -z "$REGION" ]]; then
                echo "Missing one or more required environment variables (DO_SPACES_ACCESS_KEY, DO_SPACES_SECRET_KEY, DO_SPACES_ENDPOINT)."
                exit 1
            fi
            
            function putS3 {
                local path="$1"
                local file="$2"
                local space_path="$3"
            
                date=$(date -u +"%a, %d %b %Y %T %z")
            
				acl="x-amz-acl:${privacy}"
                content_type=$(file -b --mime-type "$path")  # 
                storage_type="x-amz-storage-class:${STORAGETYPE}"
            
                string="PUT\n\n${content_type}\n${date}\n${acl}\n${storage_type}\n/${SPACE}${space_path}${file}"
            
                signature=$(echo -en "${string}" | openssl sha1 -hmac "${SECRET}" -binary | base64)
            
                url="https://${SPACE}.${REGION}.digitaloceanspaces.com${space_path}${file}"
            
                curl -s -X PUT -T "$path" \
                    -H "Host: ${SPACE}.${REGION}.digitaloceanspaces.com" \
                    -H "Date: ${date}" \
                    -H "Content-Type: ${content_type}" \
                    -H "${storage_type}" \
                    -H "${acl}" \
                    -H "Authorization: AWS ${KEY}:${signature}" \
                    "$url"
            
                if [[ $? -eq 0 ]]; then
                    echo "$url"
                else
                    echo "Failed to upload ${file}. Check cURL output for details." && return 1
                fi
            }
            
            file_name=$(basename "$to")
            dir_path=$(dirname "$to")
            
            if [[ $dir_path != /* ]]; then
                dir_path="/$dir_path"
            fi

			if [[ $dir_path == '/.' ]]; then
				dir_path=''
			fi

			# echo "$dir_path" && exit 0
            
            if [[ ! -f "$input" ]]; then
                echo "Error: The file $input does not exist."
                return 1
            fi
            
            putS3 "$input" "$file_name" "$dir_path/"

            ;;

        *) echo "Invalid command" && return 1 ;;
		
    esac

}



stripe() {

    local scope action field operator value limit pick output_file
    local args=()
    local params=()

    [[ -p /dev/stdin ]] && action=$(cat)

    # Parse arguments
    while [[ $# -gt 0 ]]; do

        case $1 in

            -p|pick)
                pick=$2
                shift 2
                ;;

            limit)
                limit=$2
                shift 2
                ;;

            where)
                [[ -z $2 ]] && echo "Error: Field is required" && return 1
                field=$2
                shift 2
                ;;

            =|is)
                if [[ $2 == 'not' ]]; then
                    operator='!='
                    shift
                elif [[ $2 == 'like' ]]; then
                    operator='~'
                    shift
                else
                    operator='='
                    shift
                fi
                ;;

            like)
                operator='~'
                shift
                ;;

            !=|isnt)
                operator='!='
                shift
                ;;

			payments) scope='payment_intents' && shift ;;

            customers|subscriptions|products|\
			invoices|prices|charges|refunds|payouts|\
			balance_transactions|disputes|transfers|payment_intents)
                scope=$1
                shift
                ;;

            list|create|update|delete)
                action=$1
                shift
                ;;

            *)
                args+=("$1")
                shift
                ;;

        esac

    done

    # Set defaults
    [[ -z $action ]] && action='list'
    [[ -z $operator ]] && operator='='

    # Extract value if provided
    if [[ ${#args[@]} -gt 0 ]]; then
        value=${args[0]}
    fi

    # Validate required parameters
    [[ -z $scope ]] && echo "Error: Scope (e.g., customers, subscriptions) is required" && return 1

    # Make temp file to store response
    output_file=$(mktemp)

    # Initialize output_file as an empty array
    echo '[]' > "$output_file"

    # Map scope to the correct endpoint if necessary
    declare -A endpoint_map
    endpoint_map[balance_transactions]="balance_transactions"
    endpoint_map[charges]="charges"
    endpoint_map[customers]="customers"
    endpoint_map[disputes]="disputes"
    endpoint_map[invoices]="invoices"
    endpoint_map[payment_intents]="payment_intents"
    endpoint_map[payouts]="payouts"
    endpoint_map[prices]="prices"
    endpoint_map[products]="products"
    endpoint_map[refunds]="refunds"
    endpoint_map[subscriptions]="subscriptions"
    endpoint_map[transfers]="transfers"

    endpoint=${endpoint_map[$scope]}

    if [[ -z $endpoint ]]; then
        echo "Error: Unsupported scope '$scope'"
        rm "$output_file"
        return 1
    fi

    # Determine the endpoint URL and parameters based on action
    base_url="https://api.stripe.com/v1/$endpoint"
    params=()
    params+=("-u" "$STRIPE_SECRET_KEY:")

    # Add limit if specified
    if [[ -n $limit ]]; then
        params+=("-d" "limit=$limit")
    fi

    # Handle search queries for resources that support it
    if [[ $action == 'list' && -n $field && -n $operator && -n $value ]]; then
        # Only certain resources support search
        # For example, customers and charges support search
        if [[ "$scope" == "customers" ]] || [[ "$scope" == "charges" ]] || [[ "$scope" == "payment_intents" ]]; then
            base_url+=""/"search"
            params+=("-d" "query=$field$operator'$value'")
        else
            # For resources that don't support search, use list filters
            params+=("-d" "$field=$value")
        fi
    fi

    # First API request
    response=$(curl -G -s "$base_url" "${params[@]}")

    # Determine fields to extract based on scope
    declare -A field_sets
    field_sets[customers]='
        {
            id: .id,
            balance: .balance,
            created: .created,
            email: .email,
            name: .name
        }
        +
        (if .address != null then
            {
                address_city: .address.city,
                address_country: .address.country,
                address_line1: .address.line1,
                address_line2: .address.line2,
                address_postal_code: .address.postal_code,
                address_state: .address.state
            }
        else {} end)
        +
        (if .shipping != null then
            {
                shipping_city: .shipping.address.city,
                shipping_country: .shipping.address.country,
                shipping_line1: .shipping.address.line1,
                shipping_line2: .shipping.address.line2,
                shipping_postal_code: .shipping.address.postal_code,
                shipping_state: .shipping.address.state,
                shipping_name: .shipping.name,
                shipping_phone: .shipping.phone
            }
        else {} end)
    '
    field_sets[subscriptions]='
        {
            id: .id,
            customer: .customer,
            status: .status,
            start_date: .start_date,
            current_period_start: .current_period_start,
            current_period_end: .current_period_end,
            cancel_at_period_end: .cancel_at_period_end,
            canceled_at: .canceled_at
        }
    '
    field_sets[products]='
        {
            id: .id,
            name: .name,
            description: .description,
            active: .active,
            created: .created,
            updated: .updated
        }
    '
    field_sets[invoices]='
        {
            id: .id,
            customer: .customer,
            amount_due: .amount_due,
            amount_paid: .amount_paid,
            created: .created,
            due_date: .due_date,
            status: .status
        }
    '
    field_sets[charges]='
        {
            id: .id,
            amount: .amount,
            currency: .currency,
            created: .created,
            status: .status,
            customer: .customer,
            payment_method: .payment_method,
            description: .description,
            receipt_email: .receipt_email
        }
    '
    field_sets[refunds]='
        {
            id: .id,
            amount: .amount,
            currency: .currency,
            created: .created,
            status: .status,
            charge: .charge,
            reason: .reason
        }
    '
    field_sets[payouts]='
        {
            id: .id,
            amount: .amount,
            currency: .currency,
            created: .created,
            arrival_date: .arrival_date,
            status: .status,
            method: .method,
            description: .description,
            failure_message: .failure_message
        }
    '
    field_sets[balance_transactions]='
        {
            id: .id,
            amount: .amount,
            currency: .currency,
            created: .created,
            available_on: .available_on,
            type: .type,
            description: .description,
            fee: .fee,
            net: .net,
            source: .source
        }
    '
    field_sets[disputes]='
        {
            id: .id,
            amount: .amount,
            currency: .currency,
            created: .created,
            status: .status,
            reason: .reason,
            charge: .charge,
            evidence_details: .evidence_details
        }
    '
    field_sets[transfers]='
        {
            id: .id,
            amount: .amount,
            currency: .currency,
            created: .created,
            destination: .destination,
            status: .status,
            description: .description
        }
    '
    field_sets[payment_intents]='
        {
            id: .id,
            amount: .amount,
            currency: .currency,
            created: .created,
            status: .status,
            customer: .customer,
            payment_method: .payment_method,
            description: .description,
            receipt_email: .receipt_email
        }
    '

    # Get the appropriate jq filter for the current scope
    jq_filter=${field_sets[$scope]}

    # Check if the scope is supported
    if [[ -z $jq_filter ]]; then
        echo "Error: Unsupported scope '$scope'"
        rm "$output_file"
        return 1
    fi

    total_fetched=0

    # Extract data and merge into output_file
    data=$(echo "$response" | jq "
        [
            .data[]? |
            $jq_filter
            | walk(if . == null then \"\" else . end)
        ]")

    fetched_count=$(echo "$data" | jq 'length')
    total_fetched=$((total_fetched + fetched_count))

    if [ "$data" != "null" ] && [ "$data" != "[]" ]; then
        tmp=$(mktemp)
        jq -s 'add' "$output_file" <(echo "$data") > "$tmp" && mv "$tmp" "$output_file"
    fi

    has_more=$(echo "$response" | jq -r '.has_more')

    # If data array is empty, last_id would be null
    last_id=$(echo "$response" | jq -r '.data[-1].id')

    # Paginate if necessary
    while [[ $has_more == 'true' ]]; do

        # Check if total_fetched >= limit (if limit is specified)
        if [[ -n $limit ]] && (( total_fetched >= limit )); then
            break
        fi

        # Reset params for pagination
        params_paginated=("-u" "$STRIPE_SECRET_KEY:")

        # Calculate remaining limit
        if [[ -n $limit ]]; then
            remaining_limit=$((limit - total_fetched))
            # Stripe API has a minimum limit of 1
            if (( remaining_limit < 1 )); then
                remaining_limit=1
            fi
            params_paginated+=("-d" "limit=$remaining_limit")
        else
            # If no limit specified, use default or maximum allowed by API
            params_paginated+=("-d" "limit=100")
        fi

        # Add starting_after parameter
        params_paginated+=("-d" "starting_after=$last_id")

        # If searching, add the query parameter
        if [[ $action == 'list' && -n $field && -n $operator && -n $value ]]; then
            # Only certain resources support search
            if [[ "$scope" == "customers" ]] || [[ "$scope" == "charges" ]] || [[ "$scope" == "payment_intents" ]]; then
                base_url="https://api.stripe.com/v1/$endpoint/search"
                params_paginated+=("-d" "query=$field$operator'$value'")
            else
                base_url="https://api.stripe.com/v1/$endpoint"
                params_paginated+=("-d" "$field=$value")
            fi
        else
            base_url="https://api.stripe.com/v1/$endpoint"
        fi

        response=$(curl -G -s "$base_url" "${params_paginated[@]}")

        data=$(echo "$response" | jq "
            [
                .data[]? |
                $jq_filter
                | walk(if . == null then \"\" else . end)
            ]")

        fetched_count=$(echo "$data" | jq 'length')
        total_fetched=$((total_fetched + fetched_count))

        if [ "$data" != "null" ] && [ "$data" != "[]" ]; then
            tmp=$(mktemp)
            jq -s 'add' "$output_file" <(echo "$data") > "$tmp" && mv "$tmp" "$output_file"
        fi

        has_more=$(echo "$response" | jq -r '.has_more')
        last_id=$(echo "$response" | jq -r '.data[-1].id')

    done

    # Output the final result

    # If limit is specified, we might have fetched more data than needed due to the last page.
    # So we need to trim the output to the specified limit.

    if [[ -n $limit ]]; then
        # Use jq to limit the output to the specified number of records
        tmp=$(mktemp)
        jq ". | .[:$limit]" "$output_file" > "$tmp" && mv "$tmp" "$output_file"
    fi

    if [[ -n $pick ]]; then
        cat "$output_file" | bare.sh rec --from-json | recsel -P "$pick"
    else
        cat "$output_file" | bare.sh rec --from-json
    fi

    # Cleanup
    rm "$output_file"
}



sub() {

    local replacing replacement input args

    replacing=$1 && shift
	if [[ -p /dev/stdin ]]; then input=$(cat); else input=$1 && shift; fi

    args=() && while [[ $# -gt 0 ]]; do
        case $1 in
            with) replacement="$2"; shift 2 ;;
            in) input=$2; shift 2 ;;
            *) args+=("$1"); shift ;;
        esac
    done
	set -- "${args[@]}"

	echo "${input//$replacing/$replacement}"

}



summarize() {

	local input length input_char_count prompt

	args=() && while [[ $# -gt 0 ]]; do
		case $1 in
			--length|-l) length=$2; shift 2 ;;
			--prompt|-p) prompt="$2"; shift 2 ;;
			*) args+=("$1"); shift ;;
		esac
	done
	set -- "${args[@]}"

	[[ -p /dev/stdin ]] && input=$(cat | codec json.encode) || input=$1

	input_word_count=$(echo "$input" | wc -w)
	
	# Calculate 25% of the word count
	auto_length=$((input_word_count * 25 / 100))
	
	# Ensure the length does not exceed 1000 words
	auto_length=$((auto_length > 1000 ? 1000 : auto_length))
	
	[[ -z $length ]] && length=$auto_length

	openai "Summarize the following USER_TEXT to approximately $length words. $prompt \n\nUSER_TEXT: $input" < /dev/null

}



transform() {

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
			--email|:email) format='email' ;;
			*) args+=("$1") ;;
		esac && shift
	done
	set -- "${args[@]}"

	if [[ -p /dev/stdin ]]; then input=$(cat); else input=$1 && shift; fi

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
		email)
			echo "$input" | bare.sh lowercase
			;;
	esac
}



translate() {

	__deps dig

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
	done
	set -- "${remaining_args[@]}"

	[[ -z $input ]] && {
		if [[ -p /dev/stdin ]]; then input=$(cat); else input=$1; fi
	}

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



trim() {

	local input
	if [[ -p /dev/stdin ]]; then input=$(cat); else input=$1; fi
	transform "$input" --trim < /dev/null

}

capitalize() { bare.sh transform "$@" --capitalize; return 0; }

unzip() {

	local arg input output localunzip

	localunzip=$(which unzip)

	if [[ -p /dev/stdin ]]; then input=$(cat); else input=$1 && shift; fi

	for arg in "$@"; do
		case $arg in
			--output|-o) output="$2"; shift 2 ;;
			*) : ;;
		esac
	done

	[[ -z $output ]] && output="$input"
	
	# Unzip the file to the output directory, automatically answering "yes" to any prompts
	yes y | "$localunzip" -q "$input" -d "$output"

	echo "$output"

}



validate() {

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

			if [[ $(echo "$input" | csvclean --dry-run 2>&1) == 'No errors.' ]]; then
				output="true"
			fi

			;;

		dir|directory|folder) [[ -d $input ]] && output="true" ;;

		file) [[ -f $input ]] && output="true" ;;

		ai)

			runs_remaining=3
			condition="$input"
			source_material="$1" && shift
			model=${OPENAI_DEFAULT_MODEL:-'gpt-4o-mini'}

			for arg in "$@"; do
				case $arg in
					--explain) explain=true ;;
					--high-powered) model='gpt-4o' ;;
					--model) model="$2"; shift ;;
					*) break ;;
				esac
				shift
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

			output=$(echo "$response" | jq -r '.answer')

			[[ -n $explain ]] && {
				reasoning=$(echo "$response" | jq -r '.reasoning')
				echo "Validation: '$output'. Explanation: $reasoning"
				exit 0
			}
			
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
			# assume it's a regex
			if echo "$input" | grep -Eq "$type"; then
				output="true"
			fi
			;;

	esac

	echo "$output"

}



weather() {

    if [[ -p /dev/stdin ]]; then input=$(cat); else input=$1 && shift; fi

    # detect if input is a lat,long
    if [[ $input =~ ^-?[0-9]+\.[0-9]+,-?[0-9]+\.[0-9]+$ ]]; then
        location=$input
    else
        location=$(geo "$input")
    fi

    cache_path="$BARE_DIR/.bare/cache/weather/$(codec text.filesafe "$location")"

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
    done
	set -- "${remaining_args[@]}"

    [[ $color == '0' ]] && color_code='T'

    [[ $json_requested == '1' ]] && {

        cacheJSON() {
            json=$(curl -sL "wttr.in/$location?format=j1")
            mkdir -p "$BARE_DIR/.bare/cache/weather"
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
            exit 0
        }

        [[ $sunrise == '1' ]] && {
            echo "$json" | jq -r '.weather[0].astronomy[0].sunrise'
            exit 0
        }

        [[ $sunset == '1' ]] && {
            echo "$json" | jq -r '.weather[0].astronomy[0].sunset'
            exit 0
        }

        [[ $moonrise == '1' ]] && {
            echo "$json" | jq -r '.weather[0].astronomy[0].moonrise'
            exit 0
        }

        [[ $moonset == '1' ]] && {
            echo "$json" | jq -r '.weather[0].astronomy[0].moonset'
            exit 0
        }

        [[ $cloud_cover == '1' ]] && {
            echo "$json" | jq -r '.current_condition[0].cloudcover'
            exit 0
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
            mkdir -p "$BARE_DIR/.bare/cache/weather"
            echo "$response" > "${cache_path}${cache_append}"
        fi
        echo "$response"
        exit 0
    }

    # if no response, check cache
    [[ -z $response ]] && {
        if [[ -f "${cache_path}${cache_append}" ]]; then
            cat "${cache_path}${cache_append}"
            exit 0
        fi
    }

    echo "$response"

}



write() {

	local contents args file

	# Read from stdin if not a terminal
	[[ -p /dev/stdin ]] && contents=$(cat)

	# Parse arguments
	args=() && while [[ $# -gt 0 ]]; do
		case $1 in
			--to|to|--file|-f|file) file="$2" && shift 2 ;;
			--into|into) [[ $2 == 'file' ]] && file="$3" && shift 3 || file="$2" && shift 2 ;;
			--contents|contents|content) contents="$2" && shift 2 ;;
			with|and) shift ;; # permits more lyrical language
			*) args+=("$1") && shift ;;
		esac
	done
	set -- "${args[@]}"


	[[ -z $contents ]] && contents=$1
	[[ -z $contents ]] && echo "Error: Missing contents" >&2 && return 1
	[[ -z $file ]] && echo "Error: Missing file" >&2 && return 1

	# Clean carriage return characters from contents
	contents=$(echo "$contents" | tr -d '\r')

	# Write contents to the specified file
	echo "$contents" > "$file"

}



# aliases & delegations

ai() { openai "$@" ; return 0 ; }

capitalize() { bare.sh transform "$@" --capitalize; return 0; }

decrypt() { bare.sh codec decrypt "$@"; return 0; }

encrypt() { bare.sh codec encrypt "$@"; return 0; }

filetype() { bare.sh examine "$@" -p type ; return 0 ; }

filepath() { bare.sh examine "$@" -p path ; return 0 ; }

lowercase() { bare.sh transform "$@" --lowercase ; return 0 ; }

password() { random --length 16 "$@"; return 0; }

round() { math round "$@" ; return 0 ; }

upload() { storage upload "$@" ; return 0 ; }

uppercase() { transform "$@" --uppercase ; return 0 ; }






# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

case $1 in
	
	--version|-v|-V) echo "$BARE_VERSION" ;;

	--upgrade) cd "$BARE_DIR" && git pull origin root ;;

	*) __isBareCommand "$1" && __bareStartUp && "$@" && exit 0 ;;

esac

exit 1