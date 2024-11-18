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
		printf '%s\n' "${missing_deps[*]}"
		exit 1
	fi

}



__getOS() {

	OS="Other"
	case $(uname) in
		Linux) grep -q 'Ubuntu' /etc/os-release && OS="Ubuntu" ;;
		Darwin) OS="macOS" ;;
	esac
	export OS

}



__bareStartUp() {

	# Set the values in the associative array
	local -A BASE_CONFIG
	BASE_CONFIG=(
		
		# bare
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
	[[ -f "$HOME/.barerc" ]] && source "$HOME/.barerc"

	return 0

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



clipboard() {

	# if mac, use pbcopy and pbpaste, if linux, use xclip

	local input command

	if [[ -p /dev/stdin ]]; then input=$(cat); fi

	command='copy'

	[[ $# -eq 1 ]] && command=$1
	[[ $# -eq 2 ]] && { command=$1; input=$2; }

	case $command in

		copy)

			case $OS in
				macOS) echo -n "$input" | pbcopy ;;
				Linux) echo -n "$input" | xclip -selection clipboard ;;
				*) echo "Error: clipboard operations are not supported on this OS." && return 1 ;;
			esac

			;;

		paste)

			case $OS in
				macOS) pbpaste ;;
				Linux) xclip -selection clipboard -o ;;
				*) echo "Error: clipboard operations are not supported on this OS." && return 1 ;;
			esac

			;;

	esac

}



codec() {

	local input command index json_array output lines line start end reverse_flag args PASSWORD_HASH_CLASS

	command=$1 && shift

	[[ -p /dev/stdin ]] && input=$(cat)
	[[ -z $input ]] && input=$1 && shift

	# PHP PasswordHash (public domain)
	# Define the PasswordHash class code without PHP tags
	PASSWORD_HASH_CLASS=$(cat <<'EOF'
class PasswordHash {
	var $itoa64;
	var $iteration_count_log2;
	var $portable_hashes;
	var $random_state;

	function __construct($iteration_count_log2, $portable_hashes)
	{
		$this->itoa64 = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';

		if ($iteration_count_log2 < 4 || $iteration_count_log2 > 31)
			$iteration_count_log2 = 8;
		$this->iteration_count_log2 = $iteration_count_log2;

		$this->portable_hashes = $portable_hashes;

		$rand = function_exists('getmypid') ? @getmypid() : uniqid(rand(), true);
		$this->random_state = microtime() . $rand;
	}

	function get_random_bytes($count)
	{
		$output = '';
		if (@is_readable('/dev/urandom') &&
			($fh = @fopen('/dev/urandom', 'rb'))) {
			$output = fread($fh, $count);
			fclose($fh);
		}

		if (strlen($output) < $count) {
			$output = '';
			for ($i = 0; $i < $count; $i += 16) {
				$this->random_state =
					md5(microtime() . $this->random_state);
				$output .=
					pack('H*', md5($this->random_state));
			}
			$output = substr($output, 0, $count);
		}

		return $output;
	}

	function encode64($input, $count)
	{
		$output = '';
		$i = 0;
		do {
			$value = ord($input[$i++]);
			$output .= $this->itoa64[$value & 0x3f];
			if ($i < $count)
				$value |= ord($input[$i]) << 8;
			$output .= $this->itoa64[($value >> 6) & 0x3f];
			if ($i++ >= $count)
				break;
			if ($i < $count)
				$value |= ord($input[$i]) << 16;
			$output .= $this->itoa64[($value >> 12) & 0x3f];
			if ($i++ >= $count)
				break;
			$output .= $this->itoa64[($value >> 18) & 0x3f];
		} while ($i < $count);

		return $output;
	}

	function gensalt_private($input)
	{
		$output = '$P$';
		$output .= $this->itoa64[min($this->iteration_count_log2 +
			((PHP_VERSION >= '5') ? 5 : 3), 30)];
		$output .= $this->encode64($input, 6);

		return $output;
	}

	function crypt_private($password, $setting)
	{
		$output = '*0';
		if (substr($setting, 0, 2) == $output)
			$output = '*1';

		if (substr($setting, 0, 3) != '$P$')
			return $output;

		$count_log2 = strpos($this->itoa64, $setting[3]);
		if ($count_log2 < 7 || $count_log2 > 30)
			return $output;

		$count = 1 << $count_log2;

		$salt = substr($setting, 4, 8);
		if (strlen($salt) != 8)
			return $output;

		# We're kind of forced to use MD5 here since it's the only
		# cryptographic primitive available in all versions of PHP
		# currently in use.  To implement our own low-level crypto
		# in PHP would result in much worse performance and
		# consequently in lower iteration counts and hashes that are
		# quicker to crack (by non-PHP code).
		if (PHP_VERSION >= '5') {
			$hash = md5($salt . $password, TRUE);
			do {
				$hash = md5($hash . $password, TRUE);
			} while (--$count);
		} else {
			$hash = pack('H*', md5($salt . $password));
			do {
				$hash = pack('H*', md5($hash . $password));
			} while (--$count);
		}

		$output = substr($setting, 0, 12);
		$output .= $this->encode64($hash, 16);

		return $output;
	}

	function gensalt_extended($input)
	{
		$count_log2 = min($this->iteration_count_log2 + 8, 24);
		# This should be odd to not reveal weak DES keys, and the
		# maximum valid value is (2**24 - 1) which is odd anyway.
		$count = (1 << $count_log2) - 1;

		$output = '_';
		$output .= $this->itoa64[$count & 0x3f];
		$output .= $this->itoa64[($count >> 6) & 0x3f];
		$output .= $this->itoa64[($count >> 12) & 0x3f];
		$output .= $this->itoa64[($count >> 18) & 0x3f];

		$output .= $this->encode64($input, 3);

		return $output;
	}

	function gensalt_blowfish($input)
	{
		# This one needs to use a different order of characters and a
		# different encoding scheme from the one in encode64() above.
		# We care because the last character in our encoded string will
		# only represent 2 bits.  While two known implementations of
		# bcrypt will happily accept and correct a salt string which
		# has the 4 unused bits set to non-zero, we do not want to take
		# chances and we also do not want to waste an additional byte
		# of entropy.
		$itoa64 = './ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

		$output = '$2a$';
		$output .= chr(ord('0') + $this->iteration_count_log2 / 10);
		$output .= chr(ord('0') + $this->iteration_count_log2 % 10);
		$output .= '$';

		$i = 0;
		do {
			$c1 = ord($input[$i++]);
			$output .= $itoa64[$c1 >> 2];
			$c1 = ($c1 & 0x03) << 4;
			if ($i >= 16) {
				$output .= $itoa64[$c1];
				break;
			}

			$c2 = ord($input[$i++]);
			$c1 |= $c2 >> 4;
			$output .= $itoa64[$c1];
			$c1 = ($c2 & 0x0f) << 2;

			$c2 = ord($input[$i++]);
			$c1 |= $c2 >> 6;
			$output .= $itoa64[$c1];
			$output .= $itoa64[$c2 & 0x3f];
		} while (1);

		return $output;
	}

	function HashPassword($password)
	{
		if ( strlen( $password ) > 4096 ) {
			return '*';
		}

		$random = '';

		if (CRYPT_BLOWFISH == 1 && !$this->portable_hashes) {
			$random = $this->get_random_bytes(16);
			$hash =
				crypt($password, $this->gensalt_blowfish($random));
			if (strlen($hash) == 60)
				return $hash;
		}

		if (CRYPT_EXT_DES == 1 && !$this->portable_hashes) {
			if (strlen($random) < 3)
				$random = $this->get_random_bytes(3);
			$hash =
				crypt($password, $this->gensalt_extended($random));
			if (strlen($hash) == 20)
				return $hash;
		}

		if (strlen($random) < 6)
			$random = $this->get_random_bytes(6);
		$hash =
			$this->crypt_private($password,
			$this->gensalt_private($random));
		if (strlen($hash) == 34)
			return $hash;

		# Returning '*' on error is safe here, but would _not_ be safe
		# in a crypt(3)-like function used _both_ for generating new
		# hashes and for validating passwords against existing hashes.
		return '*';
	}

	function CheckPassword($password, $stored_hash)
	{
		if ( strlen( $password ) > 4096 ) {
			return false;
		}

		$hash = $this->crypt_private($password, $stored_hash);
		if ($hash[0] == '*')
			$hash = crypt($password, $stored_hash);

		return $hash === $stored_hash;
	}
}
EOF
	)

	case $command in

		hash)

			local args algorithm
			
			algorithm="argon2id"
			
			args=()
			while [[ $# -gt 0 ]]; do
				case $1 in
					with|and|to|for) shift ;;
					--algorithm|-a|algorithm) algorithm=$2; shift 2 ;;
					bcrypt|argon2|argon2id) algorithm=$1; shift ;;
					wordpress) algorithm="bcrypt"; shift ;;
					couch|couchcms|CouchCMS) algorithm="couch"; shift ;;
					sqlpage) algorithm="argon2id"; shift ;;
					*) args+=("$1"); shift ;;
				esac
			done
			set -- "${args[@]}"
			
			[[ -z $algorithm ]] && echo "Error: --algorithm is required." && return 1
			[[ -z $input ]] && echo "Error: no input provided." && return 1
			
			if [[ "$algorithm" == "couch" ]]; then
				php <<END_PHP
<?php
\$password = '$input';

${PASSWORD_HASH_CLASS}

\$hasher = new PasswordHash(8, true);
\$hash = \$hasher->HashPassword(\$password);
echo \$hash;
?>
END_PHP
				echo "" # Ensure a newline is printed in CLI
			elif [[ "$algorithm" == "bcrypt" ]]; then
				php -r "
					\$password = '$input';
					\$hash = password_hash(\$password, PASSWORD_BCRYPT);
					echo \$hash;
				"
			else
				php -r "
					\$password = '$input';
					\$hash = password_hash(\$password, PASSWORD_ARGON2ID);
					echo \$hash;
				"
			fi
			;;
		
		hash.verify)
			
			local args password algorithm
			
			algorithm="argon2id"
			
			args=()
			while [[ $# -gt 0 ]]; do
				case $1 in
					with|and|to|for) shift ;;
					--password|-p|password) password=$2; shift 2 ;;
					--algorithm|-a|algorithm) algorithm=$2; shift 2 ;;
					bcrypt|argon2|argon2id) algorithm=$1; shift ;;
					wordpress) algorithm="bcrypt"; shift ;;
					couch) algorithm="couch"; shift ;;
					sqlpage) algorithm="argon2id"; shift ;;
					*) args+=("$1"); shift ;;
				esac
			done
			set -- "${args[@]}"
			
			password=${password:-$1}
			
			[[ -z $password ]] && { echo "Error: --password is required."; return 1; }
			[[ -z $input ]] && { echo "Error: hash input is required."; return 1; }
			
			if [[ "$algorithm" == "couch" ]]; then
				php <<END_PHP
<?php
\$password = '$password';
\$hash = '$input';

${PASSWORD_HASH_CLASS}

\$hasher = new PasswordHash(8, true);
if (\$hasher->CheckPassword(\$password, \$hash)) { echo 'true'; } else { echo 'false'; }
?>
END_PHP
				echo "" # Ensure a newline is printed in CLI
			elif [[ "$algorithm" == "bcrypt" ]]; then
				php -r "
					\$password = '$password';
					\$hash = '$input';
					if (password_verify(\$password, \$hash)) {
						echo 'true';
					} else {
						echo 'false';
					}
				"
			else
				php -r "
					\$password = '$password';
					\$hash = '$input';
					if (password_verify(\$password, \$hash)) {
						echo 'true';
					} else {
						echo 'false';
					}
				"
			fi
			;;

		jwt.encode)
		
			# Implement JWT encoding without external 'jwt' tool
		
			local expires issued issuer subject role secret_key algorithm args key value
			declare -A payload_args
		
			# Defaults
			issued=$(date U)
			expires=$(datecalc today "+2 days" | date U)
			issuer="bare.sh"
			algorithm="HS256"
		
			args=()
			while [[ $# -gt 0 ]]; do
				case $1 in
					with|and) shift ;; # Permits more lyrical commands
					--exp|-e|expires) expires="$2"; shift 2 ;;
					--iat|issued) issued="$2"; shift 2 ;;
					--iss|issuer) issuer="$2"; shift 2 ;;
					--sub|subject) subject="$2"; shift 2 ;;
					--user) payload_args["user"]="$2"; shift 2 ;;
					--role|-r) role="$2"; shift 2 ;;
					--secret|-s|secret) secret_key="$2"; shift 2 ;;
					--alg|-a|algorithm) algorithm="$2"; shift 2 ;;
					--payload|-p|payload) payload="$2"; shift 2 ;;
					# Capture custom key-value pairs
					--*) key="${1#--}"; value="$2"; payload_args["$key"]="$value"; shift 2 ;;
					*) args+=("$1"); shift ;;
				esac
			done
			set -- "${args[@]}"
		
			[[ -z $secret_key ]] && { echo "Error: --secret is required."; return 1; }
		
			# Add predefined claims to payload_args
			payload_args["exp"]="$expires"
			payload_args["iat"]="$issued"
			payload_args["iss"]="$issuer"
			[[ -n $subject ]] && payload_args["sub"]="$subject"
			[[ -n $role ]] && payload_args["role"]="$role"
		
			# Build header
			header='{"alg":"'"$algorithm"'","typ":"JWT"}'
			header_base64=$(echo -n "$header" | openssl base64 -e -A | tr '+/' '-_' | tr -d '=')
		
			# Build payload
			payload_json="{"
			for key in "${!payload_args[@]}"; do
				payload_json+="\"$key\":\"${payload_args[$key]}\","
			done
			payload_json=${payload_json%,} # Remove trailing comma
			payload_json+="}"
			payload_base64=$(echo -n "$payload_json" | openssl base64 -e -A | tr '+/' '-_' | tr -d '=')
		
			# Create signature
			unsigned_token="$header_base64.$payload_base64"
			signature=$(echo -n "$unsigned_token" | openssl dgst -sha256 -hmac "$secret_key" -binary | openssl base64 -e -A | tr '+/' '-_' | tr -d '=')
		
			# Output the JWT
			echo "$unsigned_token.$signature"
			;;
		
		jwt.decode)
		
			# Implement JWT decoding without external 'jwt' tool
		
			local secret_key
			local header payload signature
		
			args=()
			while [[ $# -gt 0 ]]; do
				case $1 in
					with|and) shift ;; # permits more lyrical commands
					--secret|-s|secret) secret_key="$2"; shift 2 ;;
					*) input="$1"; shift ;;
				esac
			done
		
			[[ -z $secret_key ]] && { echo "Error: --secret is required."; return 1; }
			[[ -z $input ]] && { echo "Error: JWT is required."; return 1; }
		
			# Split the JWT into its components
			IFS='.' read -r header_base64 payload_base64 signature_provided <<< "$input"
		
			# Function to add padding for base64 decoding
			base64url_decode() {
				local len=$((${#1} % 4))
				local result="$1"
				if [ "$len" -eq 2 ]; then result="$1"'=='
				elif [ "$len" -eq 3 ]; then result="$1"'='
				fi
				echo -n "$result" | tr '_-' '/+' | openssl base64 -d -A
			}
		
			# Decode header and payload
			header=$(base64url_decode "$header_base64")
			payload=$(base64url_decode "$payload_base64")
		
			# Recreate the signature
			unsigned_token="$header_base64.$payload_base64"
			signature_expected=$(echo -n "$unsigned_token" | openssl dgst -sha256 -hmac "$secret_key" -binary | openssl base64 -e -A | tr '+/' '-_' | tr -d '=')
		
			# Verify the signature
			if [[ "$signature_provided" != "$signature_expected" ]]; then
				echo "Error: Invalid signature."
				return 1
			fi
		
			# Output the decoded payload
			echo "$payload"
			;;

		superscript)
		
			# Convert input to superscript text (including letters where possible)
			sed 's/0/⁰/g; s/1/¹/g; s/2/²/g; s/3/³/g; s/4/⁴/g;
				 s/5/⁵/g; s/6/⁶/g; s/7/⁷/g; s/8/⁸/g; s/9/⁹/g;
				 s/a/ᵃ/g; s/b/ᵇ/g; s/c/ᶜ/g; s/d/ᵈ/g; s/e/ᵉ/g;
				 s/f/ᶠ/g; s/g/ᵍ/g; s/h/ʰ/g; s/i/ⁱ/g; s/j/ʲ/g;
				 s/k/ᵏ/g; s/l/ˡ/g; s/m/ᵐ/g; s/n/ⁿ/g; s/o/ᵒ/g;
				 s/p/ᵖ/g; s/r/ʳ/g; s/s/ˢ/g; s/t/ᵗ/g; s/u/ᵘ/g;
				 s/v/ᵛ/g; s/w/ʷ/g; s/x/ˣ/g; s/y/ʸ/g; s/z/ᶻ/g;
				 s/A/ᴬ/g; s/B/ᴮ/g; s/C/ᶜ/g; s/D/ᴰ/g; s/E/ᴱ/g;
				 s/G/ᴳ/g; s/H/ᴴ/g; s/I/ᴵ/g; s/J/ᴶ/g; s/K/ᴷ/g;
				 s/L/ᴸ/g; s/M/ᴹ/g; s/N/ᴺ/g; s/O/ᴼ/g; s/P/ᴾ/g;
				 s/R/ᴿ/g; s/T/ᵀ/g; s/U/ᵁ/g; s/V/ⱽ/g; s/W/ᵂ/g;
				 s/+/⁺/g; s/-/⁻/g; s/=/⁼/g; s/(/⁽/g; s/)/⁾/g;
				 ' <<< "$input"

			;;

		subscript)

			# Convert input to subscript text (including letters where possible)
			sed 's/0/₀/g; s/1/₁/g; s/2/₂/g; s/3/₃/g; s/4/₄/g;
				 s/5/₅/g; s/6/₆/g; s/7/₇/g; s/8/₈/g; s/9/₉/g;
				 s/a/ₐ/g; s/e/ₑ/g; s/h/ₕ/g; s/i/ᵢ/g; s/j/ⱼ/g;
				 s/k/ₖ/g; s/l/ₗ/g; s/m/ₘ/g; s/n/ₙ/g; s/o/ₒ/g;
				 s/p/ₚ/g; s/r/ᵣ/g; s/s/ₛ/g; s/t/ₜ/g; s/u/ᵤ/g;
				 s/v/ᵥ/g; s/x/ₓ/g;
				 s/A/ₐ/g; s/E/ₑ/g; s/H/ₕ/g; s/I/ᵢ/g; s/J/ⱼ/g;
				 s/K/ₖ/g; s/L/ₗ/g; s/M/ₘ/g; s/N/ₙ/g; s/O/ₒ/g;
				 s/P/ₚ/g; s/R/ᵣ/g; s/S/ₛ/g; s/T/ₜ/g; s/U/ᵤ/g;
				 s/V/ᵥ/g; s/X/ₓ/g;
				 s/+/₊/g; s/-/₋/g; s/=/₌/g; s/(/₍/g; s/)/₎/g;
				 ' <<< "$input"

			;;

		copyright)

			echo "©"

			;;

		degrees)

			echo "°"

			;;

		trademark)

			echo "™"

			;;

		registered)

			echo "®"

			;;

		arrow)

			case $input in
				up|north) echo "↑" ;;
				down|south) echo "↓" ;;
				left|west) echo "←" ;;
				right|east) echo "→" ;;
				upright|northeast) echo "↗" ;;
				upleft|northwest) echo "↖" ;;
				downright|southeast) echo "↘" ;;
				downleft|southwest) echo "↙" ;;
				*) echo -n "Invalid input: $input" ;;
			esac

			;;

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
		
			local pass output_file decrypted status
		
			# Parse arguments
			args=()
			{
				while [[ $# -gt 0 ]]; do
					case $1 in
						with|and|to) shift ;; # permits more lyrical commands
						--pass|-p|pass|password) pass=$2; shift 2 ;;
						--output|-o|output) output_file=$2; shift 2 ;;
						*) args+=("$1"); shift ;;
					esac
				done
			}
			set -- "${args[@]}"
		
			# If $input is a file, read the file
			[[ -f $input ]] && input=$(cat "$input")
		
			[[ -z $pass ]] && echo "Error: --pass is required." && return 1
		
			# Suppress error messages and capture output and exit status
			decrypted=$(echo -n "$input" | base64 -d | openssl enc -d -aes-256-cbc -pbkdf2 -pass pass:"$pass" 2>/dev/null)
		
			# Check if decryption was successful
			if [[ $status -ne 0 || -z "$decrypted" ]]; then
				echo "Error: invalid password"
				return 1
			fi
		
			# Output the decrypted data
			if [[ -n $output_file ]]; then
				echo "$decrypted" > "$output_file"
			else
				echo "$decrypted"
			fi
		
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

		matrix.index)

			local line_index item_index

			line_index=$1
			item_index=$2

			# Read the input from the file or stdin
			[[ -f $input ]] && input=$(cat "$input")

			# get the line at the specified index, given the lines of input
			line=$(echo "$input" | sed -n "$((line_index + 1))p")

			# get the item at the specified index, given the line
			item=$(echo "$line" | awk -v idx="$((item_index + 1))" '{print $idx}')

			echo "$item"
			
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

    local input output_format output_style show args output R G B H S L adjust_H adjust_S adjust_L

    # Capture input from stdin if available
    [[ -p /dev/stdin ]] && input=$(cat)

    # Parse arguments
    args=() && while [[ $# -gt 0 ]]; do
        case $1 in
            show) show='true'; shift ;;
            as) shift ;;
            --hsl|hsl) output_format="hsl"; shift ;;
            --hex|hex) output_format="hex"; shift ;;
            --rgb|rgb) output_format="rgb"; shift ;;
            --raw|raw) output_style="raw"; shift ;;
            -h|--hue|h|hue) adjust_H="$2"; shift 2 ;;
            -s|--saturation|sat|s) adjust_S="$2"; shift 2 ;;
            -l|--lightness|light|l) adjust_L="$2"; shift 2 ;;
            *) args+=("$1"); shift ;;
        esac
    done
    set -- "${args[@]}"

    # Set input color and output format if provided positionally
    [[ -z $input ]] && input=$1 && shift
    [[ -z $output_format ]] && output_format=$1 && shift

    # If no input and HSL values provided via flags, set H, S, L
    if [[ -z "$input" && -n "$adjust_H" && -n "$adjust_S" && -n "$adjust_L" ]]; then
        H="$adjust_H"
        S="$adjust_S"
        L="$adjust_L"
    fi

    # Function to convert HSL to RGB
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
            h = (H % 360) / 360
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

    # Function to convert HEX to RGB
    hex_to_rgb() {
        local hex="${1#\#}"
        if [[ ${#hex} -eq 3 ]]; then
            hex="${hex:0:1}${hex:0:1}${hex:1:1}${hex:1:1}${hex:2:1}${hex:2:1}"
        fi
        printf "%d %d %d\n" "0x${hex:0:2}" "0x${hex:2:2}" "0x${hex:4:2}"
    }

    # Function to convert RGB to HSL
    rgb_to_hsl() {
        awk -v R="$1" -v G="$2" -v B="$3" '
        function max(a,b,c){return (a>b)?((a>c)?a:c):((b>c)?b:c)}
        function min(a,b,c){return (a<b)?((a<c)?a:c):((b<c)?b:c)}
        BEGIN {
            r = R / 255
            g = G / 255
            b = B / 255

            maxVal = max(r, g, b)
            minVal = min(r, g, b)
            l = (maxVal + minVal) / 2

            if (maxVal == minVal) {
                h = s = 0
            } else {
                d = maxVal - minVal
                s = l > 0.5 ? d / (2 - maxVal - minVal) : d / (maxVal + minVal)
                if (maxVal == r) {
                    h = (g - b) / d + (g < b ? 6 : 0)
                } else if (maxVal == g) {
                    h = (b - r) / d + 2
                } else {
                    h = (r - g) / d + 4
                }
                h *= 60
            }

            printf "%d %d %d\n", int(h + 0.5), int(s * 100 + 0.5), int(l * 100 + 0.5)
        }'
    }

    # Function to parse input color
    parse_color_input() {
        if [[ -n "$H" && -n "$S" && -n "$L" ]]; then
            read -r R G B <<< "$(hsl_to_rgb "$H" "$S" "$L")"
            return
        fi
        local input="$1"
        if [[ $input =~ ^\#?([0-9a-fA-F]{6}|[0-9a-fA-F]{3})$ ]]; then
            # Hex color
            read -r R G B <<< "$(hex_to_rgb "$input")"
            read -r H S L <<< "$(rgb_to_hsl "$R" "$G" "$B")"
        elif [[ $input =~ rgb\(\ *([0-9]+)\ *,\ *([0-9]+)\ *,\ *([0-9]+)\ *\) ]]; then
            # RGB function format
            R="${BASH_REMATCH[1]}"
            G="${BASH_REMATCH[2]}"
            B="${BASH_REMATCH[3]}"
            read -r H S L <<< "$(rgb_to_hsl "$R" "$G" "$B")"
        elif [[ $input =~ ^([0-9]+)\ +([0-9]+)\ +([0-9]+)$ ]]; then
            # Raw RGB values
            R="${BASH_REMATCH[1]}"
            G="${BASH_REMATCH[2]}"
            B="${BASH_REMATCH[3]}"
            read -r H S L <<< "$(rgb_to_hsl "$R" "$G" "$B")"
        elif [[ $input =~ hsl\(\ *([0-9]+)\ *,\ *([0-9]+)%\ *,\ *([0-9]+)%\ *\) ]]; then
            # HSL function format
            H="${BASH_REMATCH[1]}"
            S="${BASH_REMATCH[2]}"
            L="${BASH_REMATCH[3]}"
            read -r R G B <<< "$(hsl_to_rgb "$H" "$S" "$L")"
        else
            # Extended color names
            case "${input,,}" in
				maroon) H=0; S=100; L=25 ;;
				crimson) H=0; S=85; L=40 ;;
				scarlet) H=10; S=90; L=45 ;;
				ruby) H=350; S=80; L=50 ;;
				cherry) H=350; S=90; L=55 ;;
				bloodred) H=0; S=100; L=30 ;;
				tomato) H=15; S=85; L=60 ;;
				salmon) H=15; S=75; L=70 ;;
				coral) H=15; S=85; L=65 ;;
				peach) H=30; S=85; L=85 ;;
				apricot) H=30; S=80; L=75 ;;
				tangerine) H=35; S=100; L=50 ;;
				gold) H=45; S=100; L=50 ;;
				bronze) H=30; S=60; L=40 ;;
				beige) H=30; S=20; L=80 ;;
				ivory) H=60; S=5; L=90 ;;
				ivorywhite) H=60; S=5; L=95 ;;
				khaki) H=45; S=25; L=70 ;;
				olive) H=60; S=60; L=40 ;;
				moss) H=90; S=50; L=45 ;;
				forestgreen) H=120; S=100; L=30 ;;
				darkgreen) H=120; S=100; L=25 ;;
				mint) H=150; S=50; L=75 ;;
				pistachio) H=90; S=40; L=70 ;;
				seafoam) H=150; S=50; L=85 ;;
				aqua) H=180; S=100; L=50 ;;
				mintcream) H=150; S=20; L=90 ;;
				jade) H=150; S=50; L=50 ;;
				turquoisegreen) H=165; S=75; L=55 ;;
				emerald) H=150; S=100; L=50 ;;
				peacock) H=180; S=80; L=50 ;;
				tealblue) H=195; S=60; L=60 ;;
				cobalt) H=220; S=80; L=50 ;;
				azureblue) H=210; S=80; L=60 ;;
				royalblue) H=220; S=100; L=50 ;;
				navy) H=210; S=100; L=30 ;;
				midnightblue) H=210; S=100; L=20 ;;
				slateblue) H=240; S=45; L=60 ;;
				lavender) H=240; S=40; L=75 ;;
				periwinkle) H=230; S=40; L=75 ;;
				electricblue) H=210; S=100; L=65 ;;
				denim) H=210; S=50; L=55 ;;
				indianred) H=0; S=60; L=60 ;;
				rosybrown) H=0; S=20; L=70 ;;
				wheat) H=40; S=60; L=80 ;;
				sand) H=40; S=35; L=70 ;;
				coffee) H=30; S=60; L=45 ;;
				chocolate) H=30; S=75; L=35 ;;
				sienna) H=20; S=50; L=40 ;;
				mahogany) H=0; S=70; L=30 ;;
				taupe) H=0; S=10; L=60 ;;
				eggplant) H=270; S=50; L=30 ;;
				aubergine) H=270; S=60; L=35 ;;
				plum) H=270; S=45; L=60 ;;
				lavenderblush) H=340; S=10; L=95 ;;
				mistyrose) H=5; S=20; L=90 ;;
				seashell) H=30; S=10; L=95 ;;
				flamingo) H=10; S=80; L=70 ;;
				blush) H=350; S=50; L=80 ;;
				cottoncandy) H=340; S=50; L=90 ;;
				palegoldenrod) H=45; S=80; L=80 ;;
				lightyellow) H=60; S=80; L=90 ;;
				lightcyan) H=180; S=50; L=90 ;;
				powderblue) H=180; S=30; L=85 ;;
				lightpink) H=340; S=50; L=85 ;;
				red) H=0; S=100; L=50 ;;
				pink) H=340; S=75; L=85 ;;
				vermilion) H=15; S=85; L=55 ;;
				orange) H=30; S=85; L=55 ;;
				amber) H=45; S=100; L=50 ;;
				yellow) H=60; S=100; L=50 ;;
				lime) H=75; S=100; L=50 ;;
				chartreuse) H=90; S=100; L=50 ;;
				harlequin) H=105; S=90; L=55 ;;
				green) H=120; S=100; L=50 ;;
				teal) H=135; S=75; L=50 ;;
				springgreen) H=150; S=100; L=50 ;;
				turquoise) H=165; S=75; L=55 ;;
				cyan) H=180; S=100; L=50 ;;
				skyblue) H=195; S=75; L=60 ;;
				azure) H=210; S=75; L=60 ;;
				blue) H=235; S=100; L=50 ;;
				hanblue) H=250; S=85; L=55 ;;
				indigo) H=265; S=85; L=45 ;;
				violet) H=280; S=85; L=55 ;;
				purple) H=295; S=85; L=50 ;;
				magenta) H=310; S=100; L=50 ;;
				cerise) H=325; S=85; L=60 ;;
				rose) H=340; S=80; L=75 ;;
				white) H=0; S=0; L=100 ;;
				black) H=0; S=0; L=0 ;;
				gray) H=0; S=0; L=50 ;;
				lightgray|silver) H=0; S=0; L=75 ;;
				darkgray|stone|tundora) H=0; S=0; L=25 ;;
                *)
                    echo "Unknown color: $input" >&2
                    exit 1
                    ;;
            esac
            # Convert HSL to RGB
            read -r R G B <<< "$(hsl_to_rgb "$H" "$S" "$L")"
        fi
    }

    # Parse the input color if not already done
    [[ -z "$R" || -z "$G" || -z "$B" ]] && parse_color_input "$input"

    # Ensure H, S, L are within valid ranges
    H=$(( (H + 360) % 360 ))
    [[ $S -lt 0 ]] && S=0 || [[ $S -gt 100 ]] && S=100
    [[ $L -lt 0 ]] && L=0 || [[ $L -gt 100 ]] && L=100

    # Apply HSL adjustments if provided
    [[ -n "$adjust_H" ]] && H="$adjust_H"
    [[ -n "$adjust_S" ]] && S="$adjust_S"
    [[ -n "$adjust_L" ]] && L="$adjust_L"

    # Recalculate RGB after adjustments
    read -r R G B <<< "$(hsl_to_rgb "$H" "$S" "$L")"

    # Default output format
    [[ -z $output_format ]] && output_format="hex"

    # Convert and output in the desired format
    if [[ "$output_format" == "hex" ]]; then
        output=$(rgb_to_hex "$R" "$G" "$B")
    elif [[ "$output_format" == "rgb" ]]; then
        if [[ "$output_style" == "raw" ]]; then
            output="$R $G $B"
        else
            output="rgb($R, $G, $B)"
        fi
    elif [[ "$output_format" == "hsl" ]]; then
        if [[ "$output_style" == "raw" ]]; then
            output="$H $S $L"
        else
            output="hsl($H, $S%, $L%)"
        fi
    fi

    # Display color if requested
    display_color() {
        local r="$1" g="$2" b="$3"
        echo -e "\033[48;2;${r};${g};${b}m    \033[0m"
    }

    if [[ -n $show ]]; then
        display_color "$R" "$G" "$B"
    else
        echo "$output"
    fi
}



date() {

    local input args date_cmd date_format input_format custom_format format_parts timezone

	[[ -p /dev/stdin ]] && input=$(cat)

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
            unix|U|-U|--unix) custom_format=1 && date_format="%s" && shift ;;
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
    
	[[ -z $input ]] && input=$1 && shift

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
    # Unix timestamp
    elif [[ "$input" =~ ^[0-9]+$ ]]; then
        input=$(TZ=$timezone $date_cmd -d "@$input" +"%Y-%m-%d %H:%M:%S")
    fi

    # Format and print the date using the specified format, or default to standard
    if [[ $custom_format == 1 ]]; then
        TZ=$timezone $date_cmd -d "$input" +"$date_format"
    else
        TZ=$timezone $date_cmd "$@"
    fi
}



datecalc() {

	local base_date modifiers result date_cmd

	# Input validation: must have at least two arguments
	if [ "$#" -lt 2 ]; then
		echo "Usage: datecalc <date> <modifiers...>"
		return 1
	fi

	date_cmd="date"
	[[ "$OS" == "macOS" ]] && date_cmd="gdate"

	# First argument is the date in YYYY-MM-DD format
	base_date="$1"
	shift  # Remove the first argument, now "$@" contains the time modifiers

	# Combine base date with the modifiers (e.g., +7 days, -8 hours, etc.)
	modifiers="${*}"

	# Use gdate to calculate the new date with the modifiers
	result=$(gdate -d "$base_date $modifiers" '+%Y-%m-%d %H:%M:%S')

	# Output the result
	echo "$result"

}



download() {

	__deps curl

	local url args output

	[[  -p /dev/stdin ]] && url=$(cat)
	[[ -z $url ]] && url=$1 && shift

	[[ -z $url ]] && echo "No URL provided" && return 1

	[[ $(validate url "$url") == 'false' ]] && echo "Invalid URL" && return 1

	output=$(random)

	args=() && while [[ $# -gt 0 ]]; do
		case $1 in
			--output|-o|to) output=$2; shift 2 ;;
			*) url=$1 && shift ;;
		esac
	done
	set -- "${args[@]}"

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
				echo "Content-Type: text/html; charset=UTF-8"
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



form() {

    process_field() {
        local field_args=("$@")
        local field_name=""
        local field_label=""
        local field_type=""
        local field_required="optional"

        local i=0
        while [[ $i -lt ${#field_args[@]} ]]; do
            case ${field_args[$i]} in
                as)
                    ((i++))
                    field_label=${field_args[$i]}
                    ;;
                is)
                    ;;
                required)
                    field_required="required"
                    ;;
                *)
                    if [[ -z "$field_name" ]]; then
                        field_name=${field_args[$i]}
                    elif [[ -z "$field_type" ]]; then
                        field_type=${field_args[$i]}
                    else
                        field_type="${field_type} ${field_args[$i]}"
                    fi
                    ;;
            esac
            ((i++))
        done
        if [[ -z "$field_label" ]]; then
            field_label="$field_name"
        fi
        fields+=("${field_name}:${field_label}:${field_type}:${field_required}")
    }

    local input args

    [[ -p /dev/stdin ]] && input=$(cat)

    fields=()
    args=()
    while [[ $# -gt 0 ]]; do
        case $1 in
            to) action=$2 && shift 2 ;;
            where|with|is) shift ;;
            title) title=$2 && shift 2 ;;
            description) description=$2 && shift 2 ;;
            *) args+=("$1"); shift ;;
        esac
    done

    [[ -z "$title" ]] && title="Form"
    [[ -z "$description" ]] && description="Please fill out the form below:"
    [[ -z "$action" ]] && action=""

    field_args=()
    for arg in "${args[@]}"; do
        if [[ $arg == "and" ]]; then
            if [[ ${#field_args[@]} -gt 0 ]]; then
                process_field "${field_args[@]}"
            fi
            field_args=()
        else
            field_args+=("$arg")
        fi
    done
    if [[ ${#field_args[@]} -gt 0 ]]; then
        process_field "${field_args[@]}"
    fi

    # Generate HTML form
    echo "<!DOCTYPE html>"
    echo "<html>"
    echo "<head>"
    echo "  <title>${title}</title>"
	echo "  <meta name='viewport' content='width=device-width, initial-scale=1'>"
	echo "  <link rel='stylesheet' href='https://cdn.jsdelivr.net/npm/@picocss/pico@2/css/pico.min.css'>"
    echo "</head>"
    echo "<body>"
	echo "<main class='container' style='margin-top: 8vh;'>"
    echo "  <h1>${title}</h1>"
    echo "  <p>${description}</p>"
    if [[ -n "$action" ]]; then
        echo "  <form method=\"POST\" action=\"${action}\">"
    else
        echo "  <form method=\"POST\">"
    fi

    local first_field=true
    for field in "${fields[@]}"; do
        IFS=':' read -r name label type required <<< "$field"
        echo "    <label for=\"${name}\">${label}:</label>"
        if [[ $type == "textarea" ]]; then
            echo -n "    <textarea style='height: 220px;' name=\"${name}\" id=\"${name}\""
            if [[ $required == "required" ]]; then
                echo -n " required"
            fi
            if $first_field; then
                echo " autofocus></textarea><br/>"
                first_field=false
            else
                echo "></textarea><br/>"
            fi
        else
            echo -n "    <input type=\"${type}\" name=\"${name}\" id=\"${name}\""
            if [[ $required == "required" ]]; then
                echo -n " required"
            fi
            if $first_field; then
                echo " autofocus/><br/>"
                first_field=false
            else
                echo " /><br/>"
            fi
        fi
    done
    echo "    <input type=\"submit\" value=\"Submit\" />"
    echo "  </form>"
	echo "</main>"
    echo "</body>"
    echo "</html>"

    unset -f process_field
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

    # Determine if the file is a media file
	if [[ "$mime_type" == video/* || "$mime_type" == audio/* ]]; then
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
	fi

	output=$(echo "$metadata" | jq '.' | rec from)

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

	# If the location is not in the file, fetch the coordinates from the API
	if [[ "$type" == "city" ]]; then
		coordinates=$(curl -s "https://nominatim.openstreetmap.org/search?format=json&q=$location" | jq -r '.[0].lat + "," + .[0].lon' | awk -F, '{printf "%.6f,%.6f\n", $1, $2}')
	else
		coordinates=$(curl -s "https://ipinfo.io/$location" | jq -r '.loc' | awk -F, '{printf "%.6f,%.6f\n", $1, $2}')
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
				image_url=$(storage upload "$input" --to openai/descriptions/"$image_basename" < /dev/null)
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



lexorank() {

    local command input use_buckets=false

    [[ -p /dev/stdin ]] && input=$(cat)

    # Function to check if a LexoRank value is valid
    isValidLexValue() {
        local value="$1"
        if [[ "$value" =~ ^[0-9a-z]*[1-9a-z]$ ]]; then
            return 0  # valid
        else
            return 1  # invalid
        fi
    }

    # Function to parse a LexoRank string
    parseLexoRank() {
        local lex="$1"
        if [[ "$lex" =~ ^([0-2])\|([0-9a-z]*[1-9a-z])$ ]]; then
            use_buckets=true
            bucket="${BASH_REMATCH[1]}"
            value="${BASH_REMATCH[2]}"
            return 0
        elif [[ "$lex" =~ ^([0-9a-z]*[1-9a-z])$ ]]; then
            use_buckets=false
            value="${BASH_REMATCH[1]}"
            return 0
        else
            echo "Invalid lex string: $lex" >&2
            return 1
        fi
    }

    # Function to increment a character
    incrementChar() {
        local char="$1"
        if [[ "$char" == "z" ]]; then
            echo "-1"
        elif [[ "$char" == "9" ]]; then
            echo "a"
        else
            local ord
            ord=$(printf "%d" "'$char")
            local new_ord=$(( ord + 1 ))
            printf "\\$(printf '%03o' "$new_ord")"
        fi
    }

    # Function to decrement a character
    decrementChar() {
        local char="$1"
        if [[ "$char" == "1" ]]; then
            echo "-1"
        elif [[ "$char" == "a" ]]; then
            echo "9"
        else
            local ord
            ord=$(printf "%d" "'$char")
            local new_ord=$(( ord - 1 ))
            printf "\\$(printf '%03o' "$new_ord")"
        fi
    }

    # Function to increment a LexoRank value
    lexoRankIncrement() {
        local lex="$1"
        parseLexoRank "$lex" || return 1

        local idx=$(( ${#value} - 1 ))
        while [[ $idx -ge 0 ]]; do
            local char="${value:$idx:1}"
            if [[ "$char" == "z" ]]; then
                (( idx-- ))
                continue
            fi
            local prefix="${value:0:$idx}"
            local new_char
            new_char=$(incrementChar "$char")
            if [[ "$new_char" == "-1" ]]; then
                (( idx-- ))
                continue
            fi
            local newVal="$prefix$new_char"
            if $use_buckets; then
                echo "$bucket|$newVal"
            else
                echo "$newVal"
            fi
            return 0
        done
        local newVal="${value}1"
        if $use_buckets; then
            echo "$bucket|$newVal"
        else
            echo "$newVal"
        fi
    }

    # Function to decrement a LexoRank value
    lexoRankDecrement() {
        local lex="$1"
        parseLexoRank "$lex" || return 1

        local length=${#value}
        local char="${value:$((length - 1)):1}"

        if [[ "$char" != "1" ]]; then
            local prefix="${value:0:$((length - 1))}"
            local new_char
            new_char=$(decrementChar "$char")
            local newVal="$prefix$new_char"
            if $use_buckets; then
                echo "$bucket|$newVal"
            else
                echo "$newVal"
            fi
            return 0
        fi

        if [[ $length -gt 1 && ! "${value:0:$((length - 1))}" =~ ^0+$ ]]; then
            local newVal
            newVal=$(cleanTrailingZeros "${value:0:$((length - 1))}")
            if $use_buckets; then
                echo "$bucket|$newVal"
            else
                echo "$newVal"
            fi
            return 0
        fi

        local newVal="0$value"
        if $use_buckets; then
            echo "$bucket|$newVal"
        else
            echo "$newVal"
        fi
    }

    # Function to clean trailing zeros
    cleanTrailingZeros() {
        local str="$1"
        if [[ "$str" =~ ^([0-9a-z]*[1-9a-z])0*$ ]]; then
            echo "${BASH_REMATCH[1]}"
        else
            echo "Invalid lex string: $str" >&2
            return 1
        fi
    }

    # Function to compare two LexoRank values
    lexoRankLessThan() {
        local lex1="$1"
        local lex2="$2"

        parseLexoRank "$lex1" || return 1
        local value1="$value"

        parseLexoRank "$lex2" || return 1
        local value2="$value"

        local len1=${#value1}
        local len2=${#value2}
        local len=$(( len1 > len2 ? len1 : len2 ))

        for (( idx=0; idx<len; idx++ )); do
            local charA="${value1:$idx:1}"
            local charB="${value2:$idx:1}"

            if [[ -z "$charB" ]]; then
                echo "false"
                return 0
            fi
            if [[ -z "$charA" ]]; then
                echo "true"
                return 0
            fi
            if [[ "$charA" < "$charB" ]]; then
                echo "true"
                return 0
            elif [[ "$charA" > "$charB" ]]; then
                echo "false"
                return 0
            fi
        done

        echo "false"
    }

    # Function to find a LexoRank between two LexoRank values
    lexoRankBetween() {
        local lexBefore="$1"
        local lexAfter="$2"

        if [[ -z "$lexBefore" && -z "$lexAfter" ]]; then
            echo "Only one argument may be null" >&2
            return 1
        fi

        if [[ -z "$lexAfter" ]]; then
            lexoRankIncrement "$lexBefore"
            return $?
        fi

        if [[ -z "$lexBefore" ]]; then
            lexoRankDecrement "$lexAfter"
            return $?
        fi

        parseLexoRank "$lexBefore" || return 1
        local before_value="$value"
        local before_bucket="$bucket"

        parseLexoRank "$lexAfter" || return 1
        local after_value="$value"
        local after_bucket="$bucket"

        if $use_buckets && [[ "$before_bucket" != "$after_bucket" ]]; then
            echo "Lex buckets must be the same" >&2
            return 1
        fi

        local less
        less=$(lexoRankLessThan "$lexBefore" "$lexAfter") || return 1
        if [[ "$less" != "true" ]]; then
            echo "${before_value} is not less than ${after_value}" >&2
            return 1
        fi

        local incremented
        incremented=$(lexoRankIncrement "$lexBefore") || return 1
        less=$(lexoRankLessThan "$incremented" "$lexAfter") || return 1
        if [[ "$less" == "true" ]]; then
            echo "$incremented"
            return 0
        fi

        local plus1
        if $use_buckets; then
            plus1="${before_bucket}|${before_value}1"
        else
            plus1="${before_value}1"
        fi
        less=$(lexoRankLessThan "$plus1" "$lexAfter") || return 1
        if [[ "$less" == "true" ]]; then
            echo "$plus1"
            return 0
        fi

        local pre='0'
        while true; do
            local plus
            if $use_buckets; then
                plus="${before_bucket}|${before_value}${pre}1"
            else
                plus="${before_value}${pre}1"
            fi
            less=$(lexoRankLessThan "$plus" "$lexAfter") || return 1
            if [[ "$less" == "true" ]]; then
                echo "$plus"
                return 0
            fi
            pre="${pre}0"
        done
    }

    case "$1" in
        --init|init)
            if [[ "$2" == "--no-buckets" ]]; then
                echo "mmmm"
            else
                echo "0|mmmm"
            fi
            ;;
        increment)
            lex="$2"
            lexoRankIncrement "$lex"
            ;;
        decrement)
            lex="$2"
            lexoRankDecrement "$lex"
            ;;
        lessThan)
            lex1="$2"
            lex2="$3"
            lexoRankLessThan "$lex1" "$lex2"
            ;;
        between)
            lexBefore="$2"
            lexAfter="$3"
            [[ "$lexBefore" == "null" ]] && lexBefore=""
            [[ "$lexAfter" == "null" ]] && lexAfter=""
            lexoRankBetween "$lexBefore" "$lexAfter"
            ;;

		spot|show|detect)

			local verbose
			args=()
			while [[ $# -gt 0 ]]; do
				case $1 in
					change|between|in) shift ;;
					-v|--verbose) verbose=true && shift ;;
					*) args+=("$1") && shift ;;
				esac
			done
			set -- "${args[@]}"

			[[ $# -ne 3 ]] && echo "Error: Invalid number of arguments" >&2 && return 1

			local orig_array mod_array N j moved_item prev_item next_item
		
			read -r -a orig_array <<< "$2"
			read -r -a mod_array <<< "$3"
			N=${#orig_array[@]}
		
			# Check if the two lists contain the same items
			if [[ $(echo "${orig_array[@]}" | tr ' ' '\n' | sort) != $(echo "${mod_array[@]}" | tr ' ' '\n' | sort) ]]; then
				echo "Error: The two lists do not contain the same items." >&2
				return 1
			fi
		
			j=0
			moved_item=""
			prev_item=""
			next_item=""
		
			for ((i=0; i<N; i++)); do
				if [ "$j" -lt "$N" ] && [ "${mod_array[i]}" == "${orig_array[j]}" ]; then
					((j++))
				else
					moved_item="${mod_array[i]}"
					if [ "$i" -gt 0 ]; then
						prev_item="${mod_array[i-1]}"
					fi
					if [ "$i" -lt $((N-1)) ]; then
						next_item="${mod_array[i+1]}"
					fi
					break
				fi
			done
		
			[[ -n $verbose ]] && echo "moved $moved_item between $prev_item and $next_item" && return 0
			echo "$moved_item $prev_item $next_item"
			
			;;
        --help)
            echo "Usage: $0 {increment|decrement|lessThan|between} args..."
            echo ""
            echo "Commands:"
            echo "  increment <lex_value>           Increment the LexoRank value"
            echo "  decrement <lex_value>           Decrement the LexoRank value"
            echo "  lessThan <lex1> <lex2>          Compare two LexoRank values"
            echo "  between <lexBefore> <lexAfter>  Find a LexoRank between two values"
            echo "                                  Use 'null' for one of the values if needed"
            echo "  init [--no-buckets]             Initialize a LexoRank value"
            exit 1
            ;;
        *)
            if [ $# -gt 0 ]; then
                echo "$@" | tr ' ' '\n' | sort
            # if no arguments given, read from stdin
            else
                echo "$input" | tr ' ' '\n' | sort
            fi
            ;;
    esac

    unset -f isValidLexValue
    unset -f parseLexoRank
    unset -f incrementChar
    unset -f decrementChar
    unset -f lexoRankIncrement
    unset -f lexoRankDecrement
    unset -f cleanTrailingZeros
    unset -f lexoRankLessThan
    unset -f lexoRankBetween

}



list() { # alias for `records select ...`

	# capture $input
	if [[ -p /dev/stdin ]]; then input=$(cat); else { input=$1 && shift; } fi

	# require $input
	[[ -z $input ]] && echo "Error: no input provided" && return 1

	# coalesce $input
	[[ -f "$input" ]] && input=$(cat "$input")
	[[ -f "records/$input" ]] && input=$(cat "records/$input")

	echo "$input" | records select "$@"

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



meeting() {

	local args format expires screensharing password notes privacy name participants knocking

	privacy='private'
	door='locked'
	participants='2'
	
	name=$(random 16)

	args=()
	while [[ $# -gt 0 ]]; do
		case $1 in
			--format|-f) format="$2" && shift 2 ;;
			--expires|-e) expires="$2" && shift 2 ;;
			--screensharing|-s) screensharing="$2" && shift 2 ;;
			--password|-P) password="$2" && shift 2 ;;
			--notes|-N) notes="$2" && shift 2 ;;
			--privacy|-v) privacy="$2" && shift 2 ;;
			--name|-n) name="$2" && shift 2 ;;
			--participants|-p) participants="$2" && shift 2 ;;
			--knocking|-k) knocking="$2" && shift 2 ;;
			*) args+=("$1") && shift ;;
		esac
	done
	set -- "${args[@]}"

	# debug everything:
	echo "format: $format"
	echo "expires: $expires"
	echo "screensharing: $screensharing"
	echo "password: $password"
	echo "notes: $notes"
	echo "privacy: $privacy"
	echo "name: $name"
	echo "participants: $participants"
	echo "knocking: $knocking"

	return 0

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

    __deps qrencode zbarimg

    local action link output

    if [[ -p /dev/stdin ]]; then
        link=$(cat)
        action="generate"
    else
        action="${1:-generate}"
        shift
    fi

    if [[ "$action" == "scan" ]]; then
        local image_file="$1"
        if [[ -z "$image_file" ]]; then
            echo "Usage: qr scan <image_file>" >&2
            return 1
        fi
        zbarimg --quiet --raw "$image_file"
    else
        link="${link:-$action}"
        output="$(random string 30).png"
        qrencode -o "$output" "$link"
        echo "$output"
    fi

}



random() {
    local length=16
    local chars_lower="abcdefghijklmnopqrstuvwxyz"
    local chars_upper="ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    local chars_digits="0123456789"
    local chars_symbols='!@#$%^&*+-='
    local chars="$chars_lower$chars_upper$chars_digits"
    local include_symbols=false
    local exclude_symbols=false
    local include_numbers=false
    local include_letters=false
    local only_chars=""
    local required_chars=""
    local required_length=0
    local unprocessed_args=()

    # Parse arguments
    while [[ $# -gt 0 ]]; do
        arg="$1"
        case "$arg" in
            only)
                shift
                while [[ $# -gt 0 ]]; do
                    case "$1" in
                        lowercase) only_chars+="$chars_lower"; shift ;;
                        uppercase) only_chars+="$chars_upper"; shift ;;
                        digits|numbers) only_chars+="$chars_digits"; shift ;;
                        symbols) only_chars+="$chars_symbols"; shift ;;
                        *) break ;;
                    esac
                done
                chars="$only_chars"
                ;;
            include|with)
                shift
                while [[ $# -gt 0 ]]; do
                    case "$1" in
                        symbols) include_symbols=true; shift ;;
                        numbers|digits) include_numbers=true; shift ;;
                        letters) include_letters=true; shift ;;
                        *) break ;;
                    esac
                done
                ;;
            exclude)
                shift
                while [[ $# -gt 0 ]]; do
                    case "$1" in
                        symbols)
                            exclude_symbols=true
                            chars="${chars//[$chars_symbols]/}"
                            shift
                            ;;
                        numbers|digits)
                            chars="${chars//[$chars_digits]/}"
                            shift
                            ;;
                        letters)
                            chars="${chars//[$chars_lower$chars_upper]/}"
                            shift
                            ;;
                        *) break ;;
                    esac
                done
                ;;
            string|and|password)
                shift
                ;;
            number|numbers)
                chars="$chars_digits"
                shift
                ;;
            letters)
                chars="$chars_lower$chars_upper"
                shift
                ;;
            alphanumeric)
                chars="$chars_lower$chars_upper$chars_digits"
                shift
                ;;
            lowercase)
                chars="$chars_lower"
                shift
                ;;
            uppercase)
                chars="$chars_upper"
                shift
                ;;
            alpha)
                chars="$chars_lower$chars_upper"
                shift
                ;;
            *)
                if [[ "$arg" =~ ^[0-9]+$ ]]; then
                    length="$arg"
                    shift
                else
                    unprocessed_args+=("$arg")
                    shift
                fi
                ;;
        esac
    done

    # Adjust character set based on include/exclude options
    [[ $include_symbols == true ]] && chars+="$chars_symbols"
    [[ $exclude_symbols == true ]] && chars="${chars//[$chars_symbols]/}"

    [[ -z $chars ]] && echo "Character set is empty. Cannot generate random string." >&2 && return 1

    get_random_chars() {
        local count=$1
        local char_set=$2
        local output=""
        local char_set_len=${#char_set}
        [[ $char_set_len -eq 0 ]] && echo "Character set is empty in get_random_chars." >&2 && return 1
        for _ in $(seq 1 "$count"); do
            output+=${char_set:RANDOM%char_set_len:1}
        done
        echo "$output"
    }

    # Build required_chars by including at least two characters from each included set
    if [[ $include_symbols == true ]]; then
        required_chars+=$(get_random_chars 2 "$chars_symbols")
        required_length=$((required_length + 2))
    fi
    if [[ $include_numbers == true ]]; then
        required_chars+=$(get_random_chars 2 "$chars_digits")
        required_length=$((required_length + 2))
    fi
    if [[ $include_letters == true ]]; then
        required_chars+=$(get_random_chars 2 "$chars_lower$chars_upper")
        required_length=$((required_length + 2))
    fi

    length_remaining=$((length - required_length))

    if (( length_remaining < 0 )); then
        echo "Length is too short to include required characters." >&2
        return 1
    fi

    # Generate remaining random characters
    remaining_chars=$(get_random_chars "$length_remaining" "$chars")

    # Combine required_chars and remaining_chars
    all_chars="$required_chars$remaining_chars"

    # Shuffle the combined characters
    password=$(echo "$all_chars" | fold -w1 | shuf | tr -d '\n')

    echo "$password"
}



rec() {

	__deps rec2csv csvlook

	local input command output args

	[[ -p /dev/stdin ]] && input=$(cat)

	args=()
	while [[ $# -gt 0 ]]; do
		case $1 in
			to) output_format="$2" && shift 2 ;;
			from) [[ $# -gt 1 ]] && input="$2" && shift 2 || shift ;;
			*) args+=("$1") && shift ;;
		esac
	done
	set -- "${args[@]}"

	[[ -z $input ]] && input=$1 && shift

	[[ -f $input ]] && input=$(cat "$input")
	[[ -z $input ]] && echo "Error: no input provided" && return 1

	[[ $(validate recformat "$input") == 'true' ]] && input_format='recfile'
	[[ $(validate json "$input") == 'true' ]] && input_format='json'
	[[ $(validate csv "$input") == 'true' ]] && input_format='csv'

	[[ $input_format == 'csv' ]] && output_format='recformat'
	[[ $input_format == 'json' ]] && output_format='recformat'

	case $output_format in

		csv)
			[[ $input_format != 'recfile' ]] && echo "Invalid input format (expected recformat)" && return 1
			echo "$input" | rec2csv
			;;

		json)

			[[ $input_format != 'recfile' ]] && echo "Invalid input format (expected recformat)" && return 1

			# Convert recsel output to CSV, then to JSON, and format with jq
			json_output=$(echo "$input" | rec2csv 2>/dev/null | python3 -c 'import csv, json, sys; print(json.dumps([dict(r) for r in csv.DictReader(sys.stdin)]))' 2>/dev/null | jq 2>/dev/null)

			# Check if the conversion was successful
			if [[ $? -eq 0 ]]; then
				# minified json output (no color)
				echo "$json_output" | jq -c -M
			else
				echo "Error: Conversion failed" >&2
			fi

			;;

		recformat)

			[[ $input_format == 'json' ]] && {
				
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
				return 0
			}

			[[ $input_format == 'csv' ]] && {
				output="$(echo "$input" | sed '1s/^\xEF\xBB\xBF//' | csv2rec)"
				[[ -n $1 ]] && echo "$output" >> "$1" || echo "$output"
				return 0
			}
			;;

	esac

}



recmove() {

	local dataset records args
	local primary_record primary_key primary_value entity rank_column

	[[ -p /dev/stdin ]] && dataset=$(cat)

	records=()
	args=()

	while [[ $# -gt 0 ]]; do
		case "$1" in
			in) dataset="$2" && shift 2 ;;
			by) primary_key="$2" && shift 2 ;;
			using) rank_column="$2" && shift 2 ;;
			between)
				shift
				records+=("$1") && shift
				[[ $1 == 'and' ]] && shift
				records+=("$1") && shift
				;;
			*) args+=("$1") && shift ;;
		esac
	done
	set -- "${args[@]}"

	[[ -z $dataset ]] && echo "No dataset provided" && exit 1

	[[ -n $1 ]] && primary_record=$1

	entity=$(echo "$primary_record" | cut -d':' -f1)
	primary_value=$(echo "$primary_record" | cut -d':' -f2)

	# # #

	is_recfile=$(validate recfile "$dataset")
	is_sqlite=$(validate sqlite "$dataset")
	is_recformat=$(validate recformat "$dataset")

	format=$(
		[[ $is_recfile == 'true' ]] && echo recfile
		[[ $is_recformat == 'true' ]] && echo recformat
		[[ $is_sqlite == 'true' ]] && echo sqlite
	)

	case $format in

		recfile)

			args=()
			[[ -n $entity ]] && args+=("-t" "$entity")

			# get record rank of records
			local records ranks new_rank recsel_output
			for record in "${records[@]}"; do
				recsel_output=$(recsel "$dataset" -e "$primary_key = '$record'" -P "$rank_column")
				ranks+=("$recsel_output")
			done

			new_rank=$(lexorank between "${ranks[@]}")

			# update primary record with new rank
			recset "$dataset" -e "$primary_key = '$primary_value'" -f "$rank_column" -s "$new_rank"

			;;

		sqlite)

			# pending

			;;

		recformat)

			# pending

			;;

		*)
			
			echo "Invalid format"
			exit 1

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



report() {
    __deps csvlook

    local input args title=""
    local -A notes_map
    local note_counter=1

    [[ -p /dev/stdin ]] && input=$(cat) || input="$1"
    [[ -z "$input" ]] && echo "Error: no input provided" && return 1
    [[ -f "$input" ]] && input=$(cat "$input")

    args=()
    notes=()

    while [[ $# -gt 0 ]]; do
        case "$1" in
			with|and) shift ;; # permits lyrical command syntax
            note)
                # Require two args: column name and note text
                [[ $# -lt 3 ]] && echo "Error: not enough arguments for note" && return 1
                local col_name="$2"
                local note_text="$3"
                notes_map["$col_name"]="$note_text"
                shift 3
                ;;
            title)
                # Require one arg: title text
                [[ $# -lt 2 ]] && echo "Error: not enough arguments for title" && return 1
                title="$2"
                shift 2
                ;;
            *) args+=("$1") && shift ;;
        esac
    done

    set -- "${args[@]}"

    # Read the CSV header
    IFS= read -r header_line <<< "$input"
    IFS=',' read -ra headers <<< "$header_line"

    # Function to convert a number to superscript
    to_superscript() {
        local num="$1"
        local superscript_digits=("⁰" "¹" "²" "³" "⁴" "⁵" "⁶" "⁷" "⁸" "⁹")
        local result=""
        local digit
        for (( i=0; i<${#num}; i++ )); do
            digit="${num:$i:1}"
            result+="${superscript_digits[$digit]}"
        done
        echo -n "$result"
    }

    # Map notes to columns and modify headers
    for i in "${!headers[@]}"; do
        col="${headers[i]}"
        # Remove quotes from header
        col_cleaned="${col%\"}"
        col_cleaned="${col_cleaned#\"}"
        if [[ -n "${notes_map[$col_cleaned]}" ]]; then
            superscript=$(to_superscript "$note_counter")
            headers[i]="${col}${superscript}"
            notes+=("${superscript} ${notes_map[$col_cleaned]}")
            ((note_counter++))
        fi
    done

    # Reconstruct the modified header line
    modified_header=$(IFS=,; echo "${headers[*]}")

    # Combine modified header with the rest of the input
    output="$modified_header"$'\n'"$(tail -n +2 <<< "$input")"

    # Display the title if set
    if [[ -n "$title" ]]; then
        echo "## $title"
        echo
    fi

    # Display the table
    echo "$output" | csvlook -I

    # Display the notes
    if [[ ${#notes[@]} -gt 0 ]]; then
        echo
        for note in "${notes[@]}"; do
            echo "$note"
        done
    fi
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



silence() {

	local input

	if [[ -p /dev/stdin ]]; then input=$(cat); else input=$1; fi
	echo "$input" >> /dev/null

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



storage() {

    local input command args arg privacy to

    command=$1 && shift

	privacy='public-read'
	to="/uploads/$(random string 32)"

    args=() && while [[ $# -gt 0 ]]; do
        case $1 in
            --to|-t|to) to=$2 && shift 2 ;;
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

    local scope action field operator value limit fields pick output_file
    local args=()
    local params=()

    [[ -p /dev/stdin ]] && action=$(cat)

    # Parse arguments
    while [[ $# -gt 0 ]]; do

        case $1 in

			-f|fields) fields="$2" && shift 2 ;;

            -p|pick) pick=$2 && shift 2 ;;

            limit) limit=$2 && shift 2 ;;

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

            like) operator='~' && shift ;;

            !=|isnt) operator='!=' && shift ;;

			payments) scope='payment_intents' && shift ;;

            customers|subscriptions|products|\
			invoices|prices|charges|refunds|payouts|\
			balance_transactions|disputes|transfers|payment_intents)
                scope=$1
                shift
                ;;

            list|create|update|delete) action=$1 && shift ;;

            *) args+=("$1") && shift ;;

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

	if [[ -n $fields ]]; then
		cat "$output_file" | rec from | recsel -p "$fields"
    elif [[ -n $pick ]]; then
        cat "$output_file" | rec from | recsel -P "$pick"
    else
        cat "$output_file" | rec from
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
			# shellcheck disable=SC2119
			echo "$input" | lowercase
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

			while [ "$runs_remaining" -gt 0 ]; do

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
					if [ "$runs_remaining" -eq 0 ]; then
						echo "Sorry, we're having a hard time responding to this request. Maybe try rephrasing."
					fi
				fi

			done

			[[ $explain_reasoning == 'true' ]] && echo "$response" | jq -r '.reasoning'

			echo "$response" | jq -r '.translation'

			;;

	esac

}



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

		recformat) echo "$input" | recfix &>/dev/null && output="true" ;;
		recfile) recfix "$input" &>/dev/null && output="true" ;;
		sqlite3|sqlite) { [[ -f "$input" ]] && head -c 16 "$input" | grep -q "SQLite format 3" ; } && output="true" ;;

		json|json-format)

			[[ -f $input ]] && input=$(cat "$input")

			if jq . <<< "$input" &>/dev/null; then
				output="true"
			fi

			;;

		csv|csv-format)

			[[ -f $input ]] && input=$(cat "$input")

			echo "$input" | csvclean -a &>/dev/null && output="true"

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
			
			while [ "$runs_remaining" -gt 0 ]; do
				response="$(openai chat "You are an expert validator. I will provide a condition and a source material. Your task is to determine if the source material satisfies the condition. Respond with one JSON object containing two properties: 'reasoning <string>' and 'answer <true/false boolean>' where 'reasoning' contains your reasoning and 'answer' is either true or false, indicating whether the source material satisfies the condition. - - - ###--### - - - CONDITION: $condition - - - SOURCE MATERIAL: $source_material - - - ###--### - - - So... what do you say? True or false; does the source material satisfy the condition? Remember, respond only with a one dimensional JSON object (containing just the 'reasoning' and 'answer' properties)." --model "$model" --json)"
			
				if [[ $(echo "$response" | jq 'keys | length') -eq 2 && ( $(echo "$response" | jq -r '.answer') == 'true' || $(echo "$response" | jq -r '.answer') == 'false' ) ]]; then
					runs_remaining=0
				else
					runs_remaining=$((runs_remaining - 1))
					if [ "$runs_remaining" -eq 0 ]; then
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

		json=$(curl -sL "wttr.in/$location?format=j1")

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
            ;;
        tomorrow|--tomorrow)
            response=$(curl -sL "wttr.in/${location}?uQ${color_code}F2" | sed -n '/┌─────────────┐/,/└─────────────┘/p' | tail -n 10)
            ;;
        forecast|--forecast)
            response=$(curl -sL "wttr.in/${location}?uQ${color_code}F3" | sed -n '/┌─────────────┐/,/└─────────────┘/p')
            ;;
        * )
            response=$(curl -sL "wttr.in/${location}?uQ${color_code}F" | head -n 5)
    esac

    echo "$response"

}



youtube() {

    local command quality thumbnail_quality url

    command=$1 && shift

    [[ -p /dev/stdin ]] && url=$(cat)
    [[ -z $url ]] && url=$1 && shift

    quality="1080" # Default quality for videos
    thumbnail_quality="0" # Default quality for thumbnails (0 for default hd)

    if [[ ! "$url" =~ ^(https?://)?(www\.)?(m\.)?(youtube\.com|youtu\.be|youtube-nocookie\.com) ]]; then
        echo "Invalid YouTube URL"
    fi

    # Function to download video
    download_video() {

        local output_path
        local final_output
        local output_file
        
        output_path=$(random string 32)
        
        # build args
        args=()
        args+=("--no-warnings")
        [[ "$format" == 'mp3' ]] && args+=("--extract-audio" "--audio-format" "mp3")
        args+=("--output" "$output_path.%(ext)s")
        args+=("--format" "bestvideo[height<=$quality]+bestaudio/best[height<=$quality]")
        args+=("$url")
        
        # execute command silently and capture exit status
        yt-dlp "${args[@]}" >/dev/null 2>&1 && final_output="0" || final_output="1"
        
        # Output the relative path if successful
        if [ "$final_output" -eq "0" ]; then
            # Find the downloaded file
            output_file=$(ls "$output_path".*)
            echo "$output_file"
        else
            echo "Error: Failed to download video" >&2
        fi
        
    }

    # Function to extract YouTube video ID
    extract_id() {

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
        output_path="$BARE_HOME/downloads/$random_filename"
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



recloop() {

    local input script record field value args=()

	set_variables() {
		for key in "${!record[@]}"; do
			export "$key"="${record[$key]}"
		done
	}

	unset_variables() {
		for key in "${!record[@]}"; do
			unset "$key"
		done
	}

	process_record() {
		set_variables
		if [[ -f "$script" ]]; then
			source "$script"
		else
			eval "$script"
		fi
		unset_variables
	}

    # Read arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            with|in) shift ;;
            --recordset|over) input=$2; shift 2 ;;
            --script|script) script=$2; shift 2 ;;
            *) args+=("$1"); shift ;;
        esac
    done
    set -- "${args[@]}"
    [[ -z $script ]] && script=$1 && shift
    [[ -z $input ]] && input=$(cat)

    [[ -z $script ]] && { echo "Error: missing script"; return 1; }

    # Determine if input is CSV and convert if necessary
    if [[ $(validate csv "$input") == 'true' ]]; then
        rec_data=$(csv2rec "$input")
    else
        rec_data=$(cat "$input")
    fi

    # Declare an associative array
    declare -A record

    # Read and process records
    while IFS= read -r line || [[ -n $line ]]; do
        if [[ -z $line ]]; then
            process_record
            record=()
        else
            if [[ $line =~ ^([^:]+):\ (.*) ]]; then
                field="${BASH_REMATCH[1]}"
                value="${BASH_REMATCH[2]}"
                record["$field"]="$value"
            fi
        fi
    done <<< "$(echo "$rec_data" | recsel "$@")"

    # Process the last record
    [[ ${#record[@]} -gt 0 ]] && process_record

	unset -f set_variables
	unset -f unset_variables
	unset -f process_record

}



# aliases & delegations

ai() { openai "$@" ; return 0 ; }

capitalize() { transform "$@" --capitalize; return 0; }

clip() { clipboard "$@" ; return 0 ; }

decrypt() { codec decrypt "$@"; return 0; }

encrypt() { codec encrypt "$@"; return 0; }

filetype() { examine "$@" -p type ; return 0 ; }

filepath() { examine "$@" -p path ; return 0 ; }

filesize() { examine "$@" -p size ; return 0 ; }

hash() { codec hash "$@"; return 0; }

hash.verify() { codec hash.verify "$@"; return 0; }

lowercase() { transform "$@" --lowercase ; return 0 ; }

password() { random 16 "$@"; return 0; }

round() { math round "$@" ; return 0 ; }

squish() { transform "$@" --squish ; return 0 ; }

trim() { transform "$@" --trim ; return 0 ; }

upload() { storage upload "$@" ; return 0 ; }

uppercase() { transform "$@" --uppercase ; return 0 ; }





# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

case $1 in

	--upgrade)

		[[ -f "$(which bare.sh)" ]] && {
			echo ""
			echo "   - - - "
			echo ""
			echo "   Upgrading bare.sh..."
			echo ""
			# if sudo password is needed
			[[ ! -w "$(which bare.sh)" ]] && echo "   Please enter your password to continue."
			curl -sL "https://raw.githubusercontent.com/matthewlarkin/bare.sh/refs/heads/root/bare.sh" | sudo tee "$(which bare.sh)" > /dev/null
			echo ""
			echo "   ✅ has been upgraded to the latest version!"
			echo ""
			echo "   - - - "
			echo ""
			exit 0
		}

		;;

	*) __isBareCommand "$1" && __bareStartUp && "$@" && exit 0 ;;

esac

exit 1