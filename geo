#!/usr/bin/env bash

cd "$(dirname "$0")" && source .lib/barerc || exit 1

deps curl jq
touch .var/.cache/geo.txt

format_location() {
	local location

	if [[ -z $1 ]]; then
		location=$(curl -sL https://ipinfo.io/ip)
	else
		location=${1//, /+}
		echo "$location"
	fi
}

get_coordinates() {

	local location
	local type
	local decimals
	local coordinates

	remaining_args=() && while [[ $# -gt 0 ]]; do
		case $1 in
			--decimals) decimals=$2 && shift 2 ;;
			--type) type=$2 && shift 2 ;;
			--location) location=$2 && shift 2 ;;
			*) remaining_args+=("$1") && shift ;;
		esac
	done && set -- "${remaining_args[@]}"

	[[ -z $location ]] && location=${1:-asheville-nc}
	[[ -z $type ]] && type="city"
	[[ -z $decimals ]] && decimals=2

	location=$(format_location "$location")
	[[ $location =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && type="ip" || type="city"

	# Check if the location is in the geo.txt file
	if grep -q "^$location " .var/.cache/geo.txt; then
		# If the location is in the file, get the coordinates from the file
		coordinates=$(grep "^$location " .var/.cache/geo.txt | cut -d ' ' -f 2)
	else
		# If the location is not in the file, fetch the coordinates from the API
		if [[ $type == "city" ]]; then
			coordinates=$(curl -s "https://nominatim.openstreetmap.org/search?format=json&q=$location" | jq -r '.[0].lat + "," + .[0].lon' | awk -F, '{printf "%.6f,%.6f\n", $1, $2}')
		else
			coordinates=$(curl -s "https://ipinfo.io/$location" | jq -r '.loc' | awk -F, '{printf "%.6f,%.6f\n", $1, $2}')
		fi

		# Add the location and coordinates to the geo.txt file
		echo "$location $coordinates" >> .var/.cache/geo.txt
	fi

	# Format the coordinates to the requested number of decimal places
	coordinates=$(echo "$coordinates" | awk -v decimals="$decimals" -F, '{printf "%.*f,%.*f\n", decimals, $1, decimals, $2}')

	# Output the coordinates
	echo "$coordinates"
}

function main() {

	get_coordinates "$@"

}

run_script "$@"