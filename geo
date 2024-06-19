#!/usr/bin/env bash

./deps curl jq
touch .cache/geo.txt

format_location() {
	if [[ -z $1 ]]; then
		curl -sL https://ipinfo.io/ip
	else
		# Replace comma space with plus before encoding the location
		local location=${1//, /+}
		./codec url.encode "$location"
	fi
}

get_coordinates() {
	local location=$1
	local type=$2
	local decimals=${3:-2}
	local coordinates

	# Check if the location is in the geo.txt file
	if grep -q "^$location " .cache/geo.txt; then
		# If the location is in the file, get the coordinates from the file
		coordinates=$(grep "^$location " .cache/geo.txt | cut -d ' ' -f 2)
	else
		# If the location is not in the file, fetch the coordinates from the API
		if [[ $type == "city" ]]; then
			coordinates=$(curl -s "https://nominatim.openstreetmap.org/search?format=json&q=$location" | jq -r '.[0].lat + "," + .[0].lon' | awk -F, '{printf "%.6f,%.6f\n", $1, $2}')
		else
			coordinates=$(curl -s "https://ipinfo.io/$location" | jq -r '.loc' | awk -F, '{printf "%.6f,%.6f\n", $1, $2}')
		fi

		# Add the location and coordinates to the geo.txt file
		echo "$location $coordinates" >> .cache/geo.txt
	fi

	# Format the coordinates to the requested number of decimal places
	coordinates=$(echo "$coordinates" | awk -v decimals=$decimals -F, '{printf "%.*f,%.*f\n", decimals, $1, decimals, $2}')

	# Output the coordinates
	echo "$coordinates"
}

location=$(format_location "$1")
[[ $location =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && type="ip" || type="city"

get_coordinates "$location" "$type" "$2"