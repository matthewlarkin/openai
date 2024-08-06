#!/usr/bin/env bash

[[ -t 0 ]] && file=$1 || file=$(cat)

[[ $# == 2 ]] && destination="$2" || destination="$1"

[[ ! -f "$file" ]] && echo "Error: file '$file' does not exist." && exit 1
[[ -z $destination ]] && echo "Error: destination not provided." && exit 1

mv "$file" "$destination"