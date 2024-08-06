#!/usr/bin/env bash

[[ -t 0 ]] || file=$(cat)

[[ -z $file && $# != 2 ]] || [[ -n $file && $# != 1 ]] && echo "Error: expected two arguments." && exit 1

[[ -n $file ]] && destination="$1"
[[ -z $file ]] && file="$1" && destination="$2"

[[ ! -f "$file" ]] && echo "Error: file '$file' does not exist." && exit 1

mv "$file" "$destination"