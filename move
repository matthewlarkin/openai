#!/usr/bin/env bash

# Initialize variables
destination=""
outside_bare=false
index=1

# Search for --outside-bare and adjust accordingly
for arg in "$@"; do
  if [[ $arg == "--outside-bare" ]]; then
    outside_bare=true
    # Capture the next argument as the destination
    outside_bare_index=$(($index + 1))
    destination="${!outside_bare_index}"
    # Remove --outside-bare and its argument
    set -- "${@:1:$index-1}" "${@:$index+2}"
    break
  fi
  let index++
done

# Determine file path and destination based on remaining arguments
if [[ $# -eq 0 ]]; then
  # Read file path from stdin if no arguments left
  read file
elif [[ $# -eq 1 ]]; then
  # If only one argument, it's the destination; read file path from stdin
  if [ "$outside_bare" = false ]; then
    destination=".var/$1"
  else
    destination="$1"
  fi
  read file
elif [[ $# -eq 2 ]]; then
  # If two arguments, first is file path, second is destination
  file="$1"
  if [ "$outside_bare" = false ]; then
    destination=".var/$2"
  else
    destination="$2"
  fi
fi

# Ensure destination is not empty
if [[ -z "$destination" ]]; then
  echo "Error: Destination not specified."
  exit 1
fi

# Ensure $file is in the .var directory and exists
if [[ $file != .var/* ]] || [ ! -f "$file" ]; then
  if [[ $file != .var/* ]]; then
    echo "Error: File path must be in the .var directory."
  elif [ ! -f "$file" ]; then
    echo "Error: File does not exist."
  fi
  exit 1
fi

mv "$file" "$destination"