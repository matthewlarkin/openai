#!/usr/bin/env bash

cd "$(dirname "$0")" && source .lib/barerc || exit 1

deps sqlite3

# initialize db if needed
[[ ! -f .var/www/sqlpage/sqlpage.db ]] && ./bare serve --briefly

while [[ "$#" -gt 0 ]]; do
  case $1 in
	--ascii) MODE="ascii" ;;
	--box) MODE="box" ;;
	--column) MODE="column" ;;
	--csv) MODE="csv" ;;
	--html) MODE="html" ;;
	--insert) MODE="insert" ;;
	--json) MODE="json" ;;
	--line) MODE="line" ;;
	--list) MODE="list" ;;
	--markdown) MODE="markdown" ;;
	--qbox) MODE="qbox" ;;
	--quote) MODE="quote" ;;
	--table) MODE="table" ;;
	--tabs) MODE="tabs" ;;
	--tcl) MODE="tcl" ;;
	*) statement="$1" ;;
  esac
  shift
done

if [[ -z "$statement" ]]; then
  statement=""
  while IFS= read -r -d '' line || [[ -n "$line" ]]; do
	statement="$statement$line\n"
  done < <(cat)
fi

[[ -n $MODE ]] && statement=".mode $MODE\n$statement"

# Use printf to handle the newlines correctly
printf "%b" "$statement" | sqlite3 .var/www/sqlpage/sqlpage.db