# `bare`

🎥 YouTube: [@bareDeveloper](https://youtube.com/@bareDeveloper)  
🔖 Website: [bare.sh](https://bare.sh)  

## Index

- **Overview**
- **Install**
- **Configuration**
- **Bare terminal**
- **Sample usage**
- **Bare scripts**
- **Contributing**

- - -

## Overview

`bare.sh` (aka `bare`) aims to simplify bash scripting through easy-to-write, easy-to-read scripting. The syntax and list of options is intentially kept simple (*baren*) so you can focus and write with simplicity.

Don't let simplicity fool you; `bare` is a powerful automation tool in the right hands, as `bare` can invoke user `bare scripts` (which are just `bash` scripts with `bare` syntax available), making the system highly extensible.

`bare` takes inspiration from the Unix philosophy, accepting input from `stdin` and output to `stdout` wherever possible and treats plaintext as the universal interface.

## Install

```bash
git clone https://github.com/matthewlarkin/bare.sh ~/bare.sh

# optional alias for easy reference
echo 'alias bare="~/bare.sh/bare.sh"' >> ~/.bashrc
```

## Configuration

### RC file
Bare sets some default global variables and functions and sources `~/.barerc` to pick up any user overwrites or additions (*`bare` creates this file if it doesn't already exist, setting secure permissions to `600`, useful for any user secrets, api keys, etc*).

If you'd like to add your own global variables or functions, you can include them in your `~/.barerc` file–just be sure to *`export`* them.

**Sample `~/.barerc`**
```bash
# Core variable overwrites

STRIPE_PUBLIC_KEY="xxxxx"
STRIPE_SECRET_KEY="xxxxx"

OPENAI_API_KEY="xxxxx-xxxx-xxxxx"

BARE_EMAIL_FROM="xxxxx"
POSTMARK_API_TOKEN="xxxxx-xxxx-xxxxx"

# Custom values (note the exports); all downstream
# bare scripts have access to them now. 👍

MY_VAR="xxxxx"

function myHelloFunction() {
	echo "Hello $1"
}

export MY_VAR
export -f MY_OWN_FUNCTION
```

### Bare dependencies

Some third-party tools are required for some functions, mostly classic tools like `curl` and `jq`, but sometimes more obscure ones like `yt-dlp` or `recutils`. `bare` will alert you that you don't have these installed, but if you'd like to get a head start, you can install these tools with your favorite package manager (such as `apt-get` or `snap` for Ubuntu or `brew` (homebrew) for Mac).

```md
- curl (version 7.82+)
- jq
- GNU coreutils (if using macOS)
- recutils
- sqlite3
- pandoc
- yq
- xxd
- php
- awk
- perl
- openssl
- magick
- ffmpeg
- qrencode
- yt-dlp
- csvkit
- sqlpage
```

## Bare terminal

There are two ways to use bare:

1. Inline, calling `bare.sh` itself
2. Interactively, via the `bare terminal`

`./bare.sh <options>`
```terminal
cd bare.sh
./bare.sh random string 30
xj95iUQK2KGHVap8YSUOX0l9xWbqQl
```

`bare terminal`
```terminal
cd bare.sh
./bare.sh -t
entering bare terminal. type exit when ready to leave.
🐻 bare > random string 30
a3THAyzHiVPwbP8gyY0R1xRIKMsJ5d
```

## Quick samples

For these examples, we're using the `bare terminal`.

```bash
> openai "Hello there, how are you?"
> Hello! How can I assist you today?

> codec url.encode "Hello! How can I assist you today?"
> Hello%21%20How%20can%20I%20assist%20you%20today%3F%0A

> codec form-data.decode 'user=%7B%22first_name%22%3A%22Matthew%22%2C%22last_name%22%3A%22Larkin%22%7D'
> {"first_name":"Matthew","last_name":"Larkin"}

> email --to "matthew@groveos.com" --subject "Bare suggestion" --body "Hi there, I have an idea for bare!"
> wwnzz9lw-adf6-447d-b30b-slax67kzuhlo
```

## Bare scripts

With `bare`, we can create our own custom *bare scripts*. These scripts are just bash scripts with access to the `bare` syntax. These scripts can help you automate any number of simple or complex workflows.

To create a `bare` script, navigate to your `.var/scripts` directory, create a file (no file extension necessary), and then write your `bare` commands and/or bash commands. No need to make it executable`bare` will handle this for you.

Here's a sample script called `sample` in the `.var/scripts` directory. We added a shebang at the front for better syntax highlighting in VS Code, but shebangs here are not necessary either.

**`.var/scripts/sample`**
```bash
#!/usr/bin/env bash

echo "We are using: $(ls | codec lines.index 0)"
random string 30
openai chat "Hi there, I'm using a new toolkit called bare.sh, have you heard of it?"
```

You can now run that script from the `bare` terminal or from an inline `./bare` call.

**`bare` terminal**

```terminal
🐻 bare > run sample
We are using: bare.sh
04Gg4gyS02X4skSWzQcmMFuBmZD6dG
Hello! I haven't heard of a toolkit by the name "bare.sh." Could you provide more information about it so I can assist you better?
```

This is a very powerful feature. We'll have more examples on this soon.

- - - - -

## Contributing

Thanks for your interest in contributing to `bare`! Whether you have coding chops or not, your input is welcome. Here are two easy ways you can contribute:

### 1. No Code? No Problem!

If you have ideas, suggestions, or you've bumped into an issue, please let us know. Just open a GitHub issue and let us know what's on your mind. Here are some examples:

- "Hey, I was expecting this behavior, but it's not working."
- "Hey, I'd love to see this feature."
- "I found a bug! Here's what happened..."

Please be descriptive, but don't feel like you have to adhere to any specific formality.

### 2. Got Code? Awesome!

Before you submit a code suggestion or pull request, please review the style guide below.

#### Style Guide

**Use functions where possible**

Use functions and avoid putting variables in global scope where possible. If using a function within a function, unset the child function at the tail end of the parent function (essentially making the child a private function).

```bash
function demo() {

    local input

    input=$1

    reciteDemo() {
		echo "You entered: $1"
    }

    reciteDemo "$input"

    unset -f reciteDemo
}
```

**Quoting variables and values**

- don't quote while assigning variables
- do quote when referencing variables

```bash
log=$1

if [[ -f "$file" ]]; then
	echo "$log" >> "$file"
fi
```

**Option culling**

We often cull options and their values from argument lists. This helps us deductively reason about remaining arguments and their meaning in the context of a command.

While culling use the `args=() && while [[ $# -gt 0 ]]` approach outline here:

```bash
function demo() {

	local args
	local name
	local email
	local phone
	local notes

	args=() && while [[ $# -gt 0 ]]; do
		case $1 in
			--name|-n) name=$1
			--email|-e) email=$1
			--phone|-p) phone=$1
			*) args+=("$1")
		esac && shift
	done && set -- "${args[@]}"

	notes=$1

	echo "Name: $name, Email: $email, Phone: $phone along with the notes: $notes"

}
```
