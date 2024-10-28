# `bare.sh`

🎥 YouTube: [@bareDeveloper](https://youtube.com/@bareDeveloper)  
🔖 Website: [bare.sh](https://bare.sh)  

## Index

- **Overview**
- **Install**
- **Configuration**
- **Learn**
- **Contributing**

- - -

## Overview

`bare.sh` (aka `bare`) aims to give individuals a simple toolkit for expressing common business tasks, such as creating and managing records, interacting with AI assistants, and sending emails.

In the right hands, `bare` can be a powerful automation tool, particularly when written in a bash scripting environment.

## Install

```bash
git clone https://github.com/matthewlarkin/bare.sh ~/bare.sh

# optional alias for easy reference
echo 'alias bare="$HOME/bare.sh/bare.sh"' >> ~/.bashrc
```

## Configuration

### `~/.barerc` file
You can set default global variables in your `$HOME/.barerc` file. This file is sourced by `bare` on startup and can be used to set default values for your scripts.

**Sample `~/.barerc`**
```bash
# Core variable overwrites

STRIPE_PUBLIC_KEY="xxxxx"
STRIPE_SECRET_KEY="xxxxx"

OPENAI_API_KEY="xxxxx-xxxx-xxxxx"

BARE_EMAIL_FROM="xxxxx"
POSTMARK_API_TOKEN="xxxxx-xxxx-xxxxx"

SMTP_SERVER="mail.smtp2go.com"
SMTP_PORT="2525"
SMTP_USER="xxxxx"
SMTP_PASS="xxxxx"
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

## Learn

Please refer to the [samples](samples.md) file for a collection of some of the more useful commands to get you started.

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

	local args name email phone notes

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
