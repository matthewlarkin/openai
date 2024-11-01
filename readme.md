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

`bare.sh` (aka `bare`) aims to give individuals a simple and expressive toolkit for completing common tasks, like saving and managing records, working with AI, sending emails, making passwords, downloading YouTube videos, and much more.

The aim is to provide a bare bones language that you can write and extend via bash scripts. Here are some examples of some simple tasks with and without `bare.sh`:

```bash
### Download a file ###

# with bare.sh
bare.sh download https://install.bare.sh to ~Desktop/download.txt

# without bare.sh
curl -sL https://install.bare.sh -o ~Desktop/download.txt


### OpenAI request ###

# with bare.sh
bare.sh openai "Hello, how are you?"

# without bare.sh
curl https://api.openai.com/v1/chat/completions \
  -H "Authorization: Bearer YOUR_OPENAI_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{ \
    "model": "gpt-3.5-turbo",
    "messages": [{"role": "user", "content": "Hello, how are you?"}]
  }' | jq -r '.choices[0].message.content'
```

In the right hands, `bare` can be a powerful automation tool, particularly when written in a bash scripting environment.

## Install

**Quick Install**

```bash
curl -sL https://install.bare.sh | bash
```

**Manual Install**

```bash
git clone https://github.com/matthewlarkin/bare.sh
sudo mv bare.sh/bare.sh /usr/local/bin/bare.sh
sudo chmod +x /usr/local/bin/bare.sh
```

## Configuration

### `~/.barerc` file

Set defaults in your `$HOME/.barerc` file. This file is sourced by `bare.sh` on each run.

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

Some third-party tools are required for some functions (mostly big names like `curl` and `jq` but some more obscure ones too, like `recutils`. You can install these tools with your favorite package manager (such as `apt-get` or `snap` for Ubuntu or `brew` (homebrew) for Mac).

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
```

## Learn

Learn by example at: [https://learn.bare.sh](https://learn.bare.sh).

That URL redirect here to the [samples](samples.md) file, which will be updated as the featureset grows over time.

More formal tutorials and documentation may be available in the future, but for now this is the best place to start.

- - - - -

## Contributing

Thanks for your interest in contributing to `bare.sh`! Whether you code or not, your input is welcome. Here are two easy ways you can contribute:

### 1. Non-coders

If you have ideas please let us know. Open a GitHub issue and let us know what's on your mind, such as:

- "Hey, I was expecting this behavior, but it's not working."
- "Hey, I'd love to see this feature."
- "I found a bug! Here's what happened..."

Please be descriptive, but don't feel like you have to adhere to any specific formality here.

### 2. Got Code? Awesome!

If you're a coder and have a quick fix or a new feature, please open a pull request. I'll review it and merge it in if it fits the project's goals and style. If you have a larger feature in mind, please open an issue first so we can discuss it.

- - - - -

Thanks for checking out `bare.sh`! 🚀
