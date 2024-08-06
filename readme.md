# `bare`

🆕 Subscribe to the [YouTube Channel @bareDeveloper](https://youtube.com/@bareDeveloper) to see video tutorials and more content adjacent to `bare`.

- - -

`bare` is a collection of bash scripts designed to simplify personal and small business workflows. These scripts are crafted to be easy to write and read for anyone who wants to learn *a little programming*. The syntax is intentially kept simple. More advanced users can create customer `bare` scripts using existing `bare` commands as well as any `bash` programming syntax, making the system highly extensible.

Core `bare` commands are inspired by the Unix philosophy, accepting input from `stdin`, output to `stdout` wherever possible and treat text as the universal interface.

## Environment

### RC file
Set your `.etc/barerc` file, and bare will source it for use through the system.

```env
export STRIPE_PUBLIC_KEY="xxxxx"
export STRIPE_SECRET_KEY="xxxxx"

export OPENAI_API_KEY="xxxxx-xxxx-xxxxx"

export BARE_EMAIL_FROM="xxxxx"
export POSTMARK_API_TOKEN="xxxxx-xxxx-xxxxx"
```

### Third-party CLI tools

Various CLI tools are required in the bare ecosystem, mostly classics like `curl` and `jq`, but sometimes more obscure ones like `yt-dlp`. `bare` will alert you that you don't have these installed, but if you'd like to get a headstart, here are the bulk of the tools that you'll probably need.

You can still use much of `bare` without most of these, but we recommend installing them to get the full experience. You can install them with a package manager such as `apt-get` on Ubuntu or `brew` on Mac.

```md
- curl (7.82+)
- jq
- recutils
- sqlite3
- cmark
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

Download the zip or clone this repo, hop inside to get started.

You can either use the bare terminal (recommended) or call scripts inline with `./bare`.

**`bare` terminal**
```console
cd bare.sh
./bare -I
entering bare terminal. type exit when ready to leave.
🐻 bare > random string 30
a3THAyzHiVPwbP8gyY0R1xRIKMsJ5d
```

**inline `./bare`**
```console
cd bare.sh
./bare random string 30
xj95iUQK2KGHVap8YSUOX0l9xWbqQl
```

## Quick samples

Inside the bare terminal (`./bare -I`):

```bash
openai chat "Hello there, how are you?"
# Hello! How can I assist you today?

codec url.encode "Hello! How can I assist you today?"
# Hello%21%20How%20can%20I%20assist%20you%20today%3F%0A

codec form-data.decode 'user=%7B%22first_name%22%3A%22Matthew%22%2C%22last_name%22%3A%22Larkin%22%7D'
# {"first_name":"Matthew","last_name":"Larkin"}

email --to "matthew@groveos.com" --subject "Bare suggestion" --body "Hi there, I have an idea for bare!"
# >> wwnzz9lw-adf6-447d-b30b-slax67kzuhlo (Postmark Email ID)
```

## Bare scripts

With `bare`, we can create our own custom *bare scripts*. These scripts are just bash scripts but may contain lines of `bare` script expressions, which are executed in sequence, just like any other bash script.

Each expression is a command that can be independently executed in the shell, but together they can be used to automate a more complex workflow.

To create a `bare` script, navigate to your `.var/scripts` directory, create a file (no file extension necessary), and then write your `bare` commands and/or bash commands!

Here's a sample script called `sample` in the `.var/scripts` directory. We added a shebang at the front for better syntax highlighting in VS Code, but shebangs here are not necessary.

**`.var/scripts/sample`**
```bash
#!/usr/bin/env bash

echo "We are using: $(ls | codec lines.index 0)"
random string 30
openai chat "Hi there, I'm using a new toolkit called bare, have you heard of it?"
```

You can now run that script from the `bare` terminal or from an inline `./bare` call.

**`bare` terminal**

```console
🐻 bare > run sample
We are using: bare
04Gg4gyS02X4skSWzQcmMFuBmZD6dG
Hello! I haven't heard of a toolkit by the name "bare." Could you provide more information about it so I can assist you better?
```

This is a very powerful feature. We'll have more on this soon.