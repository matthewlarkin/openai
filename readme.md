# `bare`

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

Install these with your package manager (`apt get install` on Ubuntu, `brew install` on Mac).

```md
- curl (7.82+)
- jq
- sqlite3
- cmark
- yq
- xxd
- php
- awk
- perl
- nb
- openssl
- magick
- qrencode
```

## Bare terminal

Download the zip or clone this repo, hop inside to get started.

You can either use the bare terminal (recommended) or call scripts inline with `./bare`.

**bare terminal**
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

The Bare system facilitates the use of *bare scripts*. These scripts are just bash scripts but primarily contain lines of Bare script expressions, which are executed in sequence. Each expression is a command that can be independently executed in the shell, but together they can be used to automate a more complex workflow.

This is a very powerful feature. We'll have more on this soon.