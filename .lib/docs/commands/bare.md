# ./bare

`./bare` is the entrypoint of the `bare` command system. All commands flow through the root `bare` script and are subsequently delegated to their respective subscripts.

By using `./bare` as a central entrypoint, we permit the setting of environment variables for use throughout the bare system.

## Usage

```bash
# ./bare <script> <argument_one> <argument_two> <etc>

./bare random string 30
# delegates arguments 'string' and '30' to the
# ./random script

./bare render templates/email.md --to-html
# delegates arguments 'templates/email.md' and
# '--to-html' to the ./render script

./bare weather
# delegates no arguments to the ./weather script
```

## Core bare scripts

Below are some of the core bare scripts callable by `./bare`.

- [capitalize](/commands/?script=capitalize)
- [codec](/commands/?script=codec)
- [download](/commands/?script=download)
- [email](/commands/?script=email)
- [geo](/commands/?script=geo)
- [image](/commands/?script=image)
- [interpret](/commands/?script=interpret)
- [loop](/commands/?script=loop)
- [lowercase](/commands/?script=lowercase)
- [media](/commands/?script=media)
- [note](/commands/?script=note)
- [openai](/commands/?script=openai)
- [random](/commands/?script=random)
- [render](/commands/?script=render)
- [request](/commands/?script=request)
- [silence](/commands/?script=silence)
- [stripe](/commands/?script=stripe)
- [transform](/commands/?script=transform)
- [uppercase](/commands/?script=uppercase)
- [weather](/commands/?script=weather)
- [youtube](/commands/?script=youtube)
