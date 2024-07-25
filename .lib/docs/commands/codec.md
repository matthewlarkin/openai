# codec

The `codec` scope permits us to encode and decode strings in various formats, including: base64, hexidecimal, html, form-data, url, and newlines.


## Base64

Encode &amp; decode

```bash
./bare codec base64.encode "sample text"
# c2FtcGxlIHRleHQK

./bare codec base64.decode "c2FtcGxlIHRleHQK"
# sample text
```

## Hexidecimal

Encode &amp; decode

```bash
./bare codec hex.encode "hi there"
# 68692074686572650a

./bare codec hex.decode "68692074686572650a"
# hi there
```

## HTML

Encode &amp; decode

```bash
./bare codec html.encode "<h1>Hi there</h1>"
# &lt;h1&gt;Hi there&lt;/h1&gt;

./bare codec html.decode "&lt;h1&gt;Hi there&lt;/h1&gt;"
# <h1>Hi there</h1>
```

## Form Data

Form data expects conversion between JSON and form-data strings.

```bash
./bare codec form-data.encode '{"name":"John Doe","age":30}'
# name=John%20Doe&age=30

./bare codec form-data.decode "name=John%20Doe&age=30"
# {"name":"John Doe","age":"30"}
```

## URL

Encode &amp; decode

```bash
./bare codec url.encode "https://example.com"
# https%3A%2F%2Fexample.com

./bare codec url.decode "https%3A%2F%2Fexample.com"
# https://example.com
```

## Newlines

This works best when working with existing text files with newlines. We'll use `cat` to show our file contents first.

```bash
cat my-file.txt
# Hi there
#
# This file has newline breaks.
#
#
# With a bigger gap at the bottom
#

cat my-file.txt | ./bare codec newlines.encode
# Hi there\n \nThis file has newline breaks.\n\n\nWith a bigger gap at the bottom\n

./bare codec newlines.decode "Hi there\n \nThis file has newline breaks.\n\n\nWith a bigger gap at the bottom\n"
# Hi there
#
# This file has newline breaks.
#
#
# With a bigger gap at the bottom
#