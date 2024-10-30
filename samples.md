# Sample Usage #

A collection of some of the more useful commands to get you started with `bare.sh`.

## 🌈 Color ##

```bash
bare.sh color red
# #FF0000

bare.sh color red -s 10
# #8C7373

bare.sh color -h 120 -s 100 -l 50
# #00FF00

bare.sh color orange --hsl
# hsl(30, 100%, 50%)

bare.sh color orange --rgb
# rgb(255, 165, 0)

bare.sh color orange -s 20 -l 80 --rgb
# rgb(214, 204, 194)
```

## 📜 Age ##

```bash
bare.sh age "1990-01-01" --years
# 34.85

bare.sh age ~/Desktop/my_old_file.txt --days
# 4119

bare.sh age ~/Desktop/my_old_file.txt --minutes --modified
# 13.28
```

## 🔗 QR Codes ##

```bash
bare.sh qr "Hello"
# 3NrheqGwY2k0ocWqx3BVd8VX1KlURr.png

bare.sh qr "https://google.com"
# MeRdbWfuRfjqpWk2uJpi0XqLVK5W9d.png
```

## 🧮 Maths ##

```bash
bare.sh round 7.5
# 8

bare.sh round up 7.1
# 8

bare.sh round down "7.9"
# 7

bare.sh math "7 * 8" # quotes required
# 56

bare.sh math "(1 + 2) / 3" # quotes required
# 1
```

## 👍/👎 Validations ##

```bash
bare.sh validate email "sample@gmail.com"
# true

bare.sh validate email "sample@.com"
# false

bare.sh validate url "This is not a url"
# false

bare.sh validate json '{"name": "John", "age": 30}'
# true

bare.sh validate json my_valid_file.json
# true

bare.sh validate csv my_invalid_file.csv
# false

bare.sh validate uppercase "HELLO"
# true

bare.sh validate capitalized "Hello"
# true

bare.sh validate date "2019-10-10"
# true

bare.sh validate date "2019-10-32"
# false
```

## 🤖 AI Assistance ##

```bash
bare.sh openai "Hello, my name is John."
# Hello, John! How can I assist you today?

bare.sh validate ai "Spam email" 'You won a prize! Deposit $1000 to this bank account to claim your share of $1,000,000!'
# true

bare.sh validate ai "Response to my recent job interview" 'Hi John, I am writing to inform you that you have been selected for the job. Please come to the office tomorrow to sign the contract.'
# true

bare.sh validate ai "Response to my recent job interview" 'Want to list your job offer on our website? Visit our website to learn more.' --explain
# Validation: 'false'. Explanation: The source material provides information about listing a job offer on a website, but does not contain a response to a job interview. Therefore, it does not satisfy the condition.
```

## 🏞️ Images ##

```bash
bare.sh image resize ~/Desktop/sample.jpg --height 100
# /Users/<username>/Desktop/sample_100px.jpg

bare.sh image resize ~/Desktop/sample.jpg --height 100 --width 200
# /Users/<username>/Desktop/sample_200x100px.jpg

bare.sh image resize ~/Desktop/sample.jpg --height 100 -o ~/Desktop/resized.jpg
# /Users/<username>/Desktop/resized.jpg

bare.sh image describe ~/Desktop/sample.jpg
# The image is a close-up of a cat with long white fur and green eyes.
```

## 🔐 Encryption ##

```bash
bare.sh encrypt 'Nashville, TN' with password 'testing'
# U2FsdGVkX19aKk/E71YqHLvm7MrQpf93HvzfvkZSmC8=

bare.sh decrypt 'U2FsdGVkX19aKk/E71YqHLvm7MrQpf93HvzfvkZSmC8=' with password 'testing'
# Nashville, TN

bare.sh encrypt 'Hello, World!' --pass "password"
# U2FsdGVkX18G+cjpJeId27FiONIuL4QyGmUqR2R2ORw=

bare.sh decrypt 'U2FsdGVkX18G+cjpJeId27FiONIuL4QyGmUqR2R2ORw=' --pass "password"
# Hello, World!

bare.sh encrypt myfile.txt --pass "password" --output myfile.enc
cat myfile.enc
# U2FsdGVkX19+LC9EUOPG1ll0iBAdb78bVKwdMVfJmQ0=

bare.sh decrypt myfile.enc --pass "password" --output myfile.txt
cat myfile.txt
# Hello, World!
```

## ✅ Validations ##

```bash
bare.sh validate email "info@bare.sh"
# true

bare.sh validate file ~/Desktop/does-not-exist.jpg
# false

bare.sh validate url "https://www.google.com"
# true

bare.sh validate phone "(828) 252-0000" # US based for now
# true
```

## 📝 Text Processing ##

```bash
cat note.md
# # My Note
# This is a sample note with some text.
# ## Subheading
# More text here with **bold** and *italic* formatting.

bare.sh render note.md --to-html
# <h1 id="my-note">My Note</h1>
# <p>This is a sample note with some text.</p>
# <h2 id="subheading">Subheading</h2>
# <p>More text here with <strong>bold</strong> and <em>italic</em> formatting.</p>

bare.sh render othernote.html --to-md
# # My Other Note

# This is another sample note with some text.

# ## Subheading

# More text here with **bold** and *italic* tags.
```

## 🌎 Geography ##

```bash
bare.sh geo paris-france
# 48.86,2.32

bare.sh geo "Asheville, NC"
# 35.60,-82.55

bare.sh geo google.com
# 13.98,44.17
```

## 📂 File management ##

```bash
bare.sh filetype ~/Desktop/sample.webp
# image/webp

bare.sh filetype "Hi there!"
# text/plain

bare.sh filetype ~/Desktop/does-not-exist.jpg
# text/plain
```

## ⚙️ Text Utilities ##

## Random ##

```bash
bare.sh random
# XWvRbWCRtsFSGH8d

bare.sh random number
# 3687669898045004

bare.sh random string 10
# K3oPtyOa0c

bare.sh random number 10
# 6048376577

bare.sh random alpha 10
# KQyVDxoCmh
```

## Hashing ##

```bash
bare.sh codec hash "secretpassword"
# $argon2id$v=19$m=65540,t=3,p=4$MWNyOVRtS3Q2eVc4Znp...

bare.sh codec hash.verify '$argon2id$v=19$m=65540,t=3,p=4$MWNyOVRtS3Q2eVc4Znp...' "secretpassword"
# true
```

## Encoding ##

```bash
bare.sh codec base64.encode 'Hello world!'
# SGVsbG8gd29ybGQhCg==

bare.sh codec base64.decode 'SGVsbG8gd29ybGQhCg=='
# Hello world!

bare.sh codec url.encode 'Hello world!'
# Hello%20world!

bare.sh codec html.encode '<h1>Hello world!</h1>'
# &lt;h1&gt;Hello world!&lt;/h1&gt;

bare.sh codec form-data.encode '{"name": "John", "age": 30}'
# name=John&age=30

bare.sh codec form-data.decode 'name=John&age=30'
# {"name": "John", "age": 30}
```

## ⌚️ Date and Time ##

```bash
bare.sh date
# Thu Oct 10 22:17:18 UTC 2024

bare.sh date --timezone 'America/New_York'
# Thu Oct 10 18:17:18 EDT 2024

bare.sh date --timezone 'Mountain'
# Thu Oct 10 16:17:18 MDT 2024

bare.sh date --timezone 'Mountain' --format h:m
# 4:17 PM

bare.sh date --timezone 'Mountain' --format H:M
# 16:17

bare.sh date --timezone 'Mountain' --format 'Y-m-d H:M:S'
# 2024-10-10 16:17:18
```

## 🌤️ Weather and Basic Astronomy ##

```bash
bare.sh weather asheville-nc
#       \   /     Sunny
#        .-.      66 °F          
#     ― (   ) ―   ↘ 2 mph        
#        `-’      9 mi           
#       /   \     0.0 in

bare.sh weather asheville-nc sunset
# 06:59 PM

bare.sh weather asheville-nc moonrise
# 03:45 PM

bare.sh weather asheville-nc concise
# Sunny

bare.sh weather asheville-nc forecast
#                                                        ┌─────────────┐                                                       
# ┌──────────────────────────────┬───────────────────────┤  Fri 11 Oct ├───────────────────────┬──────────────────────────────┐
# │            Morning           │             Noon      └──────┬──────┘     Evening           │             Night            │
# ├──────────────────────────────┼──────────────────────────────┼──────────────────────────────┼──────────────────────────────┤
# │     \   /     Sunny          │     \   /     Sunny          │     \   /     Sunny          │     \   /     Clear          │
# │      .-.      48 °F          │      .-.      62 °F          │      .-.      64 °F          │      .-.      51 °F          │
# │   ― (   ) ―   ↑ 0-1 mph      │   ― (   ) ―   ↑ 0 mph        │   ― (   ) ―   ↘ 3-6 mph      │   ― (   ) ―   ↘ 1-3 mph      │
# │      `-’      6 mi           │      `-’      6 mi           │      `-’      6 mi           │      `-’      6 mi           │
# │     /   \     0.0 in | 0%    │     /   \     0.0 in | 0%    │     /   \     0.0 in | 0%    │     /   \     0.0 in | 0%    │
# └──────────────────────────────┴──────────────────────────────┴──────────────────────────────┴──────────────────────────────┘
#                                                        ┌─────────────┐                                                       
# ┌──────────────────────────────┬───────────────────────┤  Sat 12 Oct ├───────────────────────┬──────────────────────────────┐
# │            Morning           │             Noon      └──────┬──────┘     Evening           │             Night            │
# ├──────────────────────────────┼──────────────────────────────┼──────────────────────────────┼──────────────────────────────┤
# │     \   /     Sunny          │     \   /     Sunny          │     \   /     Sunny          │     \   /     Clear          │
# │      .-.      +51(50) °F     │      .-.      64 °F          │      .-.      62 °F          │      .-.      +53(51) °F     │
# │   ― (   ) ―   ↘ 2-4 mph      │   ― (   ) ―   ↘ 3-4 mph      │   ― (   ) ―   ↘ 3-6 mph      │   ― (   ) ―   ↘ 1-4 mph      │
# │      `-’      6 mi           │      `-’      6 mi           │      `-’      6 mi           │      `-’      6 mi           │
# │     /   \     0.0 in | 0%    │     /   \     0.0 in | 0%    │     /   \     0.0 in | 0%    │     /   \     0.0 in | 0%    │
# └──────────────────────────────┴──────────────────────────────┴──────────────────────────────┴──────────────────────────────┘
#                                                        ┌─────────────┐                                                       
# ┌──────────────────────────────┬───────────────────────┤  Sun 13 Oct ├───────────────────────┬──────────────────────────────┐
# │            Morning           │             Noon      └──────┬──────┘     Evening           │             Night            │
# ├──────────────────────────────┼──────────────────────────────┼──────────────────────────────┼──────────────────────────────┤
# │     \   /     Sunny          │     \   /     Sunny          │     \   /     Sunny          │     \   /     Clear          │
# │      .-.      57 °F          │      .-.      +71(73) °F     │      .-.      +75(78) °F     │      .-.      68 °F          │
# │   ― (   ) ―   → 1-3 mph      │   ― (   ) ―   → 1 mph        │   ― (   ) ―   ↑ 3-8 mph      │   ― (   ) ―   ↗ 3-6 mph      │
# │      `-’      6 mi           │      `-’      6 mi           │      `-’      6 mi           │      `-’      6 mi           │
# │     /   \     0.0 in | 0%    │     /   \     0.0 in | 0%    │     /   \     0.0 in | 0%    │     /   \     0.0 in | 0%    │
# └──────────────────────────────┴──────────────────────────────┴──────────────────────────────┴──────────────────────────────┘
```