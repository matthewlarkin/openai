# `bare`

`bare` is a collection of bash scripts designed to simplify personal and small business workflows. These scripts are crafted to be easy to write and read for anyone who wants to learn *a little programming*. The syntax is intentially kept simple. More advanced users can create customer `bare` scripts using existing `bare` commands as well as any `bash` programming syntax, making the system highly extensible.

Core `bare` commands are inspired by the Unix philosophy, accepting input from `stdin`, output to `stdout` wherever possible and treat text as the universal interface.

## Sample usage

```bash
## OpenAI ##

# Basic usage: AI chat
./bare openai chat "Hello there, how are you?"
# Hello! How can I assist you today?

# Advanced usage: AI assistant prompt rendering
./bare render my-capital-assistant-prompt.md "TN" | ./bare openai chat | ./bare openai voice
# .var/downloads/QLJ58WmzrFArulMJ6fme9faqolCx96Mu.mp3 (audio file answering the question)

# Basic usage: transcribing
./bare openai transcribe .var/downloads/QLJ58WmzrFArulMJ6fme9faqolCx96Mu.mp3
# The capital of TN is Nashville.


# - - - - -


## Codec ##

./bare codec url.encode "Hello! How can I assist you today?"
# Hello%21%20How%20can%20I%20assist%20you%20today%3F%0A

./bare codec form-data.encode '{"user" : {"first_name" : "Matthew", "last_name" : "Larkin"}}'
# user=%7B%22first_name%22%3A%22Matthew%22%2C%22last_name%22%3A%22Larkin%22%7D

./bare codec form-data.decode 'user=%7B%22first_name%22%3A%22Matthew%22%2C%22last_name%22%3A%22Larkin%22%7D'
# {"first_name":"Matthew","last_name":"Larkin"}


# - - - - -


## Email ##

# Basic usage: inline sending
./bare email --to "matthew@groveos.com" --subject "Bare suggestion" --body "Hi there, I have an idea for bare!"
# >> wwnzz9lw-adf6-447d-b30b-slax67kzuhlo (Postmark Email ID)

# Advanced usage: template rendering
body=$(./bare render email/templates/welcome.md "John" "Nursing" "July 1, 2024" --to-html);
email --to "jon@example.com" --subject "Welcome to the Progam!" --body "$body"
# >> nt6i9i5j-ff41-430c-8bfd-zeb8y3dsrokk (Postmark Email ID)
```

## Run Commands
Set your `.etc/barerc` file, and bare will source it for use through the system.

```env
export name="Matthew"
export STRIPE_PUBLIC_KEY="xxxxx"
export STRIPE_SECRET_KEY="xxxxx"
export OPENAI_API_KEY="xxxxx-xxxx-xxxxx"
export POSTMARK_API_TOKEN="xxxxx-xxxx-xxxxx"
export BARE_EMAIL_FROM="matthew@groveos.com"
```

## Bare scripts

The Bare system facilitates the use of *bare scripts*. These scripts are just bash scripts but primarily contain lines of Bare script expressions, which are executed in sequence. Each expression is a command that can be independently executed in the shell, but together they can be used to automate a more complex workflow, such as:

1. intaking CSV data, producing a series of personalized emails
2. logging the status to a file
3. submitting that file to a manager upon completion