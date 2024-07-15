# Bare

Bare is a collection of bash scripts designed to simplify workflow management. These scripts are crafted to resemble natural English commands, making them more intuitive to use. Adhering to the Unix philosophy, they accept input from `stdin`, output to `stdout`, and treat plaintext as the universal interface.

## Sample usage

```bash
## OpenAI ##

./bare openai chat "Hello there, how are you?"
# Hello! How can I assist you today?

./bare openai chat "What is the capital of TN?" | ./bare openai voice
# ./.downloads/QLJ58WmzrFArulMJ6fme9faqolCx96Mu.mp3 (audio file answering the question)

./bare openai transcribe ./.downloads/QLJ58WmzrFArulMJ6fme9faqolCx96Mu.mp3
# The capital of TN is Nashville.


# - - - - -


## Codec ##

./bare codec url.encode "Hello! How can I assist you today?"
# Hello%21%20How%20can%20I%20assist%20you%20today%3F%0A


# - - - - -


## Email ##

./bare email --to "matthew@groveos.com" --subject "Bare suggestion" --body "Hi there, I have an idea for bare!"
# >> 3b78c56e-adf6-447d-b30b-f8d78ce12e20 (Postmark Email ID)
```

## .env
Set your `.env` file at the root of your `bare.sh` directory, and bare will source the exported variables for use through the system.

```env
export name="Matthew"
export OPENAI_API_KEY="xxxxx-xxxx-xxxxx"
export POSTMARK_API_TOKEN="xxxxx-xxxx-xxxxx"
export BARE_EMAIL_FROM="matthew@groveos.com"
```

## Bare scripts

The Bare system facilitates the use of *bare scripts*. These scripts are just bash scripts but primarily contain lines of Bare script expressions, which are executed in sequence. Each expression is a command that can be independently executed in the shell, but together they can be used to automate a more complex workflow, such as:

1. intaking CSV data, producing a series of personalized emails
2. logging the status to a file
3. submitting that file to a manager upon completion