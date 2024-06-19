# Bare

Bare is a collection of bash scripts designed to simplify workflow management. These scripts are crafted to resemble natural English commands, making them more intuitive to use. Adhering to the Unix philosophy, they accept input from `stdin`, output to `stdout`, and treat plaintext as the universal interface.

## Bare scripts

The Bare system facilitates the use of *bare scripts*. These scripts are just bash scripts but primarily contain lines of Bare script expressions, which are executed in sequence. Each expression is a command that can be independently executed in the shell, but together they can be used to automate a more complex workflow, such as:

1. intaking CSV data, producing a series of personalized emails
2. logging the status to a file
3. submitting that file to a manager upon completion