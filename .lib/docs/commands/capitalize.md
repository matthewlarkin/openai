# capitalize

Capitalize only the first word of a single input string

```bash
./bare capitalize "hello world"
# Hello world
```

Capitalize the first word of each line from stdin
```bash
echo -e "hello world\nanother test" | ./bare capitalize
# Hello world
```

Capitalize all words in a single input string
```bash
./bare capitalize --all "hello world"
# Hello World
```

Capitalize all words of each line from stdin
```bash
echo -e "hello world\nanother test" | ./bare capitalize --all
# Hello World
```