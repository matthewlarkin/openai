# `download`

The `download` scope lets us download things from the internet, such as html web pages, PDFs, ZIPs, and even YouTube videos (or mp3).

```bash
./bare download "https://example.com"
# .var/downloads/F6prRVgt4ZfpikcGUvXxxMUm5s9p27Yl.html

./bare download "https://pdfobject.com/pdf/sample.pdf"
# .var/downloads/CtczjeMmbii1ArrviOSrn7lxaLIbNf2j.pdf

./bare download "https://www.youtube.com/watch?v=-CbTO2NmOEs"
# .var/downloads/ksNl8MjH8y27rNmD7yIKggVA5mrndDNn.mp4

./bare download "https://www.youtube.com/watch?v=-CbTO2NmOEs" --mp3
# .var/downloads/ew42UwX0s4PE4Eu7AO4rntNcY8Wb9wSi.mp3
```