# Some Bugs: NO NOT USE ... OpenSMTPD MIME Whitelist Filter

## Project Description

This project is a MIME Whitelist Filter for the OpenSMTPD Mail Transfer Agent. It enforces a strict content policy by blocking any email that contains an attachment with a MIME type not explicitly listed in the YAML configuration.

---

## Core Features

* **Strict Whitelist Control:** Blocks all attachments whose MIME type is not explicitly allowed.
* **YAML Configuration:** Enables simple, commented management of the whitelist (`allowed_mime_types`) and logging settings.
* **Configurable Logging:** Supports adjustable logging levels (`debug`, `info`, `warn`) for granular monitoring via Syslog.

## Installation and Build

### Building from Source

Clone the repository and use the provided `Makefile`:

```bash
git clone https://github.com/marco-schm/opensmtpd-mime-filter.git
cd opensmtpd-mime-filter
make build
```
## Deployment
### 1. Copy Binary 
```bash
cp bin/mimefilter /usr/local/libexec/smtpd/
```
### 2. Copy Configuration
```bash
cp configs/opensmtpd-filter-mimetype.example.yaml /etc/opensmtp-filter-mimetype.yaml
```
### 3. Configure OpenSMTPD
```bash
filter "mimecheck" proc-exec "/usr/local/libexec/smtpd/mimefilter"

listen on all filter "mimecheck"
```
### 4. Restart OpenSMTPD

---



# MIT License

Copyright (c) 2025 Marco Schmitt

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.


