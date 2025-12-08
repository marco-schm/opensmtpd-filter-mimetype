# OpenSMTPD MIME Whitelist Filter

## Project Description

This project is a **MIME Whitelist Filter** designed for the **OpenSMTPD** Mail Transfer Agent. It strictly enforces a content policy by blocking any attachment whose MIME type is not explicitly listed in the **YAML** configuration.

---

## Core Features

* **Strict Whitelist Control:** Blocks all attachments whose MIME type is not explicitly allowed.
* **YAML Configuration:** Enables simple, commented management of the whitelist (`allowed_mime_types`) and logging settings.
* **Stability:** Implements **Panic Recovery** and **Thread Safety (Mutex)** to prevent filter crashes and data corruption during concurrent transactions.
* **Security:** Performs **Sanitization** of all user input before integrating it into SMTP protocol responses to prevent protocol injection.
* **Configurable Logging:** Supports adjustable logging levels (`debug`, `info`, `warn`) for granular monitoring via Syslog.

## Installation and Build

### Prerequisites

* Go 1.21 or higher
* OpenSMTPD
* The YAML dependency (`gopkg.in/yaml.v3`)

### Building from Source

Clone the repository and use the provided `Makefile`:

```bash
git clone [https://github.com/YOUR-USERNAME/opensmtpd-mime-filter.git](https://github.com/YOUR-USERNAME/opensmtpd-mime-filter.git)
cd opensmtpd-mime-filter
make build
```
## Deployment
### 1. Copy Binary 
```bash
cp bin/mimefilter /usr/local/bin/
```
### 2. Copy Configuration
```bash
cp configs/opensmtp-filter-mimetype.example.yaml /etc/opensmtp-filter-mimetype.yaml
```
### 3. Configure OpenSMTPD
```bash
filter "mimecheck" proc-exec "/usr/local/bin/mimefilter"

listen on all filter "mimecheck"
```
### 4. Restart OpenSMTPD

---

## Configuration

Configuration is managed via the file `/etc/mx-filter-config.yaml`.

| YAML Key                | Description                                                                 | Default Value      |
|-------------------------|-----------------------------------------------------------------------------|------------------|
| `log_tag`               | The tag used in Syslog.                                                     | `"mx-de-filter"`  |
| `log_level`             | Sets the logging detail level: debug, info, or warn.                        | `"info"`          |
| `scanner_buffer_max_mb` | The maximum line size (in MB) for the protocol scanner to prevent DoS attacks with extremely long Base64 lines. | `10`              |
| `allowed_mime_types`    | The YAML list of explicitly allowed MIME types.                             | `[...]`           |

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


