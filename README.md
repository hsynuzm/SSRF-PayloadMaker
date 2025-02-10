# SSRF URL Bypass Tool

This script **SSRF URL Bypass Tool** creates various SSRF (Server-Side Request Forgery) bypass payloads by combining a whitelisted hostname with attacker hostnames. These payloads help demonstrate potential SSRF vulnerabilities by obfuscating or manipulating URLs to bypass basic protections such as filters on hostnames.

## Features

- **Generates a list of SSRF bypass payloads** by inserting malicious/attacker hostnames into URLs in different ways.
- **Multiple encoding options** to obfuscate the payloads:
  - `intruder`
  - `everything`
  - `special_chars`
  - `unicode_escape`
- **Option to force HTTP** instead of HTTPS in the generated payloads.
- **Ability to provide a single attacker domain/IP** or read multiple attacker domains/IPs from a file (word list).
- **Predefined list of attacker domains/IPs** (including localhost variants) to demonstrate typical SSRF scenarios.
- **Output to console** or **write directly to a file**.

## Requirements

- Python 3.x
- Standard Python libraries (no additional installations required).

## Installation

1. Clone or download this repository.
2. Ensure you have Python 3 installed on your system.
3. (Optional) Create and activate a virtual environment if you wish to isolate dependencies.

## Usage

```shell
python3 ssrf_maker.py --allowed <ALLOWED_HOSTNAME> [options]
```

### Required Arguments

| Option           | Description                                                                             |
|------------------|-----------------------------------------------------------------------------------------|
| `-al, --allowed` | Whitelisted hostname (e.g., `example.com`).                                             |

You must provide the `allowed` hostname in order to generate the payloads.

### Optional Arguments

| Option                            | Description                                                                                                                     |
|-----------------------------------|---------------------------------------------------------------------------------------------------------------------------------|
| `-v,  --attacker`                 | Single attacker hostname/IP (e.g., `evil.com`).                                                                                 |
| `-w,  --word-list`                | Path to a file containing attacker hosts line by line (if this is provided, `-v` will be ignored).                              |
| `-e,  --encoding`                 | Encoding type to apply to the generated URLs. Options: `intruder`, `everything`, `special_chars`, `unicode_escape`.             |
| `-fh, --force-http`               | Replaces `https://` with `http://` in all generated URLs.                                                                       |
| `-o,  --output`                   | Write output to a specified file (e.g., `payloads.txt`).                                                                        |
| `-A,  --all`                      | Generate all payloads using all encoding methods (`none`, `intruder`, `everything`, `special_chars`, `unicode_escape`).         |

**Note**: If you use the `-A, --all` option, the `-e, --encoding` option will be ignored and the script will generate payloads for all encoding methods.

## Examples

Below are some example commands to illustrate usage:

1. **Basic usage with a single attacker domain**:
    ```bash
    python3 ssrf_maker.py --allowed example.com --attacker attacker.com
    ```

2. **Provide multiple attacker domains from a word list**:
    ```bash
    python3 ssrf_maker.py --allowed example.com --word-list attacker_list.txt
    ```

3. **Write payloads to a file**:
    ```bash
    python3 ssrf_maker.py --allowed example.com --attacker attacker.com --output payload.txt
    ```

4. **Generate payloads using all encodings**:
    ```bash
    python3 ssrf_maker.py --allowed example.com --attacker attacker.com --all
    ```

5. **Force HTTP instead of HTTPS**:
    ```bash
    python3 ssrf_maker.py --allowed example.com --attacker attacker.com --force-http
    ```

## How It Works

1. **Attacker Host Selection**  
   - You can provide a single attacker host via `-v/--attacker`.
   - Or provide a file with multiple attacker hosts via `-w/--word-list`.
   - If neither is provided, the script will use a **default** list of various known SSRF test domains (e.g., `127.0.0.1`, `localhost`, `169.254.169.254`, etc.).

2. **URL Generation**  
   - The script uses a list of pre-defined URL structures designed to bypass SSRF filters.
   - Each structure is combined with the `allowed` hostname and your attacker host.

3. **Encoding**  
   - Depending on the chosen encoding mode:
     - **No encoding** (default if none specified).
     - **`intruder`**: Percent-encodes only a specific set of characters.
     - **`everything`**: Percent-encodes everything except alphanumeric characters.
     - **`special_chars`**: Percent-encodes only certain special characters in the ASCII range.
     - **`unicode_escape`**: Converts non-ASCII or special characters to `\uXXXX` format.

4. **Output**  
   - All resulting URLs are printed to the console.
   - If `-o/--output` is used, they are also written line-by-line to the specified file.

## Contributing

Contributions, bug reports, and feature requests are welcome. Feel free to open an [issue](https://github.com/your-repo) or submit a pull request.

## License

This project is provided for **educational and testing** purposes only. Use responsibly and ensure you have **explicit permission** before performing any tests on services or infrastructure.  

---

**Disclaimer**: The author(s) of this project assume **no liability** and are **not responsible** for any misuse or damage caused by this tool.  
Use responsibly and ethically, and consult your organization's policy and applicable laws.