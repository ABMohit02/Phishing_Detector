from urllib.parse import urlparse
import re
import socket


def _dns_record(hostname):
    """Returns 1 if hostname resolves in DNS, 0 otherwise."""
    try:
        if not hostname:
            return 0
        socket.setdefaulttimeout(5)
        socket.gethostbyname(hostname)
        return 1
    except (socket.gaierror, socket.timeout):
        return 0


def extract_features(url):
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""
    full = url

    def count(s, char): return s.count(char)

    # hostname without TLD (last part)
    host_parts = hostname.split(".")
    host_no_tld = ".".join(host_parts[:-1]) if len(host_parts) > 1 else hostname

    # Word splitting: letters only, from (host_no_tld + path) for raw words
    words_full = re.findall(r"[a-zA-Z]+", host_no_tld + path)
    # Host words: hostname without TLD
    words_host = re.findall(r"[a-zA-Z]+", host_no_tld)
    # Path words: from path only
    words_path = re.findall(r"[a-zA-Z]+", path)

    # nb_com: count .com only outside hostname
    path_query = path + query
    nb_com = path_query.lower().count(".com")

    # https_token: 1 if url uses http or https scheme
    https_token = 1 if parsed.scheme in ("http", "https") else 0

    # char_repeat: max frequency of any single alpha char in hostname
    char_repeat = max((hostname.count(c) for c in set(hostname) if c.isalpha()), default=0)

    features = {
        "length_url": len(url),
        "length_hostname": len(hostname),
        "ip": 1 if re.match(r"^\d+\.\d+\.\d+\.\d+$", hostname) else 0,
        "nb_dots": count(full, "."),
        "nb_hyphens": count(full, "-"),
        "nb_at": count(full, "@"),
        "nb_qm": count(full, "?"),
        "nb_and": count(full, "&"),
        "nb_or": count(full, "|"),
        "nb_eq": count(full, "="),
        "nb_underscore": count(full, "_"),
        "nb_tilde": count(full, "~"),
        "nb_percent": count(full, "%"),
        "nb_slash": count(full, "/"),
        "nb_star": count(full, "*"),
        "nb_colon": count(full, ":"),
        "nb_comma": count(full, ","),
        "nb_semicolumn": count(full, ";"),
        "nb_dollar": count(full, "$"),
        "nb_space": count(full, " "),
        "nb_www": count(full.lower(), "www"),
        "nb_com": nb_com,
        "nb_dslash": count(path, "//"),
        "http_in_path": 1 if "http" in path.lower() else 0,
        "https_token": https_token,
        "ratio_digits_url": sum(c.isdigit() for c in url) / len(url) if url else 0,
        "ratio_digits_host": sum(c.isdigit() for c in hostname) / len(hostname) if hostname else 0,
        "punycode": 1 if "xn--" in full.lower() else 0,
        "port": 1 if parsed.port else 0,
        "tld_in_path": 1 if any(t in path for t in [".com", ".net", ".org", ".info"]) else 0,
        "tld_in_subdomain": 1 if any(t in host_parts[0] for t in ["com", "net", "org"]) else 0,
        "abnormal_subdomain": 1 if re.match(r"^(w[0-9]+|ww[^w])", hostname) else 0,
        "nb_subdomains": len(host_parts) - 1 if hostname else 0,
        "prefix_suffix": 1 if "-" in hostname else 0,
        "random_domain": 1 if re.search(r"[0-9]{4,}", hostname) else 0,
        "shortening_service": 1 if any(s in hostname for s in ["bit.ly", "tinyurl", "goo.gl", "t.co", "ow.ly"]) else 0,
        "path_extension": 1 if re.search(r"\.(exe|zip|scr|pif)$", path, re.IGNORECASE) else 0,
        "nb_redirection": count(path, "//"),
        "nb_external_redirection": 1 if re.search(r"https?://", path) else 0,
        "length_words_raw": len(words_full),
        "char_repeat": char_repeat,
        "shortest_words_raw": min((len(w) for w in words_full), default=0),
        "shortest_word_host": min((len(w) for w in words_host), default=0),
        "shortest_word_path": min((len(w) for w in words_path), default=0),
        "longest_words_raw": max((len(w) for w in words_full), default=0),
        "longest_word_host": max((len(w) for w in words_host), default=0),
        "longest_word_path": max((len(w) for w in words_path), default=0),
        "avg_words_raw": sum(len(w) for w in words_full) / len(words_full) if words_full else 0,
        "avg_word_host": sum(len(w) for w in words_host) / len(words_host) if words_host else 0,
        "avg_word_path": sum(len(w) for w in words_path) / len(words_path) if words_path else 0,
        "phish_hints": 1 if any(w in full.lower() for w in ["login", "verify", "bank", "update", "secure", "account", "password", "confirm"]) else 0,
        "suspecious_tld": 1 if any(hostname.endswith(t) for t in [".tk", ".ml", ".ga", ".cf", ".gq"]) else 0,
        "dns_record": _dns_record(hostname),
    }

    return features