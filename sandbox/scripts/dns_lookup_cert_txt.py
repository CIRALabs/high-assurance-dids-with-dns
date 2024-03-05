import hashlib
import base58
import ecdsa
import requests
import json
import dns.resolver
import dns.message
import dns.rdatatype
import dns.rdata

from urllib.parse import urlparse, parse_qs


def query_cert_record(domain):
    resolver = dns.resolver.Resolver()
    resolver.use_dnssec = True
    resolver.nameservers = ["8.8.8.8"]
    resolver.use_edns = True

    try:
        query_domain = "_cert." + domain
        response = resolver.resolve(query_domain, "TXT")
        certificate_record = str(response[0]).strip('"')
        parsed_record = urlparse(certificate_record)
        parsed_dict = parse_qs(parsed_record.query)
        certificate_key = parsed_dict["kid"][0].strip().replace('"', "")
        certificate_path = parsed_record.path
        print(certificate_key, certificate_path)
        return (
            certificate_key,
            certificate_path,
        )

    except dns.resolver.NoAnswer:
        return None, None


if __name__ == "__main__":
    domain = "trustroot.ca"
    certificate_key, certificate_path = query_cert_record(domain)
    print(
        f"OK: certificate key: {certificate_key}  certificate path: {certificate_path}"
    )
