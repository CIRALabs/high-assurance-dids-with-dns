import argparse
import logging

import dns
import dns.resolver

resolver = dns.resolver.Resolver()
resolver.use_dnssec = True
resolver.nameservers = ["8.8.8.8"]
resolver.timeout = 10

SUPPORTED_RECORD_TYPES = [
    "uri",
    "tlsa",
    "ds",
    "dnskey",
    "a",
    "aaaa",
    "cname",
    "mx",
    "ns",
]


def validate_dnskey_with_ds(zone: str) -> bool:
    """
    Validates the DNSKEY records of a domain against the DS records of its parent domain.

    Args:
        domain (str): The domain to validate.

    Returns:
        bool: True if the DNSKEY records are valid, False otherwise.
    """
    try:
        dnskey_answer = resolver.resolve(zone, dns.rdatatype.DNSKEY)
        ds_answer = resolver.resolve(zone, dns.rdatatype.DS)
        dnskey_rrset = dnskey_answer.rrset
        ds_rrset = ds_answer.rrset
        logging.info("DNSKEY records: %s", dnskey_rrset)
        logging.info("DS records: %s", ds_rrset)
        # Validate each DNSKEY against each DS
        for dnskey in dnskey_rrset:
            valid = False
            for ds in ds_rrset:
                if dns.dnssec.make_ds(zone, dnskey, ds.digest_type) == ds:
                    valid = True
            if valid is False:
                logging.error("DNSKEY validation failed for %s", dnskey)
                return False
            logging.info("DNSKEY validation passed for %s", dnskey)
        return True
    except Exception as e:
        logging.error("Error occurred: %s", e)
        return False


def resolve_dns_record_with_dnssec(
    record_name: str, record_type: str
) -> dns.rrset.RRset:
    """
    Resolves a DNS record using DNSSEC validation up to its parent domain.

    Args:
        record_name (str): The name of the DNS record to resolve.
        record_type (int): The type of the DNS record to resolve.

    Raises:
        ValueError: If DNSKEY validation fails for the zone.
        dns.resolver.NXDOMAIN: If the DNS domain does not exist.
        dns.resolver.NoAnswer: If no records are found for the given record name and type.
        dns.resolver.NoNameservers: If no nameservers are found.
        Exception: If any other error occurs.

    Returns:
        dns.rrset.RRset: The resolved DNS record as an RRset object.
    """
    try:
        if record_name.split(".")[0][0] == "_":
            zone = dns.name.from_text(record_name).parent()
        else:
            zone = dns.name.from_text(record_name)
        if not validate_dnskey_with_ds(zone):
            raise ValueError(f"DNSKEY validation failed for {zone}")
        dnskey_answer = resolver.resolve(zone, dns.rdatatype.DNSKEY)
        query = dns.message.make_query(record_name, record_type, want_dnssec=True)
        (response, _) = dns.query.udp_with_fallback(query, "1.1.1.1", timeout=10)
        rrset, rrsig = response.answer
        logging.info("RRSET: %s", rrset)
        logging.info("RRSIG: %s", rrsig)
        dns.dnssec.validate(
            rrset,
            rrsig,
            {zone: dnskey_answer},
        )
        logging.info("\nDNSSEC validation passed for %s %s", record_name, record_type)
        return rrset
    except dns.resolver.NXDOMAIN:
        logging.error("DNS domain '%s' does not exist.", record_name)
    except dns.resolver.NoAnswer:
        logging.error("No records found for '%s %s'.", record_name, record_type)
    except dns.resolver.NoNameservers:
        logging.error("No nameservers found.")
    except Exception as e:
        logging.error("Error occurred: %s", e)


def resolve_dns_record(record_name: str, record_type: str) -> dns.rrset.RRset:
    """
    Resolves a DNS record for the given record name and record type.

    Args:
        record_name (str): The name of the DNS record to resolve.
        record_type (str): The type of the DNS record to resolve.

    Returns:
        dns.rrset.RRset: The resolved DNS record.

    Raises:
        dns.resolver.NXDOMAIN: If the DNS domain does not exist.
        dns.resolver.NoAnswer: If no records are found for the given record name and type.
        dns.resolver.NoNameservers: If no nameservers are found.
        Exception: If any other error occurs during the DNS resolution process.
    """
    try:
        answers = resolver.resolve(record_name, record_type)
        return answers.rrset
    except dns.resolver.NXDOMAIN:
        logging.error("DNS domain '%s' does not exist.", record_name)
    except dns.resolver.NoAnswer:
        logging.error("No records found for '%s %s'.", record_name, record_type)
    except dns.resolver.NoNameservers:
        logging.error("No nameservers found.")
    except Exception as e:
        logging.error("Error occurred: %s", e)


def main(record_name, record_type, use_dnssec):
    if use_dnssec == True:
        return resolve_dns_record_with_dnssec(record_name, record_type)
    return resolve_dns_record(record_name, record_type)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DNS Lookup")
    parser.add_argument("record_name", help="The name of the DNS record")
    parser.add_argument(
        "record_type", choices=SUPPORTED_RECORD_TYPES, help="The type of DNS record"
    )
    parser.add_argument(
        "--dnssec",
        "-d",
        action="store_true",
        help="Whether to use dnssec validation",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Include additional information in the output",
    )
    args = parser.parse_args()
    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.ERROR)
    print(main(args.record_name, args.record_type, args.dnssec))
