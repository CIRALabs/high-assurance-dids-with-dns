import argparse

import dns
import dns.resolver

resolver = dns.resolver.Resolver()
resolver.use_dnssec = True
resolver.nameservers = ["8.8.8.8"]
resolver.timeout = 10


def validate_dnskey_with_ds(domain):
    """
    Validates the DNSKEY records of a domain against the DS records of its parent domain.

    Args:
        domain (str): The domain to validate.

    Returns:
        bool: True if the DNSKEY records are valid, False otherwise.
    """
    try:
        # Get the DNSKEY record for the domain
        dnskey_answer = resolver.resolve(domain, dns.rdatatype.DNSKEY)
        # Get the DS record from the parent domain
        ds_answer = resolver.resolve(domain, dns.rdatatype.DS)
        dnskey_rrset = dnskey_answer.rrset
        ds_rrset = ds_answer.rrset
        print("DNSKEY records:")
        print(dnskey_rrset)
        print("\nDS records:")
        print(ds_rrset)
        # Validate each DNSKEY against each DS
        for dnskey in dnskey_rrset:
            for ds in ds_rrset:
                if dns.dnssec.make_ds(domain, dnskey, ds.digest_type) == ds:
                    print(f"\nDNSKEY validation passed for {domain}")
                    return True
        return False
    except Exception as e:
        print(f"Error occurred: {e}")
        return False


def resolve_dns_record_with_dnssec(record_name, record_type):
    """
    Resolves a DNS record using DNSSEC validation up to the TLD.

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
        None
    """
    try:
        if record_name.split(".")[0][0] == "_":
            zone = dns.name.from_text(record_name).parent()
        else:
            zone = dns.name.from_text(record_name)
        if not validate_dnskey_with_ds(zone):
            raise ValueError(f"DNSKEY validation failed for {zone}")
        # Get the DNSKEY for the domain
        dnskey_answer = resolver.resolve(zone, dns.rdatatype.DNSKEY)
        # Get the RRSet and corresponding RRSIG
        query = dns.message.make_query(record_name, record_type, want_dnssec=True)
        (response, _) = dns.query.udp_with_fallback(query, "8.8.8.8")
        rrset, rrsig = response.answer
        print(f"\nRRSET:")
        print(rrset)
        print(f"\nRRSIG:")
        print(rrsig)
        # Validate
        dns.dnssec.validate(
            rrset,
            rrsig,
            {zone: dnskey_answer},
        )
        print(f"\nDNSSEC validation passed for {record_name} {record_type}")
        return rrset
    except dns.resolver.NXDOMAIN:
        print(f"DNS domain '{record_name}' does not exist.")
    except dns.resolver.NoAnswer:
        print(f"No records found for '{record_name} {record_type}'.")
    except dns.resolver.NoNameservers:
        print("No nameservers found.")
    except Exception as e:
        print(f"Error occurred: {e}")


def resolve_dns_record(record_name, record_type):
    """
    Resolves a DNS record for the given record name and record type.

    Args:
        record_name (str): The name of the DNS record to resolve.
        record_type (str): The type of the DNS record to resolve.

    Returns:
        None

    Raises:
        dns.resolver.NXDOMAIN: If the DNS domain does not exist.
        dns.resolver.NoAnswer: If no records are found for the given record name and type.
        dns.resolver.NoNameservers: If no nameservers are found.
        Exception: If any other error occurs during the DNS resolution process.
    """
    try:
        answers = resolver.resolve(record_name, record_type)
        print(answers.rrset)
    except dns.resolver.NXDOMAIN:
        print(f"DNS domain '{record_name}' does not exist.")
    except dns.resolver.NoAnswer:
        print(f"No records found for '{record_name} {record_type}'.")
    except dns.resolver.NoNameservers:
        print("No nameservers found.")
    except Exception as e:
        print(f"Error occurred: {e}")


def main(record_name, record_type, use_dnssec):
    if use_dnssec == "yes":
        resolve_dns_record_with_dnssec(record_name, record_type)
    else:
        resolve_dns_record(record_name, record_type)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DNS Lookup")
    parser.add_argument("record_name", help="The name of the DNS record")
    parser.add_argument(
        "record_type", choices=["URI", "TLSA"], help="The type of DNS record"
    )
    parser.add_argument(
        "use_dnssec", choices=["yes", "no"], help="Whether to use DNSSEC"
    )
    args = parser.parse_args()

    main(args.record_name, args.record_type, args.use_dnssec)
