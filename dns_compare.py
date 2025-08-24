#!/usr/bin/env python3
"""
Compare DNS records between the current provider and a new provider.

Examples:
  # Compare apex + common hosts before switching NS
  python dns_compare.py pageloom.com \
    --new-ns ns1.example.com ns2.example.com ns3.example.com

  # Specify additional hosts and record types
  python dns_compare.py example.com \
    --hosts @ www mail \
    --types A AAAA CNAME MX TXT \
    --new-ns ns1.example.com ns2.example.com ns3.example.com
"""

import argparse
import socket
from typing import Iterable, List, Dict, Tuple, Set

import dns.resolver
import dns.name
import dns.exception

DEFAULT_TYPES = ["A", "AAAA", "CNAME", "MX", "TXT", "NS"]
DEFAULT_HOSTS = ["@", "www", "_github-pages-challenge-pageloom", "google._domainkey", "googleffffffffa138f3b5", "mail",
                 "calendar", "docs", "_dmarc"]


def resolve_nameserver_ips(ns_hosts: Iterable[str]) -> List[str]:
    ips = []
    for host in ns_hosts:
        try:
            for family, _, _, _, sockaddr in socket.getaddrinfo(host, 53):
                ip = sockaddr[0]
                ips.append(ip)
        except socket.gaierror:
            pass
    # Deduplicate, keep order
    seen = set()
    out = []
    for ip in ips:
        if ip not in seen:
            seen.add(ip)
            out.append(ip)
    return out


def make_resolver(ns_ips: List[str] | None) -> dns.resolver.Resolver:
    r = dns.resolver.Resolver()
    if ns_ips:
        r.nameservers = ns_ips
    r.lifetime = 3.0
    r.timeout = 2.0
    return r


def fqdn(domain: str, host: str) -> str:
    if host in ("@", "", None):
        return dns.name.from_text(domain).to_text(True)
    return dns.name.from_text(f"{host}.{domain}").to_text(True)


def normalize_rdata(rdtype: str, r) -> str:
    """
    Produce a stable, comparable string for an rdata item.
    - Lowercase hostnames
    - Strip trailing dots
    - MX shown as 'priority host'
    - TXT joined as a single string
    """
    rdtype = rdtype.upper()

    def stripdot(s: str) -> str:
        return s[:-1] if s.endswith(".") else s

    if rdtype in {"A", "AAAA"}:
        return str(r.address)
    if rdtype == "CNAME":
        return stripdot(str(r.target).lower())
    if rdtype == "NS":
        return stripdot(str(r.target).lower())
    if rdtype == "MX":
        return f"{r.preference} {stripdot(str(r.exchange).lower())}"
    if rdtype == "TXT":
        # dnspython returns maybe multiple strings per TXT record
        try:
            txt = "".join([s.decode("utf-8") if isinstance(s, bytes) else s for s in r.strings])
        except AttributeError:
            # newer dnspython: r.strings removed, use .to_text()
            t = r.to_text()
            # strip quotes if present
            if t.startswith('"') and t.endswith('"'):
                t = t[1:-1]
            txt = t
        return txt
    if rdtype == "SOA":
        return r.to_text().lower()
    # Fallback
    return r.to_text().lower()


def query_rrset(resolver: dns.resolver.Resolver, name: str, rdtype: str) -> Set[str]:
    try:
        answers = resolver.resolve(name, rdtype, raise_on_no_answer=True)
        return {normalize_rdata(rdtype, r) for r in answers}
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
        return set()


def compare_sets(left: Set[str], right: Set[str]) -> Tuple[Set[str], Set[str]]:
    """return (only_in_left, only_in_right)"""
    return left - right, right - left


def main():
    p = argparse.ArgumentParser(description="Compare DNS records between current provider and a new nameserver set.")
    p.add_argument("domain", help="Base domain, e.g. example.com")
    p.add_argument("--new-ns", nargs="+", required=True, help="New provider nameservers (hostnames or IPs)")
    p.add_argument("--hosts", nargs="+", default=DEFAULT_HOSTS, help="Relative hosts to check, e.g. @ www api mail")
    p.add_argument("--types", nargs="+", default=DEFAULT_TYPES,
                   help=f"Record types to compare. Default: {', '.join(DEFAULT_TYPES)}")
    p.add_argument("--show-matches", action="store_true", help="Also print records that match on both sides")
    args = p.parse_args()

    domain = args.domain.strip(".")
    hosts = args.hosts or DEFAULT_HOSTS
    types = [t.upper() for t in args.types]

    # Prepare resolvers
    # live_resolver: current/recursive view (what the internet sees now)
    live_resolver = make_resolver(None)

    # new_resolver: query the new provider's nameservers directly
    new_ns_ips = []
    for ns in args.new_ns:
        if all(c.isdigit() or c == "." or c == ":" for c in ns):
            new_ns_ips.append(ns)
        else:
            new_ns_ips.extend(resolve_nameserver_ips([ns]))
    if not new_ns_ips:
        raise SystemExit("Could not resolve any IPs for --new-ns nameservers.")
    new_resolver = make_resolver(new_ns_ips)

    # Always include apex NS comparison
    if "NS" not in types:
        types.append("NS")

    diffs_found = False

    for host in hosts:
        name = fqdn(domain, host)
        print(f"\n=== {name} ===")
        for rdtype in types:
            left = query_rrset(live_resolver, name, rdtype)
            right = query_rrset(new_resolver, name, rdtype)

            # Sort for stable print
            sleft = sorted(left)

            if left == right:
                if args.show_matches:
                    if sleft:
                        print(f"  {rdtype}: ✅ match ({len(sleft)})")
                        for v in sleft:
                            print(f"    - {v}")
                    else:
                        print(f"  {rdtype}: ✅ both empty")
                continue

            diffs_found = True
            only_live, only_new = compare_sets(left, right)

            print(f"  {rdtype}: ❗ differs")
            if only_live:
                print("    Present in CURRENT provider only:")
                for v in sorted(only_live):
                    print(f"      - {v}")
            if only_new:
                print("    Present in NEW provider only:")
                for v in sorted(only_new):
                    print(f"      - {v}")

    if not diffs_found:
        print("\nAll compared records match. ✅")
    else:
        print("\nDifferences found. Review output above. 🔎")


if __name__ == "__main__":
    main()
