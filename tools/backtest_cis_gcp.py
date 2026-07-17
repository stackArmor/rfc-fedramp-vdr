#!/usr/bin/env python3
# tools/backtest_cis_gcp.py
"""Back-test the compliance-PAIN method against an SCC CIS GCP report.

Usage: python backtest_cis_gcp.py ../data/samples/cis-gcp-foundation-2.0-sample.csv
Assumes: multi-agency scope, one uniform asset-band assumption per run
(the SCC report is category-level; per-resource archetypes come later).
"""
import csv
import sys
from collections import Counter

from compliance_pain import (CIS_GCP_20_EXCEPTIONS, customer_effect, deadline,
                             finding_grade, pain_level, remediation_column)

# Surface-attachment joins. False entries carry category-level evidence:
# SQL_PUBLIC_IP is fully Compliant in this scan, so no Cloud SQL instance
# is public (decision log C-4 inference rule). True entries are the
# fail-safe default where no resource-level exposure feed exists.
ATTACHED_PUBLIC = {"SSL_NOT_ENFORCED": False, "SQL_NO_ROOT_PASSWORD": False,
                   "WEAK_SSL_POLICY": True, "PUBLIC_IP_ADDRESS": True,
                   "SQL_PUBLIC_IP": False,
                   "API_KEY_APPS_UNRESTRICTED": True,
                   "API_KEY_APIS_UNRESTRICTED": True}


def rows(path):
    with open(path, newline="") as f:
        reader = csv.reader(f)
        header = None
        for row in reader:
            if header is None:
                if row and row[0] == "Control":
                    header = row
                continue
            if len(row) == len(header):
                yield dict(zip(header, row))


def backtest(path, band, cert_class):
    dist = Counter()
    for r in rows(path):
        if r["Status"] != "Non-compliant":
            continue
        n = int(r["Findings"])
        grade = finding_grade(r["Severity"], governed=True)  # SCC is governed
        pain = pain_level(customer_effect(grade, band), True)
        finding = {"family": "cloud", "category": r["Finding category"]}
        if r["Finding category"] in ATTACHED_PUBLIC:
            finding["attached_resource_public"] = ATTACHED_PUBLIC[r["Finding category"]]
        col = remediation_column(finding, CIS_GCP_20_EXCEPTIONS)
        dist[(pain, col)] += n
    return dist


def main():
    path = sys.argv[1]
    for band in ("High", "Medium"):
        dist = backtest(path, band, "D")
        print(f"\n== Asset band assumption: {band} (Class D, multi-agency) ==")
        for (pain, col), n in sorted(dist.items(), reverse=True):
            d = deadline("D", pain, col)
            due = "no deadline" if d is None else f"{d} days"
            print(f"  N{pain}  {col:9s}  {n:5d} findings  -> {due}")


if __name__ == "__main__":
    main()
