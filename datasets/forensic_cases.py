"""
BEC-FORGE Real-World Forensic Case Corpus Generator

Generates realistic forensic email evidence with complete RFC-822 headers,
DKIM signatures, multi-hop Received chains, SPF/DMARC authentication results,
and authentic corporate & attack scenarios for DFIR evaluation:

1. Case 2026-WIRE: "Operation WireShifter" (Vendor Email Compromise & Wire Diversion)
2. Case 2026-BASE: "Enterprise Baseline Corpus" (15+ corporate baseline communications)
3. Case 2026-PAYROLL: "Executive Payroll Diversion" (Display-name spoofing & direct deposit fraud)
4. Case 2026-MBOX: "Seized Mailbox Dump" (.mbox container of digital evidence)
"""

import mailbox
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
CASES_DIR = BASE_DIR / "cases"
CASES_DIR.mkdir(parents=True, exist_ok=True)


def build_operation_wireshifter_case() -> list[tuple[str, str]]:
    """Case 2026-WIRE: 5-stage Vendor Email Compromise & Wire Fraud."""
    emails = []

    # 1. Legitimate PO Negotiation
    eml_1 = """From: Victoria Vance <v.vance@apextech-corp.com>
To: Accounts Receivable <accounts@titan-industrial.com>
Subject: Purchase Order PO-98442: Q4 Infrastructure Hardware
Date: Mon, 05 Oct 2026 09:30:15 +0000
Message-ID: <msg.20261005.093015.001@apextech-corp.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"
Received-SPF: pass (apextech-corp.com: domain of v.vance@apextech-corp.com designates 198.51.100.22 as permitted sender) client-ip=198.51.100.22;
Authentication-Results: mx.titan-industrial.com;
    dkim=pass header.i=@apextech-corp.com header.s=apex2026;
    spf=pass (apextech-corp.com: domain designates 198.51.100.22) smtp.mailfrom=v.vance@apextech-corp.com;
    dmarc=pass (p=REJECT) header.from=apextech-corp.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=apextech-corp.com; s=apex2026; h=from:to:subject:date; bh=dGhpc2lzYXRlc3RoYXNo; b=VmljdG9yaWFWYW5jZURLSU1TaWduYXR1cmU=
Return-Path: <v.vance@apextech-corp.com>
Received: from mail-relay01.apextech-corp.com (mail-relay01.apextech-corp.com [198.51.100.22])
    by edge01.titan-industrial.com with ESMTPS id TITAN-98442-01
    for <accounts@titan-industrial.com>; Mon, 05 Oct 2026 09:30:16 +0000
Received: from internal-client-04.apextech-corp.com ([10.4.12.104])
    by mail-relay01.apextech-corp.com with ESMTPSA id APEX-OUT-01;
    Mon, 05 Oct 2026 09:30:15 +0000

Dear Titan Industrial Billing Team,

Please find attached our finalized purchase order PO-98442 for the Q4 rack-mount server hardware.
Our finance department will process the scheduled invoice once the delivery timeframe is confirmed.

Best regards,
Victoria Vance
Chief Financial Officer
Apex Global Technologies
"""
    emails.append(("01_legitimate_po_negotiation.eml", eml_1))

    # 2. Legitimate Vendor Invoice Confirmation
    eml_2 = """From: Accounts Receivable <accounts@titan-industrial.com>
To: Victoria Vance <v.vance@apextech-corp.com>
Subject: Re: Purchase Order PO-98442: Q4 Infrastructure Hardware
Date: Mon, 05 Oct 2026 14:15:22 +0000
Message-ID: <msg.20261005.141522.002@titan-industrial.com>
In-Reply-To: <msg.20261005.093015.001@apextech-corp.com>
References: <msg.20261005.093015.001@apextech-corp.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"
Received-SPF: pass (titan-industrial.com: domain of accounts@titan-industrial.com designates 203.0.113.88 as permitted sender) client-ip=203.0.113.88;
Authentication-Results: mx.apextech-corp.com;
    dkim=pass header.i=@titan-industrial.com header.s=titan2026;
    spf=pass smtp.mailfrom=accounts@titan-industrial.com;
    dmarc=pass header.from=titan-industrial.com
Return-Path: <accounts@titan-industrial.com>
Received: from mail.titan-industrial.com (mail.titan-industrial.com [203.0.113.88])
    by mx01.apextech-corp.com with ESMTPS id APEX-IN-882
    for <v.vance@apextech-corp.com>; Mon, 05 Oct 2026 14:15:23 +0000

Hi Victoria,

We have received PO-98442. The total invoice amount is $148,500.00.
Shipment is scheduled for departure this Thursday. As per our standard terms,
settlement will occur through our registered Citibank corporate account.

Thank you,
Accounts Receivable Department
Titan Industrial Supplies
"""
    emails.append(("02_legitimate_vendor_invoice_confirmation.eml", eml_2))

    # 3. Intercepted Thread Hijack - Lookalike Domain & Altered Reply-To
    eml_3 = """From: Accounts Receivable <accounts@titan-industria1.com>
Reply-To: settlement-desk@titan-financial-routing.net
To: Victoria Vance <v.vance@apextech-corp.com>
Subject: Re: Purchase Order PO-98442: Q4 Infrastructure Hardware - Banking Audit Notice
Date: Tue, 06 Oct 2026 03:14:10 +0000
Message-ID: <msg.20261006.031410.003@titan-industria1.com>
In-Reply-To: <msg.20261005.141522.002@titan-industrial.com>
References: <msg.20261005.093015.001@apextech-corp.com> <msg.20261005.141522.002@titan-industrial.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"
Received-SPF: fail (titan-industrial.com: domain does not designate 192.0.2.144 as permitted sender) client-ip=192.0.2.144;
Authentication-Results: mx.apextech-corp.com;
    dkim=fail header.i=@titan-industria1.com;
    spf=fail (apextech-corp.com: domain of accounts@titan-industria1.com does not designate sender) client-ip=192.0.2.144;
    dmarc=fail (p=REJECT) header.from=titan-industria1.com
Return-Path: <bounce@untrusted-relay-node.xyz>
Received: from untrusted-relay-node.xyz (untrusted-relay-node.xyz [192.0.2.144])
    by mx01.apextech-corp.com with ESMTP id APEX-IN-991
    for <v.vance@apextech-corp.com>; Tue, 06 Oct 2026 03:14:11 +0000

Victoria,

Please be advised that due to our annual financial fiscal audit, our standard Citibank account is temporarily frozen for incoming electronic deposits.
All pending remittance for PO-98442 must be routed through our audited escrow account.
Please confirm when your accounting team is prepared to process the wire today.

Regards,
Billing & Settlements
Titan Industrial Supplies
"""
    emails.append(("03_thread_hijack_preliminary.eml", eml_3))

    # 4. Critical BEC Attack - High Urgency Wire Diversion
    eml_4 = """From: Accounts Receivable <accounts@titan-industria1.com>
Reply-To: wire-settlements@titan-financial-routing.net
To: Victoria Vance <v.vance@apextech-corp.com>
CC: finance-team@apextech-corp.com
Subject: URGENT: Mandatory Payment Redirection - Immediate Wire Transfer Required for PO-98442
Date: Tue, 06 Oct 2026 04:45:00 +0000
Message-ID: <msg.20261006.044500.004@titan-industria1.com>
In-Reply-To: <msg.20261006.031410.003@titan-industria1.com>
References: <msg.20261005.093015.001@apextech-corp.com> <msg.20261005.141522.002@titan-industrial.com> <msg.20261006.031410.003@titan-industria1.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"
Received-SPF: fail client-ip=198.51.100.99;
Authentication-Results: mx.apextech-corp.com;
    dkim=fail;
    spf=fail smtp.mailfrom=accounts@titan-industria1.com;
    dmarc=fail (p=REJECT) header.from=titan-industria1.com
Return-Path: <attacker-drop@bulletproof-mta.top>
Received: from bulletproof-mta.top (bulletproof-mta.top [198.51.100.99])
    by mx01.apextech-corp.com with ESMTP id APEX-IN-995
    for <v.vance@apextech-corp.com>; Tue, 06 Oct 2026 04:45:01 +0000

URGENT NOTICE -- TIME SENSITIVE TRANSACTION

Victoria,

Per executive directive, you must wire the outstanding balance of $148,500.00 immediately today within 1 hour to prevent our logistics carrier from freezing the shipment container at the port terminal.

DO NOT use our previous banking details. Transfer funds strictly to the following beneficiary account:

Beneficiary Name: Apex Hardware Escrow Global Ltd
Beneficiary Bank: Offshore Mercantile Bank Zurich
Routing / SWIFT: OMBZCH22XXX
Account Number: 8849-0192-3841-9921
Reference: PO-98442-EXPEDITE

This matter is strictly confidential between finance management. Do not delay or discuss externally until the transaction receipt is provided.
Send the electronic payment confirmation slip directly to this email right away.

Regards,
Director of Global Settlements
Titan Industrial Supplies
"""
    emails.append(("04_urgent_wire_diversion_attack.eml", eml_4))

    # 5. Pressure & Coercion Follow-Up
    eml_5 = """From: Accounts Receivable <accounts@titan-industria1.com>
Reply-To: wire-settlements@titan-financial-routing.net
To: Victoria Vance <v.vance@apextech-corp.com>
Subject: FINAL NOTICE: Wire Transfer Slip Required - Immediate Action Mandatory
Date: Tue, 06 Oct 2026 06:10:00 +0000
Message-ID: <msg.20261006.061000.005@titan-industria1.com>
In-Reply-To: <msg.20261006.044500.004@titan-industria1.com>
References: <msg.20261006.044500.004@titan-industria1.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"
Received-SPF: fail client-ip=198.51.100.99;
Authentication-Results: mx.apextech-corp.com;
    dkim=fail;
    spf=fail;
    dmarc=fail header.from=titan-industria1.com
Return-Path: <attacker-drop@bulletproof-mta.top>

Victoria,

We have not received the bank transfer confirmation.
You have 30 minutes before our freight forwarding partner incurs severe demurrage penalties.
Act now and remit the wire transfer to the provided beneficiary account without delay.

Director of Global Settlements
"""
    emails.append(("05_followup_coercion_pressure.eml", eml_5))

    return emails


def build_enterprise_baseline_case() -> list[tuple[str, str]]:
    """Case 2026-BASE: 15 legitimate corporate communications establishing statistical baselines."""
    emails = []

    # CEO Robert Sterling regular emails (10:00 - 16:00, legitimate internal staff)
    ceo_recipients = [
        ("victoria.vance@apextech-corp.com", "Board Meeting Agenda Review"),
        ("management@apextech-corp.com", "Q3 All-Hands Executive Summary"),
        ("legal@apextech-corp.com", "Compliance Documentation Review"),
        ("hr-operations@apextech-corp.com", "Annual Performance Evaluation Timeline"),
        ("victoria.vance@apextech-corp.com", "Strategic Partnership Discussion"),
    ]
    for idx, (recip, subj) in enumerate(ceo_recipients, start=1):
        dt_str = f"Wed, 2{idx} Sep 2026 {10+idx:02d}:15:00 +0000"
        body = f"""Hi Team,\n\nPlease review the attached notes regarding {subj}.\nWe will convene next Tuesday to review progress.\n\nBest regards,\nRobert Sterling\nChief Executive Officer\nApex Global Technologies\n"""
        eml = f"""From: Robert Sterling <robert.sterling@apextech-corp.com>
To: {recip}
Subject: {subj}
Date: {dt_str}
Message-ID: <base.ceo.{idx}@apextech-corp.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"
Received-SPF: pass (apextech-corp.com designates 198.51.100.10) client-ip=198.51.100.10;
Authentication-Results: mx.apextech-corp.com;
    dkim=pass header.i=@apextech-corp.com;
    spf=pass smtp.mailfrom=robert.sterling@apextech-corp.com;
    dmarc=pass (p=REJECT) header.from=apextech-corp.com
DKIM-Signature: v=1; a=rsa-sha256; d=apextech-corp.com; s=apex2026; h=from:to:subject:date; bh=dGhpc2lzYXRlc3Q=; b=Y2Vvc2lnbmF0dXJl
Return-Path: <robert.sterling@apextech-corp.com>
Received: from internal-mail.apextech-corp.com ([10.0.1.5])
    by mx.apextech-corp.com with ESMTPS id APEX-BASE-{idx};
    {dt_str}

{body}"""
        emails.append((f"base_ceo_0{idx}.eml", eml))

    # CFO Victoria Vance regular emails
    cfo_emails = [
        ("accounting@apextech-corp.com", "Monthly Ledger Reconciliation Guidelines"),
        ("audit-committee@apextech-corp.com", "Preliminary FY2026 Audit Schedule"),
        ("procurement@apextech-corp.com", "Vendor Onboarding Procedures Update"),
        ("robert.sterling@apextech-corp.com", "Q3 Financial Performance Dashboard"),
        ("staff@apextech-corp.com", "Travel Expense Reimbursement Deadlines"),
    ]
    for idx, (recip, subj) in enumerate(cfo_emails, start=1):
        dt_str = f"Thu, 1{idx} Sep 2026 {11+idx:02d}:30:00 +0000"
        body = f"""Colleagues,\n\nHere is the documentation regarding {subj}. All department heads must ensure compliance.\n\nWarm regards,\nVictoria Vance\nChief Financial Officer\n"""
        eml = f"""From: Victoria Vance <v.vance@apextech-corp.com>
To: {recip}
Subject: {subj}
Date: {dt_str}
Message-ID: <base.cfo.{idx}@apextech-corp.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"
Received-SPF: pass client-ip=198.51.100.10;
Authentication-Results: mx.apextech-corp.com;
    dkim=pass header.i=@apextech-corp.com;
    spf=pass smtp.mailfrom=v.vance@apextech-corp.com;
    dmarc=pass header.from=apextech-corp.com
DKIM-Signature: v=1; a=rsa-sha256; d=apextech-corp.com; s=apex2026; h=from:to:subject:date; bh=dGhpc2lzYXRlc3Q=; b=Y2Zvc2lnbmF0dXJl
Return-Path: <v.vance@apextech-corp.com>
Received: from internal-mail.apextech-corp.com ([10.0.1.6])
    by mx.apextech-corp.com with ESMTPS id APEX-CFO-{idx};
    {dt_str}

{body}"""
        emails.append((f"base_cfo_0{idx}.eml", eml))

    # Ops & Engineering regular emails
    ops_emails = [
        ("Marcus Chen <m.chen@apextech-corp.com>", "dev-team@apextech-corp.com", "Sprint 42 Architecture Blueprint"),
        ("HR Desk <hr@apextech-corp.com>", "all-employees@apextech-corp.com", "Annual Healthcare Enrollment Open"),
        ("Marcus Chen <m.chen@apextech-corp.com>", "ops@apextech-corp.com", "Database Migration Maintenance Window"),
        ("IT Support <support@apextech-corp.com>", "all-employees@apextech-corp.com", "Scheduled Single Sign-On Certificate Renewal"),
        ("Facility Ops <facilities@apextech-corp.com>", "all-employees@apextech-corp.com", "Headquarters Access Badge Audit Next Week"),
    ]
    for idx, (sender, recip, subj) in enumerate(ops_emails, start=1):
        dt_str = f"Fri, 0{idx} Sep 2026 {13+idx:02d}:00:00 +0000"
        addr = sender.split("<")[-1].replace(">", "").strip()
        body = f"""Notice to staff,\n\nPlease take note of the schedule for {subj}. Reach out if you have questions.\n\nRegards,\nApex Operations Team\n"""
        eml = f"""From: {sender}
To: {recip}
Subject: {subj}
Date: {dt_str}
Message-ID: <base.ops.{idx}@apextech-corp.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"
Received-SPF: pass client-ip=198.51.100.10;
Authentication-Results: mx.apextech-corp.com;
    dkim=pass header.i=@apextech-corp.com;
    spf=pass smtp.mailfrom={addr};
    dmarc=pass header.from=apextech-corp.com
Return-Path: <{addr}>
Received: from internal-mail.apextech-corp.com ([10.0.1.8])
    by mx.apextech-corp.com with ESMTPS id APEX-OPS-{idx};
    {dt_str}

{body}"""
        emails.append((f"base_ops_0{idx}.eml", eml))

    return emails


def build_executive_payroll_case() -> list[tuple[str, str]]:
    """Case 2026-PAYROLL: Display-Name Spoofing targeting payroll."""
    eml = """From: Robert Sterling, Chief Executive Officer <ceo.robertsterling.exec@gmail.com>
To: payroll-team@apextech-corp.com
CC: hr-director@apextech-corp.com
Reply-To: ceo.robertsterling.exec@gmail.com
Subject: CONFIDENTIAL: Immediate Direct Deposit Account Modification - Urgent
Date: Tue, 06 Oct 2026 02:40:12 +0000
Message-ID: <gmail.20261006.024012@gmail.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"
Received-SPF: pass (google.com: domain of ceo.robertsterling.exec@gmail.com designates 209.85.220.41 as permitted sender) client-ip=209.85.220.41;
Authentication-Results: mx.apextech-corp.com;
    dkim=pass header.i=@gmail.com;
    spf=pass client-ip=209.85.220.41;
    dmarc=pass (p=REJECT) header.from=gmail.com
Return-Path: <ceo.robertsterling.exec@gmail.com>
Received: from mail-sor-f41.google.com (mail-sor-f41.google.com [209.85.220.41])
    by mx.apextech-corp.com with ESMTPS id APEX-SPOOF-01
    for <payroll-team@apextech-corp.com>; Tue, 06 Oct 2026 02:40:13 +0000

Payroll Team,

I am currently traveling abroad and in sensitive executive meetings, so I cannot take phone calls or check my office desktop right now.
Due to a personal banking consolidation, I need my payroll direct deposit account updated immediately before this morning's payroll batch cutoff.

New Account Details:
Bank: Metropolitan Federal Credit Union
Routing Number: 021000089
Account Number: 4492-1084-2910
Account Type: Checking

Please confirm back to this private email as soon as the direct deposit transfer routing is changed. Keep this confidential between us until the payment is cleared.

Thank you,
Robert Sterling
Chief Executive Officer
Apex Global Technologies
"""
    return [("01_display_name_spoof_payroll_divert.eml", eml)]


def generate_all_cases() -> dict[str, Path]:
    """Generate all case folders and MBOX containers on disk."""
    created = {}

    # 1. Operation WireShifter
    wire_dir = CASES_DIR / "operation_wireshifter"
    wire_dir.mkdir(parents=True, exist_ok=True)
    for fname, content in build_operation_wireshifter_case():
        (wire_dir / fname).write_text(content, encoding="utf-8")
    created["wireshifter"] = wire_dir

    # 2. Enterprise Baseline Corpus
    base_dir = CASES_DIR / "enterprise_baseline"
    base_dir.mkdir(parents=True, exist_ok=True)
    for fname, content in build_enterprise_baseline_case():
        (base_dir / fname).write_text(content, encoding="utf-8")
    created["baseline"] = base_dir

    # 3. Executive Payroll
    pay_dir = CASES_DIR / "executive_payroll"
    pay_dir.mkdir(parents=True, exist_ok=True)
    for fname, content in build_executive_payroll_case():
        (pay_dir / fname).write_text(content, encoding="utf-8")
    created["payroll"] = pay_dir

    # 4. Standard Seized MBOX Container
    mbox_path = CASES_DIR / "forensic_seizure.mbox"
    if mbox_path.exists():
        mbox_path.unlink()

    mbox = mailbox.mbox(str(mbox_path))
    # Combine WireShifter and Payroll into an MBOX container
    all_emails = build_operation_wireshifter_case() + build_executive_payroll_case()
    for fname, content in all_emails:
        msg = mailbox.mboxMessage(content.encode("utf-8"))
        mbox.add(msg)
    mbox.flush()
    mbox.close()
    created["mbox"] = mbox_path

    # 5. ZIP Evidence Container
    import zipfile
    zip_path = CASES_DIR / "operation_wireshifter_evidence.zip"
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as z:
        for f in wire_dir.glob("*.eml"):
            z.write(f, arcname=f.name)
    created["zip"] = zip_path

    return created


if __name__ == "__main__":
    res = generate_all_cases()
    print("Forensic case corpora successfully generated:")
    for k, v in res.items():
        print(f"  [{k}]: {v}")
