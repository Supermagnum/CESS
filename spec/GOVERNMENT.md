# Government and high-security deployment guidance (informative)

**Version:** 0.1-draft  

This note supports procurement officers, architects, and security officers evaluating CESS for **government** and **regulated** environments. It is **not** legal advice.

## 1. Standards bodies and liaison

| Body | Role (informative) |
|------|-------------------|
| **BSI** | German federal security guidance; Brainpool and procedural references. |
| **ANSSI** | French national security posture; ECC and key management practices. |
| **ENISA** | EU-wide recommendations on crypto agility and PQ transition. |
| **NATO/NCSA** | Alliance information assurance references (deployment-specific). |
| **ETSI TC CYBER** | European telecom security standards; potential liaison for profiles. |

Contact points change over time; use official registers when initiating liaison.

## 2. Procurement mapping

CESS addresses **technical** controls: threshold splitting, AEAD, password hashing, integrity, optional PQ hybrid. **Organisational** controls (cleared personnel, split knowledge, logging) remain **separate** procurement line items.

Map CESS components to your agency’s **control catalogues** (e.g. access control, key management, crypto agility) using your national framework.

## 3. Air-gap operational procedures

- Generate master secrets only on **offline** machines with verified media.  
- **Transfer** shares via **separate** channels (in-person, registered mail, national courier).  
- **Verify** fingerprints of software releases out-of-band.

## 4. Personnel security

CESS does not replace **background checks**, **need-to-know**, or **two-person rule** procedures where policy mandates them.

## 5. Coercion resistance in practice

Technical splitting reduces **single-point** coercion; **operational** mitigations include **duress codes**, **time delays**, and **legal** protections. CESS provides **technical** building blocks only.

## 6. Jurisdiction and cross-border escrow

Cross-border **key escrow** involves **data protection**, **export**, and **national security** law. Architectures SHOULD involve **local counsel** in each jurisdiction.

## 7. Path to normative adoption

Informative options:

1. **IETF Informational RFC** publication for the CESS specification.  
2. **BSI / ANSSI** joint technical note referencing CESS profiles.  
3. **ETSI** technical report or work item if telecom alignment is desired.

Each path requires **community consensus** and **maintainer** support independent of this document.
