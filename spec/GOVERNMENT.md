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

## 8. Strategic Autonomy and Alliance Transition Scenarios

This section is **informative** and **not** legal advice. It extends planning discussions beyond day-to-day procurement to **long-horizon** alliance and supply-chain assumptions. National authorities remain authoritative for threat assessments and export classification.

### 8.1 Alliance transition as a planning threat model

Defence and civil continuity planners increasingly treat **abrupt alliance change** as a scenario class, not only classical peer adversaries. For cryptographic planning, one **named** scenario is **United States withdrawal from NATO** (or an equivalent breakdown of US–European defence integration). Under such a scenario, **cryptographic trust assumptions** tied to US agencies, US-accredited products, and NATO-wide **single points of policy** may need to be **re-evaluated** faster than typical refresh cycles.

CESS is designed so that **technical** baselines for splitting, wrapping, and encrypting long-lived secrets do **not** depend on NSA-designed symmetric primitives, SHA-2/SHA-3-only stacks, NIST elliptic curves, or ML-KEM for the **normative** profile (see `spec/CRYPTO.md` and `ALGORITHM-REGISTRY.md`). That design choice supports **European-led** review and procurement **independent** of a FIPS-only or US-centric algorithm mandate, which matters when alliance structures change.

### 8.2 Cryptographic dependencies that CESS eliminates or reduces

For deployments that adopt CESS **as specified**, the following **classes** of dependency are **avoided** for CESS protocol primitives:

- **NSA-designed block ciphers** (e.g. AES) and **NSA-designed hash families** (SHA-2; SHA-3 per CESS exclusion policy) as **mandated** CESS primitives.  
- **NIST elliptic curves** (P-256, P-384, P-521) for **classical ECDH** in the normative CESS profile; **Brainpool** (RFC 5639) is used instead, with **BSI**-aligned practice as an informative reference.  
- **ML-KEM / Kyber** as the **default** post-quantum KEM under CESS policy; alternative PQ candidates are listed in the registry for **hybrid** use.  
- **Exclusive** reliance on **NIST SP 800-series** or **FIPS-only** evidence as the **sole** audit basis for the **cipher-agnostic** layer (the specification explicitly allows other evidence; see `spec/CESS-v0.1.md`).

CESS does **not** remove the need for **sound implementation**, **key management**, or **organisational** controls; it narrows **algorithmic** lock-in to US-centric suites for the **documented** stack.

### 8.3 Cryptographic dependencies that remain

Even with CESS, **residual** dependencies include:

#### 8.3.1 Supply chain

Compilers, runtimes, operating systems, and **third-party cryptographic libraries** (including **transitive** crates or packages). These must be **vetted** under national assurance programmes; CESS cannot guarantee absence of excluded algorithms inside **non-CESS** dependencies.

#### 8.3.2 Hardware

CPUs, **HSMs**, smartcards, TPMs, and **firmware**. Physical tamper resistance and side-channel posture remain **product** and **accreditation** questions.

#### 8.3.3 Operational

Key ceremonies, personnel clearances, and **cross-border** data paths (see Section 6).

#### 8.3.4 Personnel and expertise concentration

A significant portion of practical cryptographic **operational** expertise in NATO member states has been developed in close collaboration with **US** institutions. An **abrupt alliance transition** would reduce access to this **expertise network**.

CESS **partially mitigates** this by grounding its **evaluation** framework in **European** academic and government bodies (**BSI**, **ANSSI**) and in **international** research communities with strong European participation (**IACR**; **NESSIE** and **ECRYPT** alumni networks) that maintain **independent** expertise. Member states are **encouraged** to invest in **national** cryptographic research capacity that does **not** depend on US institutional participation, and to treat the CESS **maintainer diversity** requirement (substantive specification reviewers from **organisations in different countries**; see [`CONTRIBUTING.md`](../CONTRIBUTING.md)) as a **model** for their own internal staffing of cryptographic roles.

### 8.4 Institutional gap and an interim European path

There is **no** single European body that reproduces **NATO NCSA**-style alliance-wide cryptographic policy for all member states. National agencies (**ANSSI** in France, **BSI** in Germany, **NCSC-NL** in the Netherlands, and others) publish **national** guidance; **ENISA** coordinates recommendations at EU level but does not replace national authority.

An **interim** path for governments that want **European anchor** documents while alliance structures evolve:

1. **BSI** technical references (e.g. TR-03111 alongside RFC 5639) for **ECC** practice.  
2. **ANSSI** posture and key-management guidance where profiles overlap.  
3. **ETSI** TC CYBER (and related work items) for **sector** profiles and **interoperability** artefacts when telecom or cross-border services are in scope.

CESS is a **candidate** for citation in such notes as an **open** specification with an **independent** exclusion list; **normative** adoption still follows Section 7.

### 8.5 BLS12-381 threshold signatures and the “former ally as adversary” sub-scenario

Where the threat model includes a **former ally** acting as an **active** adversary against **governance** or **infrastructure** (e.g. disputing roots of trust, revoking credentials, or manipulating policy updates), **long-term storage** alone is insufficient; **distributed authorization** and **verifiable** collective action matter.

**BLS12-381** pairing-based signatures support **short** signatures, **aggregation**, and **threshold** schemes with substantial **open** ecosystem use and **peer-reviewed** analysis. For **policy signing**, **federated issuance**, and **k-of-n** approval of high-impact actions, **BLS12-381 threshold signatures** are a strong **technical** complement to CESS’s **secret-sharing** and **AEAD** layers: CESS protects **material** at rest and in transit under chosen suites; **BLS threshold** deployments can reduce reliance on a **single** national or former-alliance **signing** root for **operational** decisions.

**Note:** BLS12-381 is **not** part of the CESS v0.1 **normative** algorithm registry. Governments SHOULD treat it as an **adjacent** governance and PKI technology to be integrated under **national** policy and, if proposed for CESS interop, through **`ALGORITHM-REGISTRY.md`** review.

### 8.6 ITAR, EAR, and open published standards (high level)

**United States** export controls include **ITAR** (defence articles and services) and **EAR** (dual-use items, including many **information security** items). Classification is **fact-specific** and **jurisdiction-specific**.

For **European sovereign adoption**, the following **general** points are often relevant in public policy discussions (verify with **qualified counsel**):

- **Publicly available** cryptographic **source code** and **documentation** are treated differently from **unpublished** or **classified** artefacts under **EAR** (including Category 5 Part 2). Open publication on a **public repository** is a common pattern for **non-licensed** redistribution of **public** algorithms, subject to current rules and end-use restrictions.  
- **ITAR** targets defence articles and technical data in the USML context; an **open**, **civilian** cryptographic **specification** document is **not** typically equivalent to a **classified** US algorithm **embodiment**, but **implementations** embedded in **defence articles** may still be controlled.  
- CESS is published as an **open** standard with **no** proprietary **secret** algorithm: implementers choose **accredited** libraries and **national** approval paths. The **text** of the standard does not, by itself, substitute for **product** export classification where hardware or controlled services are involved.

This subsection is **not** a classification ruling; agencies MUST obtain **legal** and **export** advice before procurement or cross-border transfer.

### 8.7 Recommended immediate actions (European governments dependent on NATO cryptographic infrastructure)

Governments that rely heavily on **NATO**-harmonised products and **US** accreditation paths SHOULD consider:

1. **Inventory** cryptographic **dependencies** (algorithms, HSM firmware origins, cloud regions, **PKI** roots) against **national** continuity requirements.  
2. **Pilot** CESS (or equivalent **non-FIPS-only**) **profiles** for **new** systems where **independence** from NSA/NIST-only baselines is a goal, aligned with `spec/CRYPTO.md`.  
3. **Fund** **European** audits and **open** reference implementations for **Brainpool**, **Argon2id**, **BLAKE3**, and **CESS-PQ** hybrids per registry rules.  
4. **Engage** **BSI**, **ANSSI**, and **ETSI** for **technical notes** or **profiles** that cite **open** standards explicitly.  
5. **Plan** **threshold signing** (including **BLS12-381** where policy allows) for **governance** keys separate from **storage** keys, with **k-of-n** ceremonies under **national** control.  
6. **Exercise** **break-glass** and **alliance-transition** procedures in **tabletop** form, including **key rotation** without US vendor **exclusive** control.

These actions are **complementary** to NATO operational security; they reduce **single-jurisdiction** algorithm and **vendor** concentration where policy demands it.
