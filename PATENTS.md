# Patent statement and contributor covenant (CESS)

**Standard:** CESS — Cryptologically Enchanted Shamir's Secret  
**Version:** 0.1-draft  

This file documents patent-related expectations for the CESS repository and for implementations of the standard.

## Open Invention Network (OIN)

The project maintainers **intend** for participating organisations to leverage membership in the **Open Invention Network (OIN)** where appropriate, so that Linux-related defensive patent pools may cover selected technologies used alongside CESS deployments.

OIN membership is **not** a substitute for a **licence to practise** any patent that might read on CESS in all jurisdictions. OIN arrangements are **limited by their own terms** and do not automatically extend to all conforming implementations or all use cases.

## Contributor patent non-assertion covenant

**By submitting a pull request, patch, or other contribution** to this repository that is merged or otherwise accepted into the CESS specification, test vectors, or reference code, **each contributor** (personally and, if applicable, on behalf of their employer) **irrevocably covenants** that they **will not assert** any **patent claim** they control or have the right to license against:

1. **Any conforming implementation** of the CESS standard (any version published in this repository or formally superseded with migration guidance), in **any programming language**, on **any platform**, for **any purpose**, including **commercial** and **government** use; and  
2. **Reasonable extensions** that remain interoperable with the normative wire formats and test vectors, where such extensions are clearly identified as non-normative.

This covenant is **intended to run with** the standard and **survive** changes of employment or assignment, to the maximum extent permitted by applicable law.

## Scope of coverage

The covenant covers **conforming implementations** of:

- Shamir's Secret Sharing over GF(2^8) as specified;  
- Mandatory Argon2id, BLAKE3, and share-envelope constructions in the standard;  
- Cipher-agnostic layers **when implemented** using algorithms admitted by the CESS Algorithm Registry at the time of implementation, or using profiles explicitly listed as examples in the specification.

## How contributors accept this covenant

Submission of a **merged** pull request to this repository constitutes **agreement** to this `PATENTS.md` file as of the commit date. Organisations may additionally record **signed** contributor agreements; those agreements **supplement** but do **not replace** this public covenant for community contributions.

## Relationship to OIN

- **OIN** may provide **additional** defensive value for certain Linux-related stacks.  
- **OIN membership** of an implementer is **not required** for the covenant to benefit that implementer.  
- Conversely, **OIN membership** does **not** imply freedom from unrelated patents; **due diligence** remains the responsibility of each deployer.

## Limitations (what is not covered)

This document **does not**:

- Grant a licence to **non-essential** patents on unrelated features (user interface, file systems, cloud orchestration, and so on);  
- Waive **trademark** or **branding** rights (see `CONFORMANCE.md` — the name CESS is used descriptively);  
- Guarantee **freedom to operate** in every jurisdiction; procurement and legal review remain **required** for regulated deployments;  
- Limit contributors’ rights to assert patents against **non-conforming** products that are **materially incompatible** with mandatory CESS wire formats or security properties.

## Contact

Patent clarifications should be directed to the repository maintainers via the issue tracker described in `CONTRIBUTING.md`.
