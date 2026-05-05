# Camellia test corpora

CESS does not vendor a separate Camellia JSON corpus here. Known-answer tests for **Camellia** single-layer, **ChaCha/Serpent/Camellia** cascades, and **Ed25519** inner-bulk templates are in **`vectors/camellia.toml`** (schema `cess-camellia-v0.2`) and are verified by the **`runner/`** crate (`cess_runner::camellia_bulk`).

Registry rows include **`0x0031`–`0x0036`** and **`0x0208`–`0x020c`**; see **`ALGORITHM-REGISTRY.md`**.
