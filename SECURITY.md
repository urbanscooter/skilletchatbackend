# Security & Zero-Knowledge Architecture

## Threat Model & Principles
This relay server is built strictly on the **Zero-Knowledge Principle**. The server acts as a blind routing node and enforces the following invariants:

1. **No Cryptographic Keys on Server:**
   The server never receives, generates, stores, or processes private keys or symmetric AES keys. Encryption keys are negotiated exclusively client-side.

2. **Blind Transport (E2EE Only):**
   The server validates that all outgoing messages adhere strictly to the authenticated `v2:<IV>:<CIPHERTEXT+TAG>` AES-256-GCM specification. Plaintext messages are rejected at the edge.

3. **No PII or Message Persistence:**
   The server holds all room associations in ephemeral memory. No chat payloads, IP addresses, or message texts are persisted to disk or databases.

4. **Abuse Mitigation:**
   - **Token Bucket Rate Limiting:** Enforces strict burst and sustained message caps per client.
   - **Payload Quarantine:** Messages exceeding 64 KB are dropped to prevent memory exhaustion attacks.
   - **Input Sanitization:** Room IDs and parameters are strictly validated via regular expressions.
