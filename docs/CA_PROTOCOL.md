# HNCA Certificate Authority Protocol & Data Model

## Certificate Types
- **Root CA**: Top-level authority, issues intermediate CAs.
- **Intermediate CA**: Issues user and website certificates, signed by Root CA.
- **User Certificate**: Issued to verified humans, contains hashed+salted identifier.
- **Website Certificate**: Issued to websites opting in, contains domain and HNCA metadata.
- **Robot Certificate** : Issued to trusted verified bots, such as indexing bots, research bots, and others. 

## Certificate Metadata
All certificates include standard X.509 fields plus HNCA-specific extensions:
- `hnca:type`: root | intermediate | user | website
- `hnca:register_id`: Unique ID of issuing register (for federation)
- `hnca:issued_at`: Timestamp
- `hnca:revoked`: Boolean (in registry, not cert)
- `hnca:human_hash`: (user certs) Hashed+salted phone or other proof
- `hnca:domain`: (website certs) Domain name
- `hnca:metadata`: Optional, for future extensions

## Issuance Flow (User)
1. User submits proof of humanness (e.g., phone verification)
2. System generates salt, hashes proof, creates keypair
3. Issues user certificate signed by intermediate CA
4. Logs issuance in registry

## Issuance Flow (Website)
1. Owner requests cert, proves domain control
2. System issues website certificate signed by intermediate CA
3. Logs issuance in registry

## Issuance Flow (Robot) -- this allows for better bot tracking and revocation
1. Owner of bot such as GoogleBot submits bot CA 
2. Owner also submits website CA, alongside other pertinant data
3. Logs issuance in registry

## Revocation Flow
- Certificates can be revoked by register or user/owner
- Revocation is logged in registry

## Registry/Log Structure
- Each register maintains a signed log of issued/revoked certificates
- Log entry: {
    id, type, subject, issued_at, revoked, register_id, cert_fingerprint, metadata
  }
- Logs are exportable/importable for federation

---
This protocol is designed for easy federation and future decentralization. All registers must follow the same issuance, logging, and revocation rules.
