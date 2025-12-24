# HNCA CA Server Testing Guide

This guide will help you test the HNCA Certificate Authority server on your Linux server.

## 1. Prerequisites
- Node.js (v16+ recommended)
- npm
- curl or httpie (for API testing)

## 2. Install Dependencies
```
npm install
```

## 3. Start the Server
```
npm start
```
The server should run on port 4000 by default.

## 4. Health Check
Test the health endpoint:
```
curl http://localhost:4000/health
```
Expected output: `{ "status": "ok", ... }`

## 5. Issue a User Certificate
```
curl -X POST http://localhost:4000/api/certificates/issue \
  -H 'Content-Type: application/json' \
  -d '{
    "type": "user",
    "params": {
      "commonName": "Alice Example",
      "organization": "TestOrg",
      "country": "US",
      "metadata": {"email": "alice@example.com"}
    }
  }'
```
You should receive a JSON response with PEM-encoded certificate, private key, and log entry.

## 6. Issue a Website Certificate
```
curl -X POST http://localhost:4000/api/certificates/issue \
  -H 'Content-Type: application/json' \
  -d '{
    "type": "website",
    "params": {
      "commonName": "example.com",
      "organization": "ExampleOrg",
      "country": "US",
      "subjectAltNames": ["example.com", "www.example.com"],
      "metadata": {"site": "main"}
    }
  }'
```


## 7. Merkle Proofs & Federation

### 7.1. Get Merkle Proof for a Certificate
Replace <fingerprint> with the actual fingerprint from a log entry:
```
curl http://localhost:4000/api/register/proof/<fingerprint>
```
This returns the Merkle proof, root, and entry for that certificate.

### 7.2. Verify a Merkle Proof
You can verify a proof (from above) using:
```
curl -X POST http://localhost:4000/api/register/verify-proof \
  -H 'Content-Type: application/json' \
  -d '{
    "entry": { ... },
    "proof": [ ... ],
    "merkleRoot": "..."
  }'
```
You should receive `{ "valid": true }` if the proof is correct.

### 7.3. Federation: Syncing Registers
1. On Node A, get the Merkle root:
   ```
   curl http://localhost:4000/api/register/snapshot
   ```
   (Or just use the root from any proof response)
2. On Node B, request proofs for any missing fingerprints from Node A.
3. Use `/api/register/verify-proof` to verify proofs before accepting entries.
4. Add new entries to Node B's register if proofs are valid.

This allows efficient, cryptographically secure federation without full log transfer.

## 9. Troubleshooting
- Check server logs for errors.
- Ensure all dependencies are installed.
- Use `npm run dev` for auto-reload during development.

---
For further help, provide error messages or logs for diagnosis.
