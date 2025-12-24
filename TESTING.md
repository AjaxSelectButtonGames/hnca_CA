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

## 7. Export Register Snapshot (Federation)
```
curl http://localhost:4000/api/register/snapshot
```

## 8. Import a Register Snapshot
Save a snapshot JSON from another node, then:
```
curl -X POST http://localhost:4000/api/register/import \
  -H 'Content-Type: application/json' \
  -d @snapshot.json
```

## 9. Troubleshooting
- Check server logs for errors.
- Ensure all dependencies are installed.
- Use `npm run dev` for auto-reload during development.

---
For further help, provide error messages or logs for diagnosis.
