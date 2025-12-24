// HNCA Certificate Authority Server Skeleton
// Entry point for the Node.js CA server


const express = require('express');
const Register = require('./register');
const certUtil = require('./certUtil');
const forge = require('node-forge');
const app = express();
// Allow port override via env or command-line argument
let PORT = process.env.PORT || 4000;
const argPort = process.argv.find(arg => arg.startsWith('--port='));
if (argPort) {
  PORT = parseInt(argPort.split('=')[1], 10) || PORT;
}

// Initialize the Register (in-memory for now)
const registerKeyPair = certUtil.generateKeyPair();
const register = new Register({
  name: 'HNCA Register 1',
  publicKey: registerKeyPair.publicKey,
  privateKey: registerKeyPair.privateKey
});

// Middleware
app.use(express.json());

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok', time: new Date().toISOString() });
});


// Issue certificate (user, website, robot)
app.post('/api/certificates/issue', (req, res) => {
  try {
    const { type, params } = req.body;
    // Supported types: 'user', 'website', 'robot'
    let hncaType, extKeyUsage, subjectAltNames;
    if (type === 'user') {
      hncaType = 2;
      extKeyUsage = { clientAuth: true };
    } else if (type === 'website') {
      hncaType = 3;
      extKeyUsage = { serverAuth: true };
      subjectAltNames = params.subjectAltNames || [];
    } else if (type === 'robot') {
      hncaType = 4;
      extKeyUsage = null;
    } else {
      return res.status(400).json({ error: 'Invalid certificate type' });
    }

    // For demo, generate a new intermediate CA for signing (in real use, persist this)
    const root = certUtil.createRootCACert({
      commonName: 'HNCA Root',
      organization: 'HumanNet',
      country: 'US'
    });
    const intermediate = certUtil.createIntermediateCACert({
      commonName: 'HNCA Intermediate',
      organization: 'HumanNet',
      country: 'US'
    }, root.cert, root.privateKey);

    // Compose params for entity cert
    const entityParams = {
      ...params,
      hncaType,
      registerId: register.id,
      extKeyUsage,
      subjectAltNames
    };
    const { cert, privateKey } = certUtil.createEntityCert(
      entityParams,
      intermediate.cert,
      intermediate.privateKey
    );

    // Log the issued cert in the register
    const entry = register.logIssuedCert({ cert, type, metadata: params.metadata || {} });

    // Return PEMs and log entry
    res.json({
      certificate: forge.pki.certificateToPem(cert),
      privateKey: forge.pki.privateKeyToPem(privateKey),
      intermediate: forge.pki.certificateToPem(intermediate.cert),
      root: forge.pki.certificateToPem(root.cert),
      logEntry: entry
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Placeholder: Revoke certificate
app.post('/api/certificates/revoke', (req, res) => {
  // TODO: Implement certificate revocation logic
  res.status(501).json({ error: 'Not implemented' });
});


// Export register snapshot (for federation sync)
app.get('/api/register/snapshot', (req, res) => {
  res.json(register.exportSnapshot());
});

// Import a snapshot from another register (federation sync)
app.post('/api/register/import', (req, res) => {
  try {
    register.importSnapshot(req.body);
    res.json({ status: 'imported', merkleRoot: register.merkleRoot });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

// Merkle proof endpoints
const { getLeaf } = require('./merkleUtil');

// Get Merkle proof for a cert fingerprint
app.get('/api/register/proof/:fingerprint', (req, res) => {
  const { fingerprint } = req.params;
  const entry = register.issuedCerts.get(fingerprint);
  if (!entry) {
    return res.status(404).json({ error: 'Certificate not found' });
  }
  if (!register.merkleTree) {
    return res.status(500).json({ error: 'Merkle tree not available' });
  }
  const leaf = getLeaf(entry);
  const proof = register.merkleTree.getHexProof(leaf);
  res.json({
    fingerprint,
    merkleRoot: register.merkleRoot,
    proof,
    entry
  });
});

// Verify a Merkle proof (client submits entry, proof, and root)
app.post('/api/register/verify-proof', (req, res) => {
  const { entry, proof, merkleRoot } = req.body;
  if (!entry || !proof || !merkleRoot) {
    return res.status(400).json({ error: 'Missing entry, proof, or merkleRoot' });
  }
  const { MerkleTree } = require('merkletreejs');
  const keccak256 = require('keccak256');
  const leaf = getLeaf(entry);
  // For verification, we need the same hash function and options
  const valid = MerkleTree.verify(proof, leaf, merkleRoot, keccak256, { sortPairs: true });
  res.json({ valid });
});

// Start server
app.listen(PORT, () => {
  console.log(`HNCA CA server running on port ${PORT}`);
});
