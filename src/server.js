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

// Add a new entry to the register if the proof is valid
app.post('/api/register/add-entry', (req, res) => {
  const { entry, proof, merkleRoot } = req.body;
  if (!entry || !proof || !merkleRoot) {
    return res.status(400).json({ error: 'Missing entry, proof, or merkleRoot' });
  }
  const { MerkleTree } = require('merkletreejs');
  const keccak256 = require('keccak256');
  const { getLeaf } = require('./merkleUtil');
  const leaf = getLeaf(entry);
  const valid = MerkleTree.verify(proof, leaf, merkleRoot, keccak256, { sortPairs: true });
  if (!valid) {
    return res.status(400).json({ error: 'Invalid Merkle proof' });
  }
  // Only add if not already present
  if (register.issuedCerts.has(entry.fingerprint)) {
    return res.status(409).json({ error: 'Entry already exists' });
  }
  register.issuedCerts.set(entry.fingerprint, entry);
  register.updateMerkleTree();
  res.json({ status: 'added', fingerprint: entry.fingerprint });
});

// Federation: notify peers and reach quorum on new CA
// This is a stub for federation logic. In production, use a message queue or pub/sub system.
const peers = process.env.PEER_NODES ? process.env.PEER_NODES.split(',') : [];
// Quorum logic for federation
const QUORUM = process.env.PEER_QUORUM ? parseInt(process.env.PEER_QUORUM, 10) : peers.length + 1;
const quorumAcks = new Map(); // fingerprint -> Set of peer URLs that acknowledged

// Enhance notifyPeersOfNewEntry to track acknowledgments
global.notifyPeersOfNewEntry = async function(entry, proof, merkleRoot) {
  const payload = JSON.stringify({ entry, proof, merkleRoot });
  const fingerprint = entry.fingerprint;
  if (!quorumAcks.has(fingerprint)) quorumAcks.set(fingerprint, new Set());
  // Add self-ack
  quorumAcks.get(fingerprint).add('self');
  for (const peer of peers) {
    try {
      const res = await fetch(`${peer}/api/register/add-entry`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: payload
      });
      const data = await res.json();
      if (data.status === 'added' || data.status === 'exists') {
        quorumAcks.get(fingerprint).add(peer);
      }
    } catch (err) {
      console.error(`Error notifying peer ${peer}:`, err);
    }
  }
  // Check for quorum
  if (quorumAcks.get(fingerprint).size >= QUORUM) {
    console.log(`Quorum reached for CA ${fingerprint}:`, Array.from(quorumAcks.get(fingerprint)));
  } else {
    console.log(`Waiting for quorum for CA ${fingerprint}:`, Array.from(quorumAcks.get(fingerprint)));
  }
};

// Call this after a new cert is issued
const originalLogIssuedCert = register.logIssuedCert.bind(register);
register.logIssuedCert = async function(args) {
  const entry = originalLogIssuedCert(args);
  const { getLeaf } = require('./merkleUtil');
  const leaf = getLeaf(entry);
  const proof = register.merkleTree.getHexProof(leaf);
  await global.notifyPeersOfNewEntry(entry, proof, register.merkleRoot);
  return entry;
};

// Start server
app.listen(PORT, () => {
  console.log(`HNCA CA server running on port ${PORT}`);
});
