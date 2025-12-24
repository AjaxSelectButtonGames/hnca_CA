// HNCA Certificate Authority Server Skeleton
// Entry point for the Node.js CA server


const express = require('express');
const Register = require('./register');
const certUtil = require('./certUtil');
const forge = require('node-forge');
const app = express();
const PORT = process.env.PORT || 3000;

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

// Start server
app.listen(PORT, () => {
  console.log(`HNCA CA server running on port ${PORT}`);
});
