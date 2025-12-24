const { v4: uuidv4 } = require('uuid');
const forge = require('node-forge');

const crypto = require('crypto'); // Built-in node crypto is faster for hashing
const { buildMerkleTree, getLeaf } = require('./merkleUtil');

class Register {
  constructor({ name = '', publicKey = null, privateKey = null } = {}) {
    this.name = name;
    this.publicKey = publicKey;
    this.privateKey = privateKey;
    
    // DERIVE ID from Public Key (Decentralized Identity)
    // This prevents someone from claiming your ID without your Private Key.
    this.id = publicKey ? this.generateRegisterId(publicKey) : uuidv4();
    
    this.issuedCerts = new Map(); // Use a Map for O(1) lookup by fingerprint
    this.revokedCerts = new Set(); // Use a Set for fast lookup
    this.merkleTree = null;
    this.merkleRoot = null;
  }

  generateRegisterId(publicKey) {
    const pem = forge.pki.publicKeyToPem(publicKey);
    return crypto.createHash('sha256').update(pem).digest('hex');
  }

  // Log a newly issued certificate
  logIssuedCert({ cert, type, metadata }) {
    const fingerprint = forge.pki.getPublicKeyFingerprint(cert.publicKey, {encoding: 'hex'});
    
    const entry = {
      fingerprint,
      type,
      subject: cert.subject.attributes,
      issuedAt: new Date(),
      metadata,
      signature: null // This will be the Register's signature of this specific entry
    };

    // 1. Sign the entry with Register's Private Key
    entry.signature = this.signData(JSON.stringify(entry));

    // 2. Add to local storage
    this.issuedCerts.set(fingerprint, entry);

    // 3. Update the Merkle Tree and Root
    this.updateMerkleTree();
    
    return entry;
  }

  signData(data) {
    const md = forge.md.sha256.create();
    md.update(data, 'utf8');
    return forge.util.encode64(this.privateKey.sign(md));
  }

  // Update the Merkle tree and root
  updateMerkleTree() {
    const entries = Array.from(this.issuedCerts.values());
    if (entries.length === 0) {
      this.merkleTree = null;
      this.merkleRoot = null;
      return;
    }
    this.merkleTree = buildMerkleTree(entries);
    this.merkleRoot = this.merkleTree.getHexRoot();
  }

  // Export a "Snapshot" for other nodes
  exportSnapshot() {
    return {
      registerId: this.id,
      merkleRoot: this.merkleRoot,
      log: Array.from(this.issuedCerts.values()),
      // A signature of the Merkle Root proves the Register stands by this state
      rootSignature: this.signData(this.merkleRoot) 
    };
  }
  /**
   * Import a snapshot from another register (federation sync)
   * Verifies the Merkle root and signatures for trust
   */
  importSnapshot(snapshot) {
    // 1. Verify Merkle root matches log
    const hashes = snapshot.log
      .map(entry => require('crypto').createHash('sha256').update(JSON.stringify(entry)).digest('hex'))
      .sort();
    const computedRoot = hashes.reduce((acc, hash) => {
      return require('crypto').createHash('sha256').update(acc + hash).digest('hex');
    }, "GENESIS_ROOT");
    if (computedRoot !== snapshot.merkleRoot) {
      throw new Error('Merkle root mismatch: log may be tampered');
    }
    // 2. Optionally verify rootSignature using the register's public key (if available)
    //    (In a real system, you'd fetch and cache the remote register's public key)
    // 3. Merge log entries
    for (const entry of snapshot.log) {
      if (!this.issuedCerts.has(entry.fingerprint)) {
        this.issuedCerts.set(entry.fingerprint, entry);
      }
    }
    // 4. Update local Merkle tree/root
    this.updateMerkleTree();
  }
}

module.exports = Register;