// Certificate utility for HNCA
// Handles keypair generation, certificate creation, and signing

const forge = require('node-forge');

/**
 * Generate a keypair (RSA 2048)
 */
function generateKeyPair() {
  return forge.pki.rsa.generateKeyPair(2048);
}

/**
 * Create a self-signed root CA certificate
 */

function randomSerialHex(bytes = 16) {
  return forge.util.bytesToHex(forge.random.getBytesSync(bytes));
}

function createRootCACert({ commonName, organization, country }) {
  const keys = generateKeyPair();
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = randomSerialHex();
  cert.validity.notBefore = new Date();
  cert.validity.notAfter = new Date();
  cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 10);

  const attrs = [
    { name: 'commonName', value: commonName },
    { name: 'organizationName', value: organization },
    { name: 'countryName', value: country }
  ];
  cert.setSubject(attrs);
  cert.setIssuer(attrs);
  cert.setExtensions([
    { name: 'basicConstraints', cA: true },
    { name: 'keyUsage', keyCertSign: true, cRLSign: true },
    { name: 'subjectKeyIdentifier' }
  ]);
  cert.sign(keys.privateKey, forge.md.sha256.create());
  return { cert, privateKey: keys.privateKey };
}


/**
 * Create an intermediate CA certificate signed by the root CA
 */
function createIntermediateCACert({ commonName, organization, country }, rootCert, rootKey) {
  const keys = generateKeyPair();
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = randomSerialHex();
  cert.validity.notBefore = new Date();
  cert.validity.notAfter = new Date();
  cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 5);

  const attrs = [
    { name: 'commonName', value: commonName },
    { name: 'organizationName', value: organization },
    { name: 'countryName', value: country }
  ];
  cert.setSubject(attrs);
  cert.setIssuer(rootCert.subject.attributes);
  cert.setExtensions([
    { name: 'basicConstraints', cA: true, pathLenConstraint: 0 },
    { name: 'keyUsage', keyCertSign: true, cRLSign: true },
    { name: 'subjectKeyIdentifier' },
    { name: 'authorityKeyIdentifier', keyIdentifier: true }
  ]);
  cert.sign(rootKey, forge.md.sha256.create());
  return { cert, privateKey: keys.privateKey };
}

/**
 * Create an end-entity certificate (user, website, robot) signed by an intermediate CA
 * @param {Object} params - { commonName, organization, country, hncaType, hncaExtensions }
 * @param {Certificate} issuerCert - Intermediate CA cert
 * @param {PrivateKey} issuerKey - Intermediate CA private key
 */
function createEntityCert(params, issuerCert, issuerKey) {
  const asn1 = forge.asn1;
  const {
    commonName,
    organization,
    country,
    hncaType, // ENUM: 0=root, 1=intermediate, 2=user, 3=website, 4=robot
    registerId, // string (UUID or hash)
    hncaExtensions = {},
    extKeyUsage = null, // { clientAuth: true } or { serverAuth: true }
    subjectAltNames = null // array of DNS names for website certs
  } = params;
  const keys = generateKeyPair();
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = randomSerialHex();
  cert.validity.notBefore = new Date();
  cert.validity.notAfter = new Date();
  cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 2);

  const attrs = [
    { name: 'commonName', value: commonName },
    { name: 'organizationName', value: organization },
    { name: 'countryName', value: country }
  ];
  cert.setSubject(attrs);
  cert.setIssuer(issuerCert.subject.attributes);
  // HNCA-specific extensions
  const hncaExts = [
    {
      id: '1.3.6.1.4.1.99999.1',
      name: 'hnca-type',
      critical: false,
      value: asn1.toDer(
        asn1.create(asn1.Class.UNIVERSAL, asn1.Type.INTEGER, false, hncaType)
      ).getBytes()
    },
    {
      id: '1.3.6.1.4.1.99999.2',
      name: 'register-id',
      critical: false,
      value: asn1.toDer(
        asn1.create(asn1.Class.UNIVERSAL, asn1.Type.UTF8STRING, false, registerId)
      ).getBytes()
    },
    ...Object.entries(hncaExtensions).map(([k, v], i) => ({
      id: `1.3.6.1.4.1.99999.${i+3}`,
      name: k,
      critical: false,
      value: asn1.toDer(
        asn1.create(asn1.Class.UNIVERSAL, asn1.Type.UTF8STRING, false, v)
      ).getBytes()
    }))
  ];
  const extensions = [
    { name: 'basicConstraints', cA: false },
    { name: 'keyUsage', digitalSignature: true, keyEncipherment: true },
    { name: 'subjectKeyIdentifier' },
    { name: 'authorityKeyIdentifier', keyIdentifier: true },
    ...hncaExts
  ];
  if (extKeyUsage) {
    extensions.push({ name: 'extKeyUsage', ...extKeyUsage });
  }
  if (hncaType === 3 && Array.isArray(subjectAltNames) && subjectAltNames.length > 0) {
    // hncaType 3 = website
    extensions.push({
      name: 'subjectAltName',
      altNames: subjectAltNames.map(dns => ({ type: 2, value: dns })) // 2 = DNS
    });
  }
  cert.setExtensions(extensions);
  cert.sign(issuerKey, forge.md.sha256.create());
  return { cert, privateKey: keys.privateKey };
}

module.exports = {
  generateKeyPair,
  createRootCACert,
  createIntermediateCACert,
  createEntityCert
};
