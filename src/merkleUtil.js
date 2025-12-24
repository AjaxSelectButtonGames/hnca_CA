// Merkle utility for HNCA
// Provides functions to build Merkle trees and generate proofs for federation

const { MerkleTree } = require('merkletreejs');
const keccak256 = require('keccak256');

function buildMerkleTree(entries) {
  // entries: array of cert log entries (objects)
  // Hash each entry as a string
  const leaves = entries.map(e => keccak256(JSON.stringify(e)));
  return new MerkleTree(leaves, keccak256, { sortPairs: true });
}

function getLeaf(entry) {
  return keccak256(JSON.stringify(entry));
}

module.exports = {
  buildMerkleTree,
  getLeaf
};
