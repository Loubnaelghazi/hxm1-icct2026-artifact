const fs = require("fs");
const crypto = require("crypto");

const MODES = {
  1: "RSA-KEM+HKDF-SHA256+AES-256-GCM",
  2: "ML-KEM-768+HKDF-SHA256+AES-256-GCM",
  3: "RSA-KEM+ML-KEM-768+HKDF-SHA256+AES-256-GCM",
};

function parseHxm1(buffer) {
  if (buffer.length < 15) throw new Error("truncated HXM1 package");
  const magic = buffer.subarray(0, 4);
  const version = buffer.readUInt8(4);
  const modeId = buffer.readUInt8(5);
  const cRsaLen = buffer.readUInt16BE(6);
  const cMlkemLen = buffer.readUInt16BE(8);
  const nonceLen = buffer.readUInt8(10);
  const ciphertextLen = buffer.readUInt32BE(11);

  if (!magic.equals(Buffer.from("HXM1", "ascii"))) throw new Error("bad magic");
  if (version !== 1) throw new Error("unsupported version");
  if (!MODES[modeId]) throw new Error("unsupported mode");

  let offset = 15;
  const cRsa = buffer.subarray(offset, offset + cRsaLen);
  offset += cRsaLen;
  const cMlkem = buffer.subarray(offset, offset + cMlkemLen);
  offset += cMlkemLen;
  const nonce = buffer.subarray(offset, offset + nonceLen);
  offset += nonceLen;
  const ciphertext = buffer.subarray(offset, offset + ciphertextLen);
  offset += ciphertextLen;

  if (offset !== buffer.length) throw new Error("length mismatch");
  if (nonceLen !== 12) throw new Error("unexpected AES-GCM nonce length");
  if (ciphertextLen < 16) throw new Error("ciphertext shorter than GCM tag");
  if (modeId === 1 && (cRsaLen !== 384 || cMlkemLen !== 0)) throw new Error("invalid RSA profile lengths");
  if (modeId === 2 && (cRsaLen !== 0 || cMlkemLen !== 1088)) throw new Error("invalid ML-KEM profile lengths");
  if (modeId === 3 && (cRsaLen !== 384 || cMlkemLen !== 1088)) throw new Error("invalid hybrid profile lengths");

  return {
    format: "HXM1 binary v1",
    version,
    mode_id: modeId,
    mode: MODES[modeId],
    c_rsa_bytes: cRsa.length,
    c_mlkem_bytes: cMlkem.length,
    nonce_bytes: nonce.length,
    ciphertext_and_tag_bytes: ciphertext.length,
    total_bytes: buffer.length,
    sha256: crypto.createHash("sha256").update(buffer).digest("hex"),
  };
}

function main() {
  const paths = process.argv.slice(2);
  if (paths.length === 0) {
    console.error("usage: node hxm1_parser.js <file.hxm1> [...]");
    process.exit(2);
  }
  for (const path of paths) {
    const info = parseHxm1(fs.readFileSync(path));
    console.log(JSON.stringify({ file: path, ...info }, null, 2));
  }
}

if (require.main === module) main();

module.exports = { parseHxm1 };
