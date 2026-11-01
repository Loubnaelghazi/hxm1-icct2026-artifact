const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const { parseHxm1 } = require("./hxm1_parser");

const vectorDir = path.join(__dirname, "test_vectors");
const vectors = JSON.parse(fs.readFileSync(path.join(vectorDir, "vectors.json"), "utf8"));

for (const [mode, vector] of Object.entries(vectors.modes)) {
  const original = fs.readFileSync(path.join(vectorDir, vector.package_file));

  test(`${mode}: valid vector retains exact metadata and hash`, () => {
    assert.deepEqual(parseHxm1(original), {
      ...vector.package_info,
      sha256: vector.package_sha256,
    });
  });

  test(`${mode}: reject high-bit aliases in every magic byte`, () => {
    for (let offset = 0; offset < 4; offset++) {
      const mutant = Buffer.from(original);
      mutant[offset] |= 0x80;
      assert.throws(() => parseHxm1(mutant), /^Error: bad magic$/);
    }
  });

  test(`${mode}: reject invalid magic and malformed framing`, () => {
    const badMagic = Buffer.from(original);
    badMagic[0] = 0;
    assert.throws(() => parseHxm1(badMagic), /^Error: bad magic$/);
    assert.throws(() => parseHxm1(original.subarray(0, 14)), /truncated HXM1 package/);
    assert.throws(() => parseHxm1(original.subarray(0, -1)), /length mismatch/);
    assert.throws(() => parseHxm1(Buffer.concat([original, Buffer.from([0])])), /length mismatch/);
  });
}
