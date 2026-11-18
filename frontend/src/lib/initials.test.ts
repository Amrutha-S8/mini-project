import { test } from "node:test";
import assert from "node:assert/strict";

import { avatarIndex, initials } from "./initials.ts";

test("initials from first and last word", () => {
  assert.equal(initials("Test Owner"), "TO");
  assert.equal(initials("ana maría lópez"), "AL");
  assert.equal(initials("  Single  "), "S");
  assert.equal(initials("Élodie   Ñúñez"), "ÉÑ");
  assert.equal(initials("李小龍"), "李");
  assert.equal(initials("(Guest) Visitor"), "GV");
});

test("empty or symbol-only names fall back to '?'", () => {
  for (const name of ["", "   ", "---", "\u00a0"]) assert.equal(initials(name), "?");
});

test("combining characters stay with their letter", () => {
  assert.equal(initials("e\u0301mile zola"), "ÉZ");
});

test("avatar colour is stable and in range", () => {
  const a = avatarIndex("member:7", 6);
  assert.equal(a, avatarIndex("member:7", 6));
  for (let i = 0; i < 200; i++) {
    const n = avatarIndex(`k${i}`, 6);
    assert.ok(Number.isInteger(n) && n >= 0 && n < 6);
  }
  assert.throws(() => avatarIndex("x", 0), RangeError);
});
