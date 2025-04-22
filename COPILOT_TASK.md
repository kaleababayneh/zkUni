## Task for Copilot

* File layout stays:
  constants.nr, gadgets.nr, stable_matching.nr, encrypted_matching.nr
* Add poseidon `commit_inputs()` to constants.nr that hashes:
  - every student pref (5×5)
  - every college pref (5×5)
  - capacities (5)
* In gadgets.nr implement:
  - fn mask(pk_s: Field, pk_c: Field, nonce: Field) -> Field
  - fn encrypt_u32(msg: u32, pk_s: Field, pk_c: Field, nonce: Field)
      returns [Field; 4]  // [cipher, nonce, tag, 0]
* Modify encrypted_matching.nr:
  1. public input `instance_H`
  2. assert hash == instance_H
  3. take witness arrays `nonce_stu[5]`, `nonce_col[15]`
  4. build ciphertext vector of length 20*4, flatten, return
* Replace bitwise & and | with && and || in stable_matching.nr
* Keep all loop bounds constant; no dynamic allocations.
