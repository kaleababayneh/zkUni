//! Noir `std` lib is [constistent] to *assume that the points are on the curve* when fed as an argument. The assumtion is adopted in this lib. \
//! [constistent]: couple of relevant links are <noir_stdlib/src/embedded_curve_ops.nr> and <https://github.com/noir-lang/noir/pull/4368>

/* The workaround is present here which prevented to use `EmbeddedCurvePoint` methods and go with `_array_` flavour functions. I left them qualified in the code, so they can be easily 
corrected back when the bug is fixed. */

use std::embedded_curve_ops::{EmbeddedCurvePoint, EmbeddedCurveScalar, fixed_base_scalar_mul, multi_scalar_mul};

global MSG_PANIC: str<41> = "we're in a subgroup smaller than intended";

/// Cipher-text. `BITS_DL` limits the bit-length of the plain-text when deciphering. \
/// Depending on your use-case you might want to provide `BITS_DL` when transfer or storing a ciphertext. (Often a system would be just parameterized so we save here one property.)
pub struct ElGamalCiphered<let BITS_DL: u32> { 
    /// ephemeral public key
    c1: EmbeddedCurvePoint,
    /// the message part of the ciphertext
    c2: EmbeddedCurvePoint,
}

impl<let BITS_DL: u32> std::ops::Add for ElGamalCiphered<BITS_DL> {
    /// Depending on your use-case you should choose `BITS_DL` size to accomodate 
    /// the sum of all the plain-texts that will be added. 
    /// Also you should convert both cipher-texts to the same `BITS_DL` before addition. 
    /// (It's more efficient than generilize this method for different lengths, most probably you would want to work with a specific one.)
    fn add(self, rhs: Self) -> Self {
        let c1 = std::embedded_curve_ops::embedded_curve_add_array_return(self.c1, rhs.c1);
        let c2 = std::embedded_curve_ops::embedded_curve_add_array_return(self.c2, rhs.c2);

        Self{
            c1: EmbeddedCurvePoint { x: c1[0], y: c1[1], is_infinite: c1[2] as bool }, 
            c2: EmbeddedCurvePoint { x: c2[0], y: c2[1], is_infinite: c2[2] as bool },
        }
    }
}

impl<let BITS_DL: u32> ElGamalCiphered<BITS_DL> {
    /// Exponential ElGamal Encryption on the curve embedded to the backend. Plaintext is constrained to `BITS_DL` bit-length; as the last step of decryption requires solving 
    /// the Discrete Logarithm Problem.
    /// The randomness should be sampled uniformly from the scalar field and NEVER reused. 
    pub fn new(public_key: EmbeddedCurvePoint, plaintext: Field, randomness: EmbeddedCurveScalar) -> Self {
        plaintext.assert_max_bit_size::<BITS_DL>();
        //   let c2 = shared_secret.add(plain_embedded);
        let c2 = std::embedded_curve_ops::embedded_curve_add_array_return(
            multi_scalar_mul([public_key], [randomness]), 
            fixed_base_scalar_mul(EmbeddedCurveScalar::from_field(plaintext))
        );
        // TODO should it be asserted `c2` isn't identity as an attack indicator?
        ElGamalCiphered{
            c1: fixed_base_scalar_mul(randomness), 
            c2: EmbeddedCurvePoint { 
                x: c2[0], y: c2[1], is_infinite: c2[2] as bool
            },
        }
    }

    /// Returns the point corresponding to the plain-text and the bit-length of the plain-text for grinding. This method is useful if you have an
    /// oracle which grind the scalar from it.
    /// Reminder
    /// =======
    /// After getting the scalar don't forget to constraint it with `assert_dl`.
    pub fn decrypt_to_point(self, private_key: EmbeddedCurveScalar) -> (EmbeddedCurvePoint, u32) {
        let shared_secret = 
            multi_scalar_mul([self.c1], [private_key]);
        //   let plain_embedded = ciphertext.1.sub(shared_secret);
            let plain_embedded = 
                std::embedded_curve_ops::embedded_curve_add_array_return(self.c2, shared_secret.neg());
        //   plain_embedded // give this embedded plaintext as input to the Baby-Step Giant-Step algorithm to get back the original plaintext
        (EmbeddedCurvePoint { x: plain_embedded[0], y: plain_embedded[1], is_infinite: plain_embedded[2] as bool }, BITS_DL)
    }

    pub fn decrypt_to_scalar(self, private_key: EmbeddedCurveScalar) -> u64 {
        let (plain_embedded, _) = self.decrypt_to_point(private_key);
        let plain = unsafe {baby_giant_unconstrained::<BITS_DL>(plain_embedded)};
        assert_dl(plain as Field, plain_embedded);
        plain
    }

    /// It'd be ok to constrain bit-length to `u8`; it's `u32` only for compatibility with `Field` methods used.
    pub fn bit_length(self) -> u32 {BITS_DL}
    /// Utility to change accomodated plain-text bit-length.
    pub fn convert<let BITS_DL_NEW: u32>(self) -> ElGamalCiphered<BITS_DL_NEW> {ElGamalCiphered::<BITS_DL_NEW>{c1: self.c1, c2: self.c2}}
}

/// It's possible that instead `decrypt_to_scalar` you'd want to use `decrypt_to_point` and get the scalar via an oracle; then constrain the result with this function.
pub fn assert_dl(plain: Field, plain_embedded: EmbeddedCurvePoint) {
    assert(fixed_base_scalar_mul(EmbeddedCurveScalar::from_field(plain)) == plain_embedded, "false plain-text");
}

/// Solve DL between the given point and the curve generator. \
/// (If `EmbeddedCurvePoint` is planned to get `Hash` trait - I'd be happy to adapt this to `HashMap` approach which seems to be more efficient.)
pub unconstrained fn baby_giant_unconstrained<let BITS_DL: u32>(plain_embedded: EmbeddedCurvePoint) -> u64 {
    let mut (result, success) = (0, false);

    let l = 1 << (BITS_DL / 2 + BITS_DL % 2) as u8;

    // `embedded_curve_ops` doesn't provide a dedicated method to get the generator currently
    let g = fixed_base_scalar_mul(EmbeddedCurveScalar::from_field(1));
    
    let mut steps_baby = Vec::new();
    let mut steps_giant = Vec::new();

    let identity = EmbeddedCurvePoint::point_at_infinity();
    steps_baby.push(identity);

    println("baby-steps table loop starting");
    let mut runner = g;
    steps_baby.push(runner);
    for _ in 1..=l {
        runner = runner.add(g);
        assert(runner != g, MSG_PANIC);
        steps_baby.push(runner);
    }
    println("baby-steps table loop finished");

    let multiplicator = multi_scalar_mul(
        [g.neg()], [EmbeddedCurveScalar::from_field(l as Field)]
    );
    let mut runner = plain_embedded;
    steps_giant.push(runner);
    println("giant-steps table loop starting");
    for _ in 1..=l {
        runner = runner.add(multiplicator);
        assert(runner != g, MSG_PANIC);
        steps_giant.push(runner);
    }
    println("giant-steps table loop finished");

    for i_baby in 0..l {
        for i_giant in 0..l {
            if steps_baby.get(i_baby) == steps_giant.get(i_giant) {
                result = i_baby as u64 + i_giant as u64 * l as u64;
                success = true;
                break;
            }
        }
        if success {break;}
    }

    assert(success, " ");
    result
}

#[test] 
fn test_main_20() {
  let message = 1028430; // 20-bit
  let private_key: Field = 0x04c330a81537c0d29cc09e8b2b9c43fc5fb5a9d244ab741fc88dff3d40dbd75c; // chosen randomly between 0 and bjj_l-1
  
  let randomness: Field = 0x010fe5884a7852054a21e21e549520352f563f03d3f79e66a2d75fbd2a21d5cf; // chosen randomly between 0 and bjj_l-1, and never reused

  let private_key = EmbeddedCurveScalar::from_field(private_key);
  let public_key = fixed_base_scalar_mul(private_key);
  println(public_key);
  let ciphertext = ElGamalCiphered::<20>::new(public_key, message as Field, EmbeddedCurveScalar::from_field(randomness));
//   let decryption = decrypt_to_point(private_key, ciphertext); // in embedded form (before the baby-step giant-step application)

//   let bjj_affine: AffineCurve = get_affine_curve();
//   let base_pt: Gaffine = get_base_point();
//   let plain_embedded: Gaffine = bjj_affine.mul(message as Field,base_pt);

//   assert(plain_embedded.x == decryption.x);
//   assert(plain_embedded.y == decryption.y);

    assert(message == ciphertext.decrypt_to_scalar(private_key) as Field);
    println(ciphertext.decrypt_to_scalar(private_key));
    // assert_scalar(message, decrypt_to_point(private_key, ciphertext));
}

// #[test]
// fn test_main_1() {
//   let key_priv = EmbeddedCurveScalar::from_field(7115637666404682632379307215493662218327241124760828634863089038725962038957);
//   let key_pub = fixed_base_scalar_mul(key_priv);
  
//   let msg1 = 1111;
//   let msg2 = 2222;

//   // ~~TODO~~ It only works if the 2 randomnessess together aren't too big it seems.
//   let randomness1 = EmbeddedCurveScalar::from_field(18781456255357152124930966365016094019362299655621530163902908874136078409517);
//   // doesn't work
//   let randomness2 = EmbeddedCurveScalar::from_field(16691817043247903474315859400317678937424095611113194787133324833622392219635);
//   // works...
// //   let randomness2 = EmbeddedCurveScalar::from_field(1234);

//   let combined_msg = msg1+msg2;
// //   let combined_randomness = randomness1 + randomness2;
//   let combined_ciphered = ElGamalCiphered::<13>::new(key_pub, msg1, randomness1) + ElGamalCiphered::<13>::new(key_pub, msg2, randomness2);

//   assert(combined_msg == combined_ciphered.decrypt_to_scalar(key_priv) as Field);
// }

// #[test]
// fn example() {
//     let (bytes, offset) = ([2; 64], 5);
//     let key_private = EmbeddedCurveScalar::from_field(6);
//     let key_public = fixed_base_scalar_mul(key_private);
//     let message = 777;
//     let randomness = EmbeddedCurveScalar::from_bytes(bytes, offset);
//     let ciphertext_another = 
//         ElGamalCiphered::<16>::new(key_public, 333, EmbeddedCurveScalar::from_field(9));

//     // Encrypt a 16-bits length message using recipient's public key.
//     let ciphertext = 
//         ElGamalCiphered::<16>::new(key_public, message, randomness);

//     // Get the sum of the ciphertexts.
//     let ciphertext_combined = ciphertext + ciphertext_another;

//     // Decrypt the cipher-text. The result will be the sum of the plain-texts.
//     let decrypted = ciphertext_combined.decrypt_to_scalar(key_private);

//     assert(decrypted as Field == message + 333);

//     assert(16 as u32 == ciphertext_combined.bit_length());
// }
