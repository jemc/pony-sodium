
use "ponytest"
use ".."

class CryptoBoxTest is UnitTest
  new iso create() => None
  fun name(): String => "sodium.CryptoBox"
  
  fun apply(h: TestHelper): TestResult? =>
    (let apk, let ask) = CryptoBox.keypair() // Alice's public and secret key
    (let bpk, let bsk) = CryptoBox.keypair() // Bob's   public and secret key
    (let cpk, let csk) = CryptoBox.keypair() // Cyril's public and secret key
    
    h.assert_eq[U64](apk.string().size(), CryptoBox.public_key_size())
    h.assert_eq[U64](ask.string().size(), CryptoBox.secret_key_size())
    
    let nonce = CryptoBox.nonce()
    
    h.assert_eq[U64](nonce.string().size(), CryptoBox.nonce_size())
    
    let crypt = CryptoBox("Hello, Bob!", nonce, bpk, ask)
    
    h.assert_eq[U64](crypt.size(), CryptoBox.mac_size() + "Hello, Bob!".size())
    
    let message = CryptoBox.open(crypt, nonce, apk, bsk)
    h.expect_eq[String](message, "Hello, Bob!")
    
    let nonce' = CryptoBox.nonce()
    let crypt' = CryptoBox("Hi, Alice!", nonce', apk, bsk)
    
    let message' = CryptoBox.open(crypt', nonce', bpk, ask)
    h.expect_eq[String](message', "Hi, Alice!")
    
    try CryptoBox.open(crypt, nonce, apk, csk)
      h.assert_failed("Cyril shouldn't be able to open Alice's message to Bob.")
    end
    
    try CryptoBox.open(crypt', nonce', bpk, csk)
      h.assert_failed("Cyril shouldn't be able to open Bob's message to Alice.")
    end
    
    ///
    // Scalar multiplication (Diffie-Hellman) tests
    
    h.assert_eq[U64](CryptoBox.scalar_size(), CryptoBox.public_key_size())
    h.assert_eq[U64](CryptoBox.scalar_size(), CryptoBox.secret_key_size())
    
    if not (apk.string() == CryptoBox.scalar_mult_base(ask).string()) then
      h.assert_failed("Alice's public key should be derivable from her secret key.")
    end
    
    if not (bpk.string() == CryptoBox.scalar_mult_base(bsk).string()) then
      h.assert_failed("Bob's public key should be derivable from his secret key.")
    end
    
    if not (CryptoBox.scalar_mult(apk, bsk).string()
         == CryptoBox.scalar_mult(bpk, ask).string()) then
      h.assert_failed("Alice and Bob's keys should be able to derive a shared secret.")
    end
    
    true
