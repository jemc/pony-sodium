
use "ponytest"
use ".."

class CryptoBoxTest is UnitTest
  new iso create() => None
  fun name(): String => "sodium.CryptoBox"
  
  fun apply(h: TestHelper): TestResult? =>
    (let apk, let ask) = CryptoBox.keypair() // Alice's public and secret key
    (let bpk, let bsk) = CryptoBox.keypair() // Bob's   public and secret key
    (let cpk, let csk) = CryptoBox.keypair() // Cyril's public and secret key
    
    let nonce = CryptoBox.nonce()
    let crypt = CryptoBox("Hello, Bob!", nonce, bpk, ask)
    
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
    
    true
