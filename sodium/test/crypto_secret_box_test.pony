
use "ponytest"
use ".."

class CryptoSecretBoxTest is UnitTest
  new iso create() => None
  fun name(): String => "sodium.CryptoSecretBox"
  
  fun apply(h: TestHelper): TestResult? =>
    let key   = CryptoSecretBox.key()
    let nonce = CryptoSecretBox.nonce()
    let crypt = CryptoSecretBox("My secret!", nonce, key)
    
    let message = CryptoSecretBox.open(crypt, nonce, key)
    h.expect_eq[String](message, "My secret!")
    
    try CryptoSecretBox.open(crypt, CryptoSecretBox.nonce(), key)
      h.assert_failed("Shouldn't be able to open with the wrong nonce.")
    end
    
    try CryptoSecretBox.open(crypt, nonce, CryptoSecretBox.key())
      h.assert_failed("Shouldn't be able to open with the wrong key.")
    end
    
    true
