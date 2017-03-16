
use "ponytest"
use ".."
use "debug"

class CryptoSecretBoxTest is UnitTest
  new iso create() => None
  fun name(): String => "sodium.CryptoSecretBox"
  
  fun apply(h: TestHelper)? =>
    let key   = CryptoSecretBox.key()
    let nonce = CryptoSecretBox.nonce()
    let crypt = CryptoSecretBox("My secret!", nonce, key)
    
    h.assert_eq[USize](key  .string().size(), CryptoSecretBox.key_size())
    h.assert_eq[USize](nonce.string().size(), CryptoSecretBox.nonce_size())
    h.assert_eq[USize](crypt.string().size(), CryptoSecretBox.mac_size() + "My secret!".size())
    
    let message = CryptoSecretBox.open(crypt, nonce, key)
    h.assert_eq[String](message, "My secret!")
    
    try CryptoSecretBox.open(crypt, CryptoSecretBox.nonce(), key)
      h.fail("Shouldn't be able to open with the wrong nonce.")
    end
    
    try CryptoSecretBox.open(crypt, nonce, CryptoSecretBox.key())
      h.fail("Shouldn't be able to open with the wrong key.")
    end
