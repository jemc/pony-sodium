
use "ponytest"
use ".."

class CryptoHashTest is UnitTest
  new iso create() => None
  fun name(): String => "sodium.CryptoHash"
  
  fun apply(h: TestHelper) =>
    let message = "My message to be hashed by the hashing function."
    
    let sha256_hash = CryptoHash.sha256(message)
    
    h.assert_eq[USize](sha256_hash.size(), CryptoHash.sha256_size())
    
    h.assert_eq[String](sha256_hash, CryptoHash.sha256(message),
      "Should have been a deterministic SHA-256 hash.")
    
    let sha512_hash = CryptoHash.sha512(message)
    
    h.assert_eq[USize](sha512_hash.size(), CryptoHash.sha512_size())
    
    h.assert_eq[String](sha512_hash, CryptoHash.sha512(message),
      "Should have been a deterministic SHA-512 hash.")
