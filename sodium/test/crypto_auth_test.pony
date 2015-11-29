
use "ponytest"
use ".."

class CryptoAuthTest is UnitTest
  new iso create() => None
  fun name(): String => "sodium.CryptoAuth"
  
  fun apply(h: TestHelper): TestResult? =>
    let key = CryptoAuth.key()
    let mac = CryptoAuth("My message!", key)
    
    h.assert_eq[USize](key.string().size(), CryptoAuth.key_size())
    h.assert_eq[USize](mac.string().size(), CryptoAuth.mac_size())
    
    CryptoAuth.verify("My message!", key, mac)
    
    try CryptoAuth.verify("Bad message", key, mac)
      h.assert_failed("Shouldn't verify if given the wrong message.")
    end
    
    let mac' = CryptoAuth("Bad message", key)
    try CryptoAuth.verify("My message!", key, mac')
      h.assert_failed("Shouldn't verify if given the wrong mac tag.")
    end
    
    try CryptoAuth.verify("My message!", CryptoAuth.key(), mac)
      h.assert_failed("Shouldn't verify if given the wrong key.")
    end
    
    true
