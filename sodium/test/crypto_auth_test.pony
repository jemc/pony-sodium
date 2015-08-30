
use "ponytest"
use ".."

class CryptoAuthTest is UnitTest
  new iso create() => None
  fun name(): String => "sodium.CryptoAuth"
  
  fun apply(h: TestHelper): TestResult? =>
    let key = CryptoAuth.key()
    let mac = CryptoAuth("My message!", key)
    
    CryptoAuth.verify("My message!", key, mac)
    
    try CryptoAuth.verify("Some other message!", key, mac)
      h.assert_failed("Shouldn't verify if given the wrong message.")
    end
    
    let mac' = CryptoAuth("Some other message!", key)
    try CryptoAuth.verify("My message!", key, mac')
      h.assert_failed("Shouldn't verify if given the wrong mac tag.")
    end
    
    try CryptoAuth.verify("My message!", CryptoAuth.key(), mac)
      h.assert_failed("Shouldn't verify if given the wrong key.")
    end
    
    true
