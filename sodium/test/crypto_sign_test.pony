
use "ponytest"
use ".."
use "../../../pony-zmq/zmq/inspect"

class CryptoSignTest is UnitTest
  new iso create() => None
  fun name(): String => "sodium.CryptoSign"
  
  fun apply(h: TestHelper): TestResult? =>
    (let sk, let pk) = CryptoSign.keypair()
    
    h.assert_eq[U64](sk.string().size(), CryptoSign.secret_key_size())
    h.assert_eq[U64](pk.string().size(), CryptoSign.public_key_size())
    
    ///
    // Attached mode
    
    let signed = CryptoSign("My message!", sk)
    
    h.assert_eq[U64](signed.size(), CryptoSign.mac_size() + "My message!".size())
    
    CryptoSign.open(signed, pk)
    
    let forged = CryptoSign.random_bytes(CryptoSign.mac_size())
               + "My message!"
    try CryptoSign.open(forged, pk)
      h.assert_failed("Shouldn't verify if given a forged signed message.")
    end
    
    let lifted = signed.substring(0, (CryptoSign.mac_size().i64() - 1))
               + "Bad message"
    try CryptoSign.open(lifted, pk)
      h.assert_failed("Shouldn't verify if given a lifted-signature message.")
    end
    
    try CryptoSign.open(signed, CryptoSign.keypair()._2)
      h.assert_failed("Shouldn't verify if given the wrong key.")
    end
    
    ///
    // Detached mode
    
    let mac = CryptoSign.detached("My message!", sk)
    
    h.assert_eq[U64](mac.string().size(), CryptoSign.mac_size())
    
    CryptoSign.verify_detached("My message!", pk, mac)
    
    try CryptoSign.verify_detached("Bad message", pk, mac)
      h.assert_failed("Shouldn't verify if given the wrong message.")
    end
    
    let mac' = CryptoSign.detached("Bad message", sk)
    try CryptoSign.verify_detached("My message!", pk, mac')
      h.assert_failed("Shouldn't verify if given the wrong mac tag.")
    end
    
    try CryptoSign.verify_detached("My message!", CryptoSign.keypair()._2, mac)
      h.assert_failed("Shouldn't verify if given the wrong key.")
    end
    
    true
