
use "ponytest"
use ".."

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
    
    ///
    // Convert to CryptoBox (curve) keys and use with normal CryptoBox keys
    
    (let ask, let apk) = (sk.to_curve(), pk.to_curve())
    (let bsk, let bpk) = CryptoBox.keypair()
    
    h.assert_eq[U64](ask.string().size(), CryptoBox.secret_key_size())
    h.assert_eq[U64](apk.string().size(), CryptoBox.public_key_size())
    
    let nonce = CryptoBox.nonce()
    let crypt = CryptoBox("Hello, Bob!", nonce, ask, bpk)
    
    let message = CryptoBox.open(crypt, nonce, bsk, apk)
    h.expect_eq[String](message, "Hello, Bob!")
    
    let nonce' = CryptoBox.nonce()
    let crypt' = CryptoBox("Hi, Alice!", nonce', bsk, apk)
    
    let message' = CryptoBox.open(crypt', nonce', ask, bpk)
    h.expect_eq[String](message', "Hi, Alice!")
    
    true
