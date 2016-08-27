
use "ponytest"
use ".."

class CryptoSignTest is UnitTest
  new iso create() => None
  fun name(): String => "sodium.CryptoSign"
  
  fun apply(h: TestHelper)? =>
    (let sk, let pk) = CryptoSign.keypair()
    
    h.assert_eq[USize](sk.string().size(), CryptoSign.secret_key_size())
    h.assert_eq[USize](pk.string().size(), CryptoSign.public_key_size())
    
    ///
    // Attached mode
    
    let signed = CryptoSign("My message!", sk)
    
    h.assert_eq[USize](signed.size(), CryptoSign.mac_size() + "My message!".size())
    
    CryptoSign.open(signed, pk)
    
    let forged = CryptoSign.random_bytes(CryptoSign.mac_size())
               + "My message!"
    try CryptoSign.open(forged, pk)
      h.fail("Shouldn't verify if given a forged signed message.")
    end
    
    let lifted = signed.substring(0, (CryptoSign.mac_size().isize() - 1))
               + "Bad message"
    try CryptoSign.open(lifted, pk)
      h.fail("Shouldn't verify if given a lifted-signature message.")
    end
    
    try CryptoSign.open(signed, CryptoSign.keypair()._2)
      h.fail("Shouldn't verify if given the wrong key.")
    end
    
    ///
    // Detached mode
    
    let mac = CryptoSign.detached("My message!", sk)
    
    h.assert_eq[USize](mac.string().size(), CryptoSign.mac_size())
    
    CryptoSign.verify_detached("My message!", pk, mac)
    
    try CryptoSign.verify_detached("Bad message", pk, mac)
      h.fail("Shouldn't verify if given the wrong message.")
    end
    
    let mac' = CryptoSign.detached("Bad message", sk)
    try CryptoSign.verify_detached("My message!", pk, mac')
      h.fail("Shouldn't verify if given the wrong mac tag.")
    end
    
    try CryptoSign.verify_detached("My message!", CryptoSign.keypair()._2, mac)
      h.fail("Shouldn't verify if given the wrong key.")
    end

    ///
    // Key pairs generated with seeds

    (let sks, let pks) = CryptoSign.seed_keypair(CryptoSignSeed("Hello seeds!"))

    h.assert_eq[USize](sks.string().size(), CryptoSign.secret_key_size())
    h.assert_eq[USize](pks.string().size(), CryptoSign.public_key_size())

    (let sks', let pks') = CryptoSign.seed_keypair(CryptoSignSeed("Hello seeds!"))

    h.assert_eq[String](sks.string(), sks'.string())
    h.assert_eq[String](pks.string(), pks'.string())

    (let sksb, let pksb) = CryptoSign.seed_keypair(CryptoSignSeed("Hello world!"))

    h.assert_ne[String](sks.string(), sksb.string())
    h.assert_ne[String](pks.string(), pksb.string())

    ///
    // Convert to CryptoBox (curve) keys and use with normal CryptoBox keys
    
    (let ask, let apk) = (sk.to_curve(), pk.to_curve())
    (let bsk, let bpk) = CryptoBox.keypair()
    
    h.assert_eq[USize](ask.string().size(), CryptoBox.secret_key_size())
    h.assert_eq[USize](apk.string().size(), CryptoBox.public_key_size())
    
    let nonce = CryptoBox.nonce()
    let crypt = CryptoBox("Hello, Bob!", nonce, ask, bpk)
    
    let message = CryptoBox.open(crypt, nonce, bsk, apk)
    h.assert_eq[String](message, "Hello, Bob!")
    
    let nonce' = CryptoBox.nonce()
    let crypt' = CryptoBox("Hi, Alice!", nonce', bsk, apk)
    
    let message' = CryptoBox.open(crypt', nonce', ask, bpk)
    h.assert_eq[String](message', "Hi, Alice!")
