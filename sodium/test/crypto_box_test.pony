
use "ponytest"
use ".."

class CryptoBoxTest is UnitTest
  new iso create() => None
  fun name(): String => "sodium.CryptoBox"
  
  fun apply(h: TestHelper)? =>
    (let ask, let apk) = CryptoBox.keypair()? // Alice's public and secret key
    (let bsk, let bpk) = CryptoBox.keypair()? // Bob's   public and secret key
    (let csk, let cpk) = CryptoBox.keypair()? // Cyril's public and secret key
    
    h.assert_eq[USize](ask.string().size(), CryptoBox.secret_key_size())
    h.assert_eq[USize](apk.string().size(), CryptoBox.public_key_size())
    
    let nonce = CryptoBox.nonce()
    
    h.assert_eq[USize](nonce.string().size(), CryptoBox.nonce_size())
    
    let crypt = CryptoBox("Hello, Bob!", nonce, ask, bpk)?
    
    h.assert_eq[USize](crypt.size(), CryptoBox.mac_size() + "Hello, Bob!".size())
    
    let message = CryptoBox.open(crypt, nonce, bsk, apk)?
    h.assert_eq[String](message, "Hello, Bob!")
    
    let nonce' = CryptoBox.nonce()
    let crypt' = CryptoBox("Hi, Alice!", nonce', bsk, apk)?
    
    let message' = CryptoBox.open(crypt', nonce', ask, bpk)?
    h.assert_eq[String](message', "Hi, Alice!")
    
    try CryptoBox.open(crypt, nonce, csk, apk)?
      h.fail("Cyril shouldn't be able to open Alice's message to Bob.")
    end
    
    try CryptoBox.open(crypt', nonce', csk, bpk)?
      h.fail("Cyril shouldn't be able to open Bob's message to Alice.")
    end
    
    ///
    // Key pairs generated with seeds
    
    (let sks, let pks) = CryptoBox.seed_keypair(CryptoBoxSeed("Hello seeds!                    "))?
    
    h.assert_eq[USize](sks.string().size(), CryptoBox.secret_key_size())
    h.assert_eq[USize](pks.string().size(), CryptoBox.public_key_size())
    
    (let sks', let pks') = CryptoBox.seed_keypair(CryptoBoxSeed("Hello seeds!                    "))?
    
    h.assert_eq[String](sks.string(), sks'.string())
    h.assert_eq[String](pks.string(), pks'.string())
    
    (let sksb, let pksb) = CryptoBox.seed_keypair(CryptoBoxSeed("Hello world!                    "))?
    
    h.assert_ne[String](sks.string(), sksb.string())
    h.assert_ne[String](pks.string(), pksb.string())
    
    ///
    // Scalar multiplication (Diffie-Hellman) tests
    
    h.assert_eq[USize](CryptoBox.scalar_size(), CryptoBox.secret_key_size())
    h.assert_eq[USize](CryptoBox.scalar_size(), CryptoBox.public_key_size())
    
    if not (apk.string() == CryptoBox.scalar_mult_base(ask)?.string()) then
      h.fail("Alice's public key should be derivable from her secret key.")
    end
    
    if not (bpk.string() == CryptoBox.scalar_mult_base(bsk)?.string()) then
      h.fail("Bob's public key should be derivable from his secret key.")
    end
    
    if not (CryptoBox.scalar_mult(bsk, apk)?.string()
         == CryptoBox.scalar_mult(ask, bpk)?.string()) then
      h.fail("Alice and Bob's keys should be able to derive a shared secret.")
    end
