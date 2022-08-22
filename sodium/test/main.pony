
use "pony_test"

actor Main is TestList
  new create(env: Env) => PonyTest(env, this)
  new make() => None
  
  fun tag tests(test: PonyTest) =>
    // Secret-key cryptography (single-key)
    test(CryptoSecretBoxTest) // Authenticated encryption (encrypted messages)
    test(CryptoAuthTest)      // Authentication           (tagged messages)
    
    // Public-key cryptography (keypairs)
    test(CryptoBoxTest)       // Authenticated encryption (encrypted messages)
    test(CryptoSignTest)      // Public-key signatures    (tagged messages)
    
    // Hashing
    test(CryptoHashTest)
