
use "lib:sodium"

primitive CryptoHash
  fun tag sha256_size(): USize => @crypto_hash_sha256_bytes[USize]().usize()
  fun tag sha512_size(): USize => @crypto_hash_sha512_bytes[USize]().usize()
  
  fun tag _make_buffer(size: USize): String iso^ =>
    recover String.from_cstring(@pony_alloc[Pointer[U8]](size), size) end
  
  fun tag sha256(m: String): String =>
    let buf = _make_buffer(sha256_size())
    @crypto_hash_sha256[_Int](
      buf.cstring(), m.cstring(), m.size()
    )
    consume buf
  
  fun tag sha512(m: String): String =>
    let buf = _make_buffer(sha512_size())
    @crypto_hash_sha512[_Int](
      buf.cstring(), m.cstring(), m.size()
    )
    consume buf
