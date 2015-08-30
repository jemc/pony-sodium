
use "lib:sodium"

primitive CryptoHash
  fun tag sha256_size(): U64 => @crypto_hash_sha256_bytes[_SizeT]().u64()
  fun tag sha512_size(): U64 => @crypto_hash_sha512_bytes[_SizeT]().u64()
  
  fun tag _make_buffer(size: U64): String iso^ =>
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
