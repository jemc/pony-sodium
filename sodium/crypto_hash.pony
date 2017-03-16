
use "lib:sodium"

primitive CryptoHash
  fun tag sha256_size(): USize => @crypto_hash_sha256_bytes[USize]().usize()
  fun tag sha512_size(): USize => @crypto_hash_sha512_bytes[USize]().usize()
  
  fun tag _make_buffer(size: USize): String iso^ =>
    recover String.from_cpointer(
      @pony_alloc[Pointer[U8]](@pony_ctx[Pointer[None] iso](), size), size
    ) end
  
  fun tag sha256(m: String): String =>
    let buf = _make_buffer(sha256_size())
    @crypto_hash_sha256[_Int](
      buf.cpointer(), m.cpointer(), m.size()
    )
    consume buf
  
  fun tag sha512(m: String): String =>
    let buf = _make_buffer(sha512_size())
    @crypto_hash_sha512[_Int](
      buf.cpointer(), m.cpointer(), m.size()
    )
    consume buf
