
use "lib:sodium"

class val CryptoAuthKey
  let _inner: String
  fun string(): String => _inner
  fun cpointer(): Pointer[U8] tag => _inner.cpointer()
  fun is_valid(): Bool => _inner.size() == CryptoAuth.key_size()
  new val create(buf: (ReadSeq[U8] iso | ReadSeq[U8] val)) =>
    _inner = recover String.>append(consume buf) end

class val CryptoAuthMac
  let _inner: String
  fun string(): String => _inner
  fun cpointer(): Pointer[U8] tag => _inner.cpointer()
  fun is_valid(): Bool => _inner.size() == CryptoAuth.mac_size()
  new val create(buf: (ReadSeq[U8] iso | ReadSeq[U8] val)) =>
    _inner = recover String.>append(consume buf) end

primitive CryptoAuth
  fun tag key_size(): USize => @crypto_auth_keybytes[USize]().usize()
  fun tag mac_size(): USize => @crypto_auth_bytes[USize]().usize()
  
  fun tag _make_buffer(size: USize): String iso^ =>
    recover String.from_cpointer(
      @pony_alloc[Pointer[U8]](@pony_ctx[Pointer[None] iso](), size), size
    ) end
  
  fun tag random_bytes(size: USize): String iso^ =>
    let buf = _make_buffer(size)
    @randombytes_buf[None](buf.cpointer(), size)
    buf
  
  fun tag key(): CryptoAuthKey =>
    CryptoAuthKey(random_bytes(key_size()))
  
  fun tag apply(m: String, k: CryptoAuthKey): CryptoAuthMac? =>
    if not k.is_valid() then error end
    let buf = _make_buffer(mac_size())
    if 0 != @crypto_auth[_Int](
      buf.cpointer(), m.cpointer(), m.size(), k.cpointer()
    ) then error end
    CryptoAuthMac(consume buf)
  
  fun tag verify(m: String, k: CryptoAuthKey, t: CryptoAuthMac)? =>
    if not (k.is_valid() and t.is_valid()) then error end
    if 0 != @crypto_auth_verify[_Int](
      t.cpointer(), m.cpointer(), m.size(), k.cpointer()
    ) then error end
