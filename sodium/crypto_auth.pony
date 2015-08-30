
use "lib:sodium"

class CryptoAuthKey val
  let _inner: String
  fun string(): String => _inner
  fun cstring(): Pointer[U8] tag => _inner.cstring()
  fun is_valid(): Bool => _inner.size() == CryptoAuth._keybytes()
  new val create(buf: (ReadSeq[U8] iso | ReadSeq[U8] val)) =>
    _inner = recover String.append(consume buf) end

class CryptoAuthMac val
  let _inner: String
  fun string(): String => _inner
  fun cstring(): Pointer[U8] tag => _inner.cstring()
  fun is_valid(): Bool => _inner.size() == CryptoAuth._bytes()
  new val create(buf: (ReadSeq[U8] iso | ReadSeq[U8] val)) =>
    _inner = recover String.append(consume buf) end

primitive CryptoAuth
  fun tag _bytes(): U64    => @crypto_auth_bytes[_SizeT]().u64()
  fun tag _keybytes(): U64 => @crypto_auth_keybytes[_SizeT]().u64()
  
  fun tag _make_buffer(size: U64): String iso^ =>
    recover String.from_cstring(@pony_alloc[Pointer[U8]](size), size) end
  
  fun tag random_bytes(size: U64): String iso^ =>
    let buf = _make_buffer(size)
    @randombytes_buf[None](buf.cstring(), size)
    buf
  
  fun tag key(): CryptoAuthKey =>
    CryptoAuthKey(random_bytes(_keybytes()))
  
  fun tag apply(m: String, k: CryptoAuthKey): CryptoAuthMac? =>
    if not k.is_valid() then error end
    let buf = _make_buffer(_bytes())
    if 0 != @crypto_auth[_Int](
      buf.cstring(), m.cstring(), m.size(), k.cstring()
    ) then error end
    CryptoAuthMac(consume buf)
  
  fun tag verify(m: String, k: CryptoAuthKey, t: CryptoAuthMac)? =>
    if not (k.is_valid() and t.is_valid()) then error end
    if 0 != @crypto_auth_verify[_Int](
      t.cstring(), m.cstring(), m.size(), k.cstring()
    ) then error end
