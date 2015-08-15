
use "lib:sodium"

class CryptoSecretBoxKey val
  let _inner: String
  fun string(): String => _inner
  fun cstring(): Pointer[U8] tag => _inner.cstring()
  fun is_valid(): Bool => _inner.size() == CryptoSecretBox._keybytes()
  new val create(buf: (ReadSeq[U8] iso | ReadSeq[U8] val)) =>
    _inner = recover String.append(consume buf) end

class CryptoSecretBoxNonce val
  let _inner: String
  fun string(): String => _inner
  fun cstring(): Pointer[U8] tag => _inner.cstring()
  fun is_valid(): Bool => _inner.size() == CryptoSecretBox._noncebytes()
  new val create(buf: (ReadSeq[U8] iso | ReadSeq[U8] val)) =>
    _inner = recover String.append(consume buf) end

primitive CryptoSecretBox
  fun tag _macbytes(): U64   => @crypto_secretbox_macbytes[_SizeT]().u64()
  fun tag _keybytes(): U64   => @crypto_secretbox_keybytes[_SizeT]().u64()
  fun tag _noncebytes(): U64 => @crypto_secretbox_noncebytes[_SizeT]().u64()
  
  fun tag _make_buffer(size: U64): String iso^ =>
    recover String.from_cstring(@pony_alloc[Pointer[U8]](size), size) end
  
  fun tag random_bytes(size: U64): String iso^ =>
    let buf = _make_buffer(size)
    @randombytes_buf[None](buf.cstring(), size)
    buf
  
  fun tag key(): CryptoSecretBoxKey =>
    CryptoSecretBoxKey(random_bytes(_keybytes()))
  
  fun tag nonce(): CryptoSecretBoxNonce =>
    CryptoSecretBoxNonce(random_bytes(_noncebytes()))
  
  fun tag apply(m: String, n: CryptoSecretBoxNonce, k: CryptoSecretBoxKey): String? =>
    if not (n.is_valid() and k.is_valid()) then error end
    let buf_size = m.size() + _macbytes()
    let buf = _make_buffer(buf_size)
    if 0 != @crypto_secretbox_easy[_Int](
      buf.cstring(), m.cstring(), m.size(), n.cstring(), k.cstring()
    ) then error end
    consume buf
  
  fun tag open(c: String, n: CryptoSecretBoxNonce, k: CryptoSecretBoxKey): String? =>
    if not (n.is_valid() and k.is_valid()) then error end
    let buf_size = c.size() - _macbytes()
    let buf = _make_buffer(buf_size)
    if 0 != @crypto_secretbox_open_easy[_Int](
      buf.cstring(), c.cstring(), c.size(), n.cstring(), k.cstring()
    ) then error end
    consume buf
  