
use "lib:sodium"

class val CryptoSecretBoxKey
  let _inner: String
  fun string(): String => _inner
  fun cpointer(): Pointer[U8] tag => _inner.cpointer()
  fun is_valid(): Bool => _inner.size() == CryptoSecretBox.key_size()
  new val create(buf: (ReadSeq[U8] iso | ReadSeq[U8] val)) =>
    _inner = recover String.>append(consume buf) end

class val CryptoSecretBoxNonce
  let _inner: String
  fun string(): String => _inner
  fun cpointer(): Pointer[U8] tag => _inner.cpointer()
  fun is_valid(): Bool => _inner.size() == CryptoSecretBox.nonce_size()
  new val create(buf: (ReadSeq[U8] iso | ReadSeq[U8] val)) =>
    _inner = recover String.>append(consume buf) end

primitive CryptoSecretBox
  fun tag mac_size(): USize   => @crypto_secretbox_macbytes[USize]().usize()
  fun tag key_size(): USize   => @crypto_secretbox_keybytes[USize]().usize()
  fun tag nonce_size(): USize => @crypto_secretbox_noncebytes[USize]().usize()
  
  fun tag _make_buffer(size: USize): String iso^ =>
    recover String.from_cpointer(
      @pony_alloc[Pointer[U8]](@pony_ctx[Pointer[None] iso](), size), size
    ) end
  
  fun tag random_bytes(size: USize): String iso^ =>
    let buf = _make_buffer(size)
    @randombytes_buf[None](buf.cpointer(), size)
    buf
  
  fun tag key(): CryptoSecretBoxKey =>
    CryptoSecretBoxKey(random_bytes(key_size()))
  
  fun tag nonce(): CryptoSecretBoxNonce =>
    CryptoSecretBoxNonce(random_bytes(nonce_size()))
  
  fun tag apply(m: String, n: CryptoSecretBoxNonce, k: CryptoSecretBoxKey): String? =>
    if not (n.is_valid() and k.is_valid()) then error end
    let buf_size = m.size() + mac_size()
    let buf = _make_buffer(buf_size)
    if 0 != @crypto_secretbox_easy[_Int](
      buf.cpointer(), m.cpointer(), m.size(), n.cpointer(), k.cpointer()
    ) then error end
    consume buf
  
  fun tag open(c: String, n: CryptoSecretBoxNonce, k: CryptoSecretBoxKey): String? =>
    if not (n.is_valid() and k.is_valid()) then error end
    let buf_size = c.size() - mac_size()
    let buf = _make_buffer(buf_size)
    if 0 != @crypto_secretbox_open_easy[_Int](
      buf.cpointer(), c.cpointer(), c.size(), n.cpointer(), k.cpointer()
    ) then error end
    consume buf
  