
use "lib:sodium"

class CryptoBoxPublicKey val
  let _inner: String
  fun string(): String => _inner
  fun cstring(): Pointer[U8] tag => _inner.cstring()
  fun is_valid(): Bool => _inner.size() == CryptoBox._publickeybytes()
  new val create(buf: (ReadSeq[U8] iso | ReadSeq[U8] val)) =>
    _inner = recover String.append(consume buf) end

class CryptoBoxSecretKey val
  let _inner: String
  fun string(): String => _inner
  fun cstring(): Pointer[U8] tag => _inner.cstring()
  fun is_valid(): Bool => _inner.size() == CryptoBox._secretkeybytes()
  new val create(buf: (ReadSeq[U8] iso | ReadSeq[U8] val)) =>
    _inner = recover String.append(consume buf) end

class CryptoBoxNonce val
  let _inner: String
  fun string(): String => _inner
  fun cstring(): Pointer[U8] tag => _inner.cstring()
  fun is_valid(): Bool => _inner.size() == CryptoBox._noncebytes()
  new val create(buf: (ReadSeq[U8] iso | ReadSeq[U8] val)) =>
    _inner = recover String.append(consume buf) end

primitive CryptoBox
  fun tag _publickeybytes(): U64 => @crypto_box_publickeybytes[_SizeT]().u64()
  fun tag _secretkeybytes(): U64 => @crypto_box_secretkeybytes[_SizeT]().u64()
  fun tag _noncebytes(): U64     => @crypto_box_noncebytes[_SizeT]().u64()
  fun tag _macbytes(): U64       => @crypto_box_macbytes[_SizeT]().u64()
  
  fun tag _make_buffer(size: U64): String iso^ =>
    recover String.from_cstring(@pony_alloc[Pointer[U8]](size), size) end
  
  fun tag random_bytes(size: U64): String iso^ =>
    let buf = _make_buffer(size)
    @randombytes_buf[None](buf.cstring(), size)
    buf
  
  fun tag nonce(): CryptoBoxNonce =>
    CryptoBoxNonce(random_bytes(_noncebytes()))
  
  fun tag keypair(): (CryptoBoxPublicKey, CryptoBoxSecretKey)? =>
    let pk_size = _publickeybytes(); let pk = _make_buffer(pk_size)
    let sk_size = _secretkeybytes(); let sk = _make_buffer(sk_size)
    if 0 != @crypto_box_keypair[_Int](pk.cstring(), sk.cstring()) then error end
    (CryptoBoxPublicKey(consume pk), CryptoBoxSecretKey(consume sk))
  
  fun tag apply(m: String, n: CryptoBoxNonce, pk: CryptoBoxPublicKey, sk: CryptoBoxSecretKey): String? =>
    if not (n.is_valid() and pk.is_valid() and sk.is_valid()) then error end
    let buf_size = m.size() + _macbytes()
    let buf = _make_buffer(buf_size)
    if 0 != @crypto_box_easy[_Int](
      buf.cstring(), m.cstring(), m.size(), n.cstring(), pk.cstring(), sk.cstring()
    ) then error end
    consume buf
  
  fun tag open(c: String, n: CryptoBoxNonce, pk: CryptoBoxPublicKey, sk: CryptoBoxSecretKey): String? =>
    if not (n.is_valid() and pk.is_valid() and sk.is_valid()) then error end
    let buf_size = c.size() - _macbytes()
    let buf = _make_buffer(buf_size)
    if 0 != @crypto_box_open_easy[_Int](
      buf.cstring(), c.cstring(), c.size(), n.cstring(), pk.cstring(), sk.cstring()
    ) then error end
    consume buf
  