
use "lib:sodium"

class val CryptoSignSeed
  let _inner: String
  fun string(): String => _inner
  fun cstring(): Pointer[U8] tag => _inner.cstring()
  fun is_valid(): Bool => _inner.size() == CryptoSign.seed_size()
  new val create(buf: (ReadSeq[U8] iso | ReadSeq[U8] val)) =>
    _inner = recover String.append(consume buf) end

class val CryptoSignSecretKey
  let _inner: String
  fun string(): String => _inner
  fun cstring(): Pointer[U8] tag => _inner.cstring()
  fun is_valid(): Bool => _inner.size() == CryptoSign.secret_key_size()
  fun val to_curve(): CryptoBoxSecretKey? => CryptoSign._secret_key_to_curve(this)
  new val create(buf: (ReadSeq[U8] iso | ReadSeq[U8] val)) =>
    _inner = recover String.append(consume buf) end

class val CryptoSignPublicKey
  let _inner: String
  fun string(): String => _inner
  fun cstring(): Pointer[U8] tag => _inner.cstring()
  fun is_valid(): Bool => _inner.size() == CryptoSign.public_key_size()
  fun val to_curve(): CryptoBoxPublicKey? => CryptoSign._public_key_to_curve(this)
  new val create(buf: (ReadSeq[U8] iso | ReadSeq[U8] val)) =>
    _inner = recover String.append(consume buf) end

class val CryptoSignMac
  let _inner: String
  fun string(): String => _inner
  fun cstring(): Pointer[U8] tag => _inner.cstring()
  fun is_valid(): Bool => _inner.size() == CryptoSign.mac_size()
  new val create(buf: (ReadSeq[U8] iso | ReadSeq[U8] val)) =>
    _inner = recover String.append(consume buf) end

primitive CryptoSign
  fun tag seed_size(): USize => @crypto_sign_seedbytes[USize]().usize()
  fun tag secret_key_size(): USize => @crypto_sign_secretkeybytes[USize]().usize()
  fun tag public_key_size(): USize => @crypto_sign_publickeybytes[USize]().usize()
  fun tag mac_size(): USize        => @crypto_sign_bytes[USize]().usize()
  
  fun tag _make_buffer(size: USize): String iso^ =>
    recover String.from_cstring(
      @pony_alloc[Pointer[U8]](@pony_ctx[Pointer[None] iso](), size), size
    ) end
  
  fun tag random_bytes(size: USize): String iso^ =>
    let buf = _make_buffer(size)
    @randombytes_buf[None](buf.cstring(), size)
    buf
  
  fun tag keypair(): (CryptoSignSecretKey, CryptoSignPublicKey)? =>
    let sk_size = secret_key_size(); let sk = _make_buffer(sk_size)
    let pk_size = public_key_size(); let pk = _make_buffer(pk_size)
    if 0 != @crypto_sign_keypair[_Int](pk.cstring(), sk.cstring()) then error end
    (CryptoSignSecretKey(consume sk), CryptoSignPublicKey(consume pk))

  fun tag seed_keypair(seed: CryptoSignSeed): (CryptoSignSecretKey, CryptoSignPublicKey)? =>
    let sk_size = secret_key_size(); let sk = _make_buffer(sk_size)
    let pk_size = public_key_size(); let pk = _make_buffer(pk_size)
    if 0 != @crypto_sign_seed_keypair[_Int](
      pk.cstring(), sk.cstring(), seed.cstring()
    ) then error end
    (CryptoSignSecretKey(consume sk), CryptoSignPublicKey(consume pk))

  fun tag apply(m: String, sk: CryptoSignSecretKey): String? =>
    if not sk.is_valid() then error end
    var buf_size: USize = m.size() + mac_size()
    let buf = _make_buffer(buf_size)
    if 0 != @crypto_sign[_Int](
      buf.cstring(), addressof buf_size, m.cstring(), m.size(), sk.cstring()
    ) then error end
    consume buf
  
  fun tag open(c: String, pk: CryptoSignPublicKey): String? =>
    if not pk.is_valid() then error end
    var buf_size: USize = c.size() - mac_size()
    let buf = _make_buffer(buf_size)
    if 0 != @crypto_sign_open[_Int](
      buf.cstring(), addressof buf_size, c.cstring(), c.size(), pk.cstring()
    ) then error end
    consume buf
  
  fun tag detached(m: String, sk: CryptoSignSecretKey): CryptoSignMac? =>
    if not sk.is_valid() then error end
    var buf_size: USize = mac_size()
    let buf = _make_buffer(buf_size)
    if 0 != @crypto_sign_detached[_Int](
      buf.cstring(), addressof buf_size, m.cstring(), m.size(), sk.cstring()
    ) then error end
    CryptoSignMac(consume buf)
  
  fun tag verify_detached(m: String, pk: CryptoSignPublicKey, t: CryptoSignMac)? =>
    if not (pk.is_valid() and t.is_valid()) then error end
    if 0 != @crypto_sign_verify_detached[_Int](
      t.cstring(), m.cstring(), m.size(), pk.cstring()
    ) then error end
  
  fun tag _secret_key_to_curve(sk: CryptoSignSecretKey): CryptoBoxSecretKey? =>
    if not sk.is_valid() then error end
    let buf_size = CryptoBox.secret_key_size()
    let buf = _make_buffer(buf_size)
    if 0 != @crypto_sign_ed25519_sk_to_curve25519[_Int](
      buf.cstring(), sk.cstring()
    ) then error end
    CryptoBoxSecretKey(consume buf)
  
  fun tag _public_key_to_curve(pk: CryptoSignPublicKey): CryptoBoxPublicKey? =>
    if not pk.is_valid() then error end
    let buf_size = CryptoBox.public_key_size()
    let buf = _make_buffer(buf_size)
    if 0 != @crypto_sign_ed25519_pk_to_curve25519[_Int](
      buf.cstring(), pk.cstring()
    ) then error end
    CryptoBoxPublicKey(consume buf)
