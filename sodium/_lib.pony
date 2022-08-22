
use "lib:sodium"

use @pony_alloc[Pointer[U8]](ctx: Pointer[None], size: USize)
use @pony_ctx[Pointer[None]]()
use @sodium_init[None]()
use @randombytes_buf[None](buf_cpointer: Pointer[None], size: USize)
use @crypto_sign_ed25519_pk_to_curve25519[_Int](buf_cpointer: Pointer[None], pk_cpointer: Pointer[None])
use @crypto_box_keypair[_Int](pk_cpointer: Pointer[None], sk_cpointer: Pointer[None])
use @crypto_box_seed_keypair[_Int](pk_cpointer: Pointer[None], sk_cpointer: Pointer[None], seed_cpointer: Pointer[None])
use @crypto_sign_keypair[_Int](pk_cpointer: Pointer[None], sk_cpointer: Pointer[None])
use @crypto_sign_seed_keypair[_Int](pk_cpointer: Pointer[None], sk_cpointer: Pointer[None], seed_cpointer: Pointer[None])
use @crypto_sign_seedbytes[USize]()
use @crypto_sign_publickeybytes[USize]()
use @crypto_sign_bytes[USize]()
use @crypto_sign_secretkeybytes[USize]()
use @crypto_secretbox_macbytes[USize]()
use @crypto_secretbox_keybytes[USize]()
use @crypto_sign[_Int](buf_cpointer: Pointer[None], addressof_buf_size: Pointer[None], m_cpointer: Pointer[None], m_size: USize, sk_cpointer: Pointer[None])
use @crypto_sign_open[_Int](buf_cpointer: Pointer[None], addressof_buf_size: Pointer[None], c_cpointer: Pointer[None], c_size: USize, pk_cpointer: Pointer[None])
use @crypto_sign_detached[_Int](buf_cpointer: Pointer[None], addressof_buf_size: Pointer[None], m_cpointer: Pointer[None], m_size: USize, sk_cpointer: Pointer[None])
use @crypto_sign_verify_detached[_Int](t_cpointer: Pointer[None], m_cpointer: Pointer[None], m_size: USize, pk_cpointer: Pointer[None])
use @crypto_hash_sha256_bytes[USize]()
use @crypto_hash_sha512_bytes[USize]()
use @crypto_box_seedbytes[USize]()
use @crypto_box_secretkeybytes[USize]()
use @crypto_box_publickeybytes[USize]()
use @crypto_box_noncebytes[USize]()
use @crypto_box_macbytes[USize]()
use @crypto_scalarmult_bytes[USize]()
use @crypto_sign_ed25519_sk_to_curve25519[_Int](buf_cpointer: Pointer[None], sk_cpointer: Pointer[None])
use @crypto_hash_sha256[_Int](buf_cpointer: Pointer[None], m_cpointer: Pointer[None], m_size: USize)
use @crypto_hash_sha512[_Int](buf_cpointer: Pointer[None], m_cpointer: Pointer[None], m_size: USize)
use @crypto_scalarmult_base[_Int](buf_cpointer: Pointer[None], sk_cpointer: Pointer[None])
use @crypto_scalarmult[_Int](buf_cpointer: Pointer[None], sk_cpointer: Pointer[None], pk_cpointer: Pointer[None])
use @crypto_auth_keybytes[USize]()
use @crypto_auth_bytes[USize]()
use @crypto_auth[_Int](buf_cpointer: Pointer[None], m_cpointer: Pointer[None], m_size: USize, k_cpointer: Pointer[None])
use @crypto_auth_verify[_Int](t_cpointer: Pointer[None], m_cpointer: Pointer[None], m_size: USize, k_cpointer: Pointer[None])
use @crypto_box_easy[_Int](buf_cpointer: Pointer[None], m_cpointer: Pointer[None], m_size: USize, n_cpointer: Pointer[None], pk_cpointer: Pointer[None], sk_cpointer: Pointer[None])
use @crypto_box_open_easy[_Int](buf_cpointer: Pointer[None], c_cpointer: Pointer[None], c_size: USize, n_cpointer: Pointer[None], pk_cpointer: Pointer[None], sk_cpointer: Pointer[None])
use @crypto_secretbox_noncebytes[USize]()
use @crypto_secretbox_easy[_Int](buf_cpointer: Pointer[None], m_cpointer: Pointer[None], m_size: USize, n_cpointer: Pointer[None], k_cpointer: Pointer[None])
use @crypto_secretbox_open_easy[_Int](buf_cpointer: Pointer[None], c_cpointer: Pointer[None], c_size: USize, n_cpointer: Pointer[None], k_cpointer: Pointer[None])

primitive _Lib
  fun _init() =>
    @sodium_init[None]()

type _UChar is U8
type _Int   is I32

