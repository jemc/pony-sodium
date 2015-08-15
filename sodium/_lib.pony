
use "lib:sodium"

primitive _Lib
  fun _init(env: Env) =>
    @sodium_init[None]()

// Platform-specific typdefs
// TODO: detect these based on platform (which Pony doesn't yet do either)
type _SizeT is U64
type _UChar is U8
type _Int   is U32
