
use "lib:sodium"

primitive _Lib
  fun _init() =>
    @sodium_init[None]()

type _UChar is U8
type _Int   is I32
