
use "lib:sodium"

primitive _Lib
  fun _init(env: Env) =>
    @sodium_init[None]()
