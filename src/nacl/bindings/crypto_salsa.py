# Copyright 2013 Donald Stufft and individual contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import absolute_import, division, print_function

from nacl._sodium import ffi, lib

crypto_core_hsalsa20_outputBYTES = lib.crypto_core_hsalsa20_outputbytes()
crypto_core_hsalsa20_inputBYTES = lib.crypto_core_hsalsa20_inputbytes()
crypto_core_hsalsa20_keyBYTES = lib.crypto_core_hsalsa20_keybytes()
crypto_core_hsalsa20_constBYTES = lib.crypto_core_hsalsa20_constbytes()

def crypto_core_hsalsa20(m, k, c):
    out = ffi.new("unsigned char[]", crypto_core_hsalsa20_outputBYTES)
    rc = lib.crypto_core_hsalsa20(out, m, k, c)
    assert rc == 0
    return ffi.buffer(out, crypto_core_hsalsa20_outputBYTES)
