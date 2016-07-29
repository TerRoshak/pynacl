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


# crypto_hash_BYTES = lib.crypto_hash_bytes()
#crypto_hash_BYTES = lib.crypto_hash_sha512_bytes()
#crypto_hash_sha256_BYTES = lib.crypto_hash_sha256_bytes()
#crypto_hash_sha512_BYTES = lib.crypto_hash_sha512_bytes()

crypto_auth_BYTES = lib.crypto_auth_bytes()
crypto_auth_hmacsha256_BYTES = lib.crypto_auth_hmacsha256_bytes()
crypto_auth_hmacsha512256_BYTES = lib.crypto_auth_hmacsha512256_bytes()

def crypto_auth(message, k):
    
    a = ffi.new("unsigned char[]", crypto_auth_BYTES)
    rc = lib.crypto_auth(a, message, len(message), k)

    assert rc == 0
    return ffi.buffer(a, crypto_auth_BYTES)[:]

def crypto_auth_hmacsha256(message, k):

    a = ffi.new("unsigned char[]", crypto_auth_hmacsha256_BYTES)
    rc = lib.crypto_auth_hmacsha256(a, message, len(message), k)

    assert rc == 0
    return ffi.buffer(a, crypto_auth_hmacsha256_BYTES)[:]

def crypto_auth_hmacsha512256(message, k):

    a = ffi.new("unsigned char[]", crypto_auth_hmacsha512256_BYTES)
    rc = lib.crypto_auth_hmacsha512256(a, message, len(message), k)

    assert rc == 0
    return ffi.buffer(a, crypto_auth_hmacsha512256_BYTES)[:]

def crypto_auth_verify(a, message, k):

    rc = lib.crypto_auth_verify(a, message, len(message), k)
    return (rc == 0)

def crypto_auth_hmacsha256_verify(a, message, k):
    
    rc = lib.crypto_auth_hmacsha256_verify(a, message, len(message), k)
    return (rc == 0) 

def crypto_auth_hmacsha512256_verify(a, message, k):
    
    rc = lib.crypto_auth_hmacsha512256_verify(a, message, len(message), k)
    return (rc == 0)
