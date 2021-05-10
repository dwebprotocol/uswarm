'use strict'
const assert = require('assert')
const {
  crypto_generichash: hash,
  crypto_sign_verify_detached: verify
} = require('sodium-native')
const finished = require('end-of-stream')
const {
    VALUE_MAX_SIZE,
    DWebIdSign
  } = require('@dwebid/sign')

const PUT_VALUE_MAX_SIZE = VALUE_MAX_SIZE
const maybeSeqError = (seqA, seqB, valueA, valueB) => {
  if (valueA && valueB && seqA === seqB && Buffer.compare(valueA, valueB) !== 0) {
    return Error('ERR_INVALID_SEQ')
  }
  if (seqA <= seqB) {
      return Error('ERR_SEQ_MUST_EXCEED_CURRENT')
    }
  return null
}

class MutableUser extends DWebIdSign {
  constructor (dht, store) {
    super()
    this.dht = dht
    this.store = store
    this.prefix = 'm'
  }

  get (username, opts = {}, cb = opts) {
    const { dht, signable } = this
    const { seq = 0 } = opts
    assert(Buffer.isBuffer(username), 'key must be a buffer.')
    assert(typeof seq === 'number', 'seq should be a number.')
    
    const queryStream = dht.query('mutable-user', username, { seq })
      .map((result) => {
        if (!result.value) return
        const { username, signature, dk, publicKey, seq: storedSeq } = result.value
        const msg = signable(username, { dk, seq: storedSeq })
        if (storedSeq >= userSeq && verify(signature, msg, publicKey)) {
          const id = result.node.id
          return {
            id, 
            username,
            dk,
            publicKey,
            seq: storedSeq
          }
        }
      })
    let found = false
    const hasCb = typeof cb === 'function'
    const userSeq = seq
    if (hasCb) {
      queryStream.once('data', (info) => {
        found = true
        cb(null, info)
        queryStream.destroy()
      })
      finished(queryStream, (err) => {
        if (err) {
          cb(err)
          return
        }
        if (found === false) cb(null, { value: null })
      })
    }
    return queryStream
  }
  put (username, opts, cb) {
    assert(Buffer.isBuffer(username), 'username must be a Buffer.')
    assert(typeof opts === 'object', 'opts are required.')
    assert(typeof cb === 'function', 'callback is required.')
    assert(username.length <= PUT_VALUE_MAX_SIZE, `${username} cannot exceed ${PUT_VALUE_MAX_SIZE}`)
    const { dht } = this
    const { seq=0, dk, keypair, signature = this.sign(username, opts) } = opts
        if (opts.signature) {
      assert(keypair, 'keypair is required.')
      const { secretKey, publicKey } = keypair
      assert(Buffer.isBuffer(publicKey), 'keypair.publicKey is required')
      assert(!secretKey, 'Only opts.signature or opts.keypair.secretKey should be supplied.')
    }
    const key = Buffer.alloc(32)
    hash(key, username)

    const queryStream = dht.update('mutable-user', key, {
      username, signature, dk, publicKey, seq
    })

    queryStream.once('warning', (err, proof) => {
      if (err && proof) {
        const seqErr = maybeSeqError(seq, proof.seq, proof.username, username)
        if (seqErr) {
          const { username, signature, publicKey, seq } = proof
          const msg = this.signable(username, { seq })
          const verified = verify(signature, msg, publicKey)
          if (verified) queryStream.destroy(seqErr)
        }
      }
    })

    queryStream.resume()
    finish(queryStream, (err) => {
      if (err) {
        cb(err)
        return
      }
      cb(null, { username, signature, dk, publicKey, seq })
    })
    return queryStream
  }
  _command() {
    const { store, signable, prefix } = this
    return {
      valueEncoding: Mutable,
      update (input, cb) {
        if (input.value.username == null || input.value.signature == null) {
          cb(null)
          return
        }
        const { username, signature, dk, publicKey, seq } = input.value
        const key = prefix + username.toString('hex')
        const local = store.get(key)
        const msg = signable(username, { dk, seq })
        const verified = verify(signature, msg, publicKey)
        if (verified === false) {
          cb(Error('ERROR_INVALID_INPUT'))
          return
        }
        if (local) {
          const err = maybeSeqError(seq, local.seq, local.username, username)
          if (err) cb(err, local)
        }
        store.set(key, { username, signature, dk, publicKey, seq })
        cb(null)
      },
      query({target, value }, cb) {
        const { username, seq } = value
        const key = prefix + target.toString('hex')
        const result = store.get(key)
        if (result && result.seq >= seq) {
          cb(null, result)
        } else {
          cb(null, null)
        }
      }
    }
  }
}

module.exports = MutableUser