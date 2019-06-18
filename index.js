const sofUtil = require('sophonjs-util')
const srlp = require('srlp')
const Buffer = require('safe-buffer').Buffer

var Account = module.exports = function (data) {
  // Define Properties
  var fields = [{
    name: 'nonce',
    default: Buffer.alloc(0)
  }, {
    name: 'balance',
    default: Buffer.alloc(0)
  }, {
    name: 'stateRoot',
    length: 32,
    default: sofUtil.SHA3_SRLP
  }, {
    name: 'codeHash',
    length: 32,
    default: sofUtil.SHA3_NULL
  }]

  sofUtil.defineProperties(this, fields, data)
}

Account.prototype.serialize = function () {
  return srlp.encode(this.raw)
}

Account.prototype.isContract = function () {
  return this.codeHash.toString('hex') !== sofUtil.SHA3_NULL_S
}

Account.prototype.getCode = function (state, cb) {
  if (!this.isContract()) {
    cb(null, Buffer.alloc(0))
    return
  }

  state.getRaw(this.codeHash, cb)
}

Account.prototype.setCode = function (trie, code, cb) {
  var self = this

  this.codeHash = sofUtil.sha3(code)

  if (this.codeHash.toString('hex') === sofUtil.SHA3_NULL_S) {
    cb(null, Buffer.alloc(0))
    return
  }

  trie.putRaw(this.codeHash, code, function (err) {
    cb(err, self.codeHash)
  })
}

Account.prototype.getStorage = function (trie, key, cb) {
  var t = trie.copy()
  t.root = this.stateRoot
  t.get(key, cb)
}

Account.prototype.setStorage = function (trie, key, val, cb) {
  var self = this
  var t = trie.copy()
  t.root = self.stateRoot
  t.put(key, val, function (err) {
    if (err) return cb()
    self.stateRoot = t.root
    cb()
  })
}

Account.prototype.isEmpty = function () {
  return this.balance.toString('hex') === '' &&
  this.nonce.toString('hex') === '' &&
  this.stateRoot.toString('hex') === sofUtil.SHA3_SRLP_S &&
  this.codeHash.toString('hex') === sofUtil.SHA3_NULL_S
}
