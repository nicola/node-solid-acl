var ACL = require('../')
var rdf = require('rdf-ext')()
var InMemoryStore = require('rdf-store-inmemory')
var assert = require('chai').assert

describe('ACL Class', function () {

  var user1 = "https://user1.databox.me/profile/card#me"
  var user2 = "https://user2.databox.me/profile/card#me"
  var address = 'https://server.tld/test'

  describe('can', function () {
    it('should give "Control" if not ACL is found', function (done) {
      var store = new InMemoryStore(rdf)
      var acl = new ACL(store, {
        suffix: '.acl'
      })

      acl.can(user1, 'Control', 'example.ttl', function (err) {
        assert.notOk(err)
        done(err)
      })
    })

    it('should give "Read" if valid rule is found', function (done) {
      var store = new InMemoryStore(rdf)
      var acl = new ACL(store, {
        suffix: '.acl'
      })

      rdf.parseTurtle('', function (graph) {
        store.add('example.ttl', graph, function (graph) {
          acl.can(user1, 'Control', 'example.ttl', function (err) {
            assert.notOk(err)
            done(err)
          })
        })
      })
    })

  })
})
