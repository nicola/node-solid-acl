var ACL = require('../')
var rdf = require('rdf-ext')()
var InMemoryStore = require('rdf-store-inmemory')
var assert = require('chai').assert

describe('ACL Class', function () {

  var user1 = 'https://user1.databox.me/profile/card#me'
  var user2 = 'https://user2.databox.me/profile/card#me'
  var address = 'https://server.tld/test'

  describe('can', function () {
    describe('with no ACL file', function () {
      it('should give "Read"/"Write"/"Append" if no ACL is found', function (done) {
        var store = new InMemoryStore(rdf)
        var acl = new ACL(store, {
          suffix: '.acl'
        })

        acl.can(user1, 'Read', 'example.ttl', function (err) {
          assert.notOk(err)
          acl.can(user1, 'Write', 'example.ttl', function (err) {
            assert.notOk(err)
            done(err)
          })
        })
      })

    describe('with ACL file', function () {
      it('should not "Read"/"Write" if no valid rule is not found in existing ACL files', function (done) {
      })
      it('should not "Read"/"Write"/"Control" if Origin is present and doesn\'t match the request', function (done) {
      })
      it('should "Read"/"Write"/"Control" if Agent rule is found', function (done) {
      })
      it('should "Read"/"Write"/"Control" if AgentClass rule is found', function (done) {
      })
      it('should "Read"/"Write"/"Control" if Owner rule is found', function (done) {
      })
      it('should "Read"/"Write" on defaultForNew in parent path', function (done) {
      })
      it('should not "Control" an ACL file on defaultForNew in parent path', function (done) {
      })
    })
  })
})
