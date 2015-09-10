var ACL = require('../')
var rdf = require('rdf-ext')()
var InMemoryStore = require('rdf-store-inmemory')
var assert = require('chai').assert
var utils = require('../lib/utils')

describe('utils', function () {
  describe('possibleACLs', function () {
    it('should return a list of ACLs in an ordered list of parent paths', function () {
      var list = utils.possibleACLs('http://example.com/a/b/c/foo', '.acl')
      assert.equal(list[0], 'http://example.com/a/b/c/foo.acl')
      assert.equal(list[1], 'http://example.com/a/b/c/.acl')
      assert.equal(list[2], 'http://example.com/a/b/.acl')
      assert.equal(list[3], 'http://example.com/a/.acl')
      assert.equal(list[4], 'http://example.com/.acl')

      assert.equal(list.length, 5)

      var list = utils.possibleACLs('http://example.com/', '.acl')
      assert.equal(list[0], 'http://example.com/.acl')
      assert.equal(list.length, 1)
    })
    it('should also work for folders', function () {
      var list = utils.possibleACLs('/a/b/c/foo', '.acl')
      assert.equal(list[0], '/a/b/c/foo.acl')
      assert.equal(list[1], '/a/b/c/.acl')
      assert.equal(list[2], '/a/b/.acl')
      assert.equal(list[3], '/a/.acl')
      assert.equal(list[4], '/.acl')

      assert.equal(list.length, 5)

      var list = utils.possibleACLs('/', '.acl')
      assert.equal(list[0], '/.acl')
      assert.equal(list.length, 1)
    })
  })
})

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

        acl.can(user1, 'Read', 'http://example.tld/example.ttl', function (err) {
          assert.notOk(err)
          acl.can(user1, 'Write', 'http://example.tld/example.ttl', function (err) {
            assert.notOk(err)
            done(err)
          })
        })
      })
    })

    describe('with ACL file', function () {
      it('should not "Read"/"Write"/"Append" if no valid rule is found in existing ACL files', function (done) {
        var store = new InMemoryStore(rdf)
        var acl = new ACL(store, {
          suffix: '.acl'
        })
        rdf.parseTurtle(
          '<#0>\n' +
          ' <http://www.w3.org/ns/auth/acl#accessTo> <http://example.tld/example.ttl>;\n' +
          ' <http://www.w3.org/ns/auth/acl#agent> <' + user1 + '>;\n' +
          ' <http://www.w3.org/ns/auth/acl#mode> <http://www.w3.org/ns/auth/acl#Read>, <http://www.w3.org/ns/auth/acl#Write> .\n',
          function (graph) {
            store.add('http://example.tld/example.ttl.acl', graph, function (graph) {
              acl.can(user1, 'Control', 'http://example.tld/example.ttl', function (err) {
                assert.ok(err)
                done()
              })
            })
          })
      })
      it('should not "Read"/"Write"/"Control"/"Append" if Origin is present and doesn\'t match the request', function (done) {
        var store = new InMemoryStore(rdf)
        var acl = new ACL(store, {
          suffix: '.acl'
        })
        rdf.parseTurtle(
          '<#0>\n' +
          ' <http://www.w3.org/ns/auth/acl#accessTo> <http://example.tld/example.ttl>;\n' +
          ' <http://www.w3.org/ns/auth/acl#origin> <http://origin.tld>;\n' +
          ' <http://www.w3.org/ns/auth/acl#mode> <http://www.w3.org/ns/auth/acl#Read>, <http://www.w3.org/ns/auth/acl#Write> .\n',
          function (graph) {
            store.add('http://example.tld/example.ttl.acl', graph, function (graph) {
              acl.can(user1, 'Read', 'http://example.tld/example.ttl', function (err) {
                assert.ok(err)
                done()
              })
            })
          })
      })
      it('should "Read"/"Write"/"Control"/"Append" if Agent rule is found', function (done) {
        var store = new InMemoryStore(rdf)
        var acl = new ACL(store, {
          suffix: '.acl'
        })
        rdf.parseTurtle(
          '<#0>\n' +
          ' <http://www.w3.org/ns/auth/acl#accessTo> <http://example.tld/example.ttl>;\n' +
          ' <http://www.w3.org/ns/auth/acl#agent> <' + user1 + '>;\n' +
          ' <http://www.w3.org/ns/auth/acl#mode> <http://www.w3.org/ns/auth/acl#Read>, <http://www.w3.org/ns/auth/acl#Write> .\n',
          function (graph) {
            store.add('http://example.tld/example.ttl.acl', graph, function (graph) {
              acl.can(user1, 'Read', 'http://example.tld/example.ttl', function (err) {
                assert.notOk(err)
                done()
              })
            })
          })
      })
      it('should "Read"/"Write"/"Control"/"Append" if AgentClass rule is found', function (done) {
        done()
      })
      it('should "Read"/"Write"/"Control"/"Append" if Owner rule is found', function (done) {
        done()
      })
      it('should "Read"/"Write"/"Append" on defaultForNew in parent path', function (done) {
        done()
      })
      it('should not "Control" an ACL file on defaultForNew in parent path', function (done) {
        done()
      })
    })
  })
})
