var ACL = require('../')
var rdf = require('rdf-ext')
var InMemoryStore = require('rdf-store-inmemory')
var assert = require('chai').assert
var utils = require('../lib/utils')
var async = require('async')
var N3Parser = require('rdf-parser-n3')

describe('utils', function () {
  describe('.possibleACLs', function () {
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

    it('when suffix is present, should not add the suffix', function () {
      var list = utils.possibleACLs('/a/b/c/foo.acl', '.acl')
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

describe('ACL', function () {

  var user1 = 'https://user1.databox.me/profile/card#me'
  var user2 = 'https://user2.databox.me/profile/card#me'
  var address = 'https://server.tld/test'

  describe('with no `.acl` resource found in all paths', function () {
    it('should not give "Write", "Append", "Read" and "Control" access', function (done) {
      var store = new InMemoryStore()
      var acl = new ACL({
        store: store,
        suffix: '.acl'
      })

      async.waterfall([
        function (next) {
          acl.can(user1, 'Read', 'http://example.tld/example.ttl', function (err) {
            assert.ok(err)
            next()
          })
        },
        function (next) {
          acl.can(user1, 'Write', 'http://example.tld/example.ttl', function (err) {
            assert.ok(err)
            next()
          })
        },
        function (next) {
          acl.can(user1, 'Append', 'http://example.tld/example.ttl', function (err) {
            assert.ok(err)
            next()
          })
        },
        function (next) {
          acl.can(user1, 'Control', 'http://example.tld/example.ttl', function (err) {
            assert.ok(err)
            next()
          })
        }
      ], done)
    })
  })

  describe('origin', function () {

    it('should "Read"/"Write"/"Control"/"Append" if Agent and Origin are matched', function (done) {
      var store = new InMemoryStore()
      var acl = new ACL({
        store: store,
        suffix: '.acl'
      })
      N3Parser.parse(
        '<#0>\n' +
        ' <http://www.w3.org/ns/auth/acl#accessTo> <http://example.tld/example.ttl>;\n' +
        ' <http://www.w3.org/ns/auth/acl#agent> <' + user1 + '>;\n' +
        ' <http://www.w3.org/ns/auth/acl#origin> <http://origin.tld>;\n' +
        ' <http://www.w3.org/ns/auth/acl#mode> <http://www.w3.org/ns/auth/acl#Read>, <http://www.w3.org/ns/auth/acl#Write> .\n',
        function (err, graph) {
          store.add('http://example.tld/example.ttl.acl', graph, function (err, graph) {
            acl.can(user1, 'Read', 'http://example.tld/example.ttl', function (err) {
              assert.notOk(err)
              done()
            }, {origin: 'http://origin.tld'})
          })
        })
    })

    it('should not "Read"/"Write"/"Control"/"Append" if Origin is present and doesn\'t match the request', function (done) {
      var store = new InMemoryStore()
      var acl = new ACL({
        store: store,
        suffix: '.acl'
      })
      N3Parser.parse(
        '<#0>\n' +
        ' <http://www.w3.org/ns/auth/acl#accessTo> <http://example.tld/example.ttl>;\n' +
        ' <http://www.w3.org/ns/auth/acl#origin> <http://origin.tld>;\n' +
        ' <http://www.w3.org/ns/auth/acl#mode> <http://www.w3.org/ns/auth/acl#Read>, <http://www.w3.org/ns/auth/acl#Write> .\n',
        function (err, graph) {
          store.add('http://example.tld/example.ttl.acl', graph, function (err, graph) {
            acl.can(user1, 'Read', 'http://example.tld/example.ttl', function (err) {
              assert.ok(err)
              done()
            }, {origin: 'http://differentorigin.tld'})
          })
        })
    })

    it('should not "Read"/"Write"/"Control"/"Append" if Origin is present and the request has no Origin', function (done) {
      var store = new InMemoryStore()
      var acl = new ACL({
        store: store,
        suffix: '.acl'
      })
      N3Parser.parse(
        '<#0>\n' +
        ' <http://www.w3.org/ns/auth/acl#accessTo> <http://example.tld/example.ttl>;\n' +
        ' <http://www.w3.org/ns/auth/acl#origin> <http://origin.tld>;\n' +
        ' <http://www.w3.org/ns/auth/acl#mode> <http://www.w3.org/ns/auth/acl#Read>, <http://www.w3.org/ns/auth/acl#Write> .\n',
        function (err, graph) {
          store.add('http://example.tld/example.ttl.acl', graph, function (err, graph) {
            acl.can(user1, 'Read', 'http://example.tld/example.ttl', function (err) {
              assert.ok(err)
              done()
            })
          })
        })
    })
  })

  describe('Resource ACL file is present', function () {
    it('should always allow on foaf:Agent (public)', function (done) {
      var store = new InMemoryStore()
      var acl = new ACL({
        store: store,
        suffix: '.acl'
      })
      N3Parser.parse(
        '<#0>\n' +
        ' <http://www.w3.org/ns/auth/acl#accessTo> <http://example.tld/example.ttl>;\n' +
        ' <http://www.w3.org/ns/auth/acl#agentClass> <http://xmlns.com/foaf/0.1/Agent>;\n' +
        ' <http://www.w3.org/ns/auth/acl#mode> <http://www.w3.org/ns/auth/acl#Write> .\n',
        function (err, graph) {
          store.add('http://example.tld/example.ttl.acl', graph, function () {
            acl.can(user1, 'Write', 'http://example.tld/example.ttl', function (err) {
              assert.notOk(err)
              done()
            })
          })
        })
    })
    it('should look for a defaultForNew if ACL is empty', function (done) {
      var store = new InMemoryStore()
      var acl = new ACL({
        store: store,
        suffix: '.acl'
      })
      N3Parser.parse(
        '<#0>\n' +
        ' <http://www.w3.org/ns/auth/acl#defaultForNew> <http://example.tld/>;\n' +
        ' <http://www.w3.org/ns/auth/acl#agent> <' + user1 + '>;\n' +
        ' <http://www.w3.org/ns/auth/acl#mode> <http://www.w3.org/ns/auth/acl#Write> .\n',
        function (err, graph) {
          store.add('http://example.tld/.acl', graph, function () {
            N3Parser.parse('', function (err, graph) {
              store.add('http://example.tld/example.ttl.acl', graph, function () {
                acl.can(user1, 'Write', 'http://example.tld/example.ttl', function (err) {
                  assert.notOk(err)
                  done()
                })
              })
            })
          })
        })
    })

    it('should not "Read"/"Write"/"Append" if no valid policy is found', function (done) {
      var store = new InMemoryStore()
      var acl = new ACL({
        store: store,
        suffix: '.acl'
      })
      N3Parser.parse(
        '<#0>\n' +
        ' <http://www.w3.org/ns/auth/acl#accessTo> <http://example.tld/example.ttl>;\n' +
        ' <http://www.w3.org/ns/auth/acl#agent> <' + user1 + '>;\n' +
        ' <http://www.w3.org/ns/auth/acl#mode> <http://www.w3.org/ns/auth/acl#Write> .\n',
        function (err, graph) {
          store.add('http://example.tld/example.ttl.acl', graph, function (err, graph) {
            acl.can(user1, 'Read', 'http://example.tld/example.ttl', function (err) {
              assert.ok(err)
              done()
            })
          })
        })
    })

    it('should "Read"/"Write"/"Control"/"Append" if Agent is matched', function (done) {
      var store = new InMemoryStore()
      var acl = new ACL({
        store: store,
        suffix: '.acl'
      })
      N3Parser.parse(
        '<#0>\n' +
        ' <http://www.w3.org/ns/auth/acl#accessTo> <http://example.tld/example.ttl>;\n' +
        ' <http://www.w3.org/ns/auth/acl#agent> <' + user1 + '>;\n' +
        ' <http://www.w3.org/ns/auth/acl#mode> <http://www.w3.org/ns/auth/acl#Read> .\n',
        function (err, graph) {
          store.add('http://example.tld/example.ttl.acl', graph, function (err, graph) {

            async.waterfall([
              function (next) {
                acl.can(user1, 'Read', 'http://example.tld/example.ttl', function (err) {
                  assert.notOk(err)
                  next()
                })
              },
              function (next) {
                acl.can(user2, 'Read', 'http://example.tld/example.ttl', function (err) {
                  assert.ok(err)
                  next()
                })
              }
            ], done)

          })
        })
    })

    it('should "Append" if "Write" is granted', function (done) {
      var store = new InMemoryStore()
      var acl = new ACL({
        store: store,
        suffix: '.acl'
      })
      N3Parser.parse(
        '<#0>\n' +
        ' <http://www.w3.org/ns/auth/acl#accessTo> <http://example.tld/example.ttl>;\n' +
        ' <http://www.w3.org/ns/auth/acl#agent> <' + user1 + '>;\n' +
        ' <http://www.w3.org/ns/auth/acl#mode> <http://www.w3.org/ns/auth/acl#Write> .\n',
        function (err, graph) {
          store.add('http://example.tld/example.ttl.acl', graph, function (err, graph) {
            acl.can(user1, 'Append', 'http://example.tld/example.ttl', function (err) {
              assert.notOk(err)
              done()
            })
          })
        })
    })
  })

  describe('Parent ACL resource', function () {

    it('should always allow on foaf:Agent (public) on defaultForNew', function (done) {
      var store = new InMemoryStore()
      var acl = new ACL({
        store: store,
        suffix: '.acl'
      })
      N3Parser.parse(
        '<#0>\n' +
        ' <http://www.w3.org/ns/auth/acl#defaultForNew> <http://example.tld/>;\n' +
        ' <http://www.w3.org/ns/auth/acl#agentClass> <http://xmlns.com/foaf/0.1/Agent>;\n' +
        ' <http://www.w3.org/ns/auth/acl#mode> <http://www.w3.org/ns/auth/acl#Write> .\n',
        function (err, graph) {
          store.add('http://example.tld/.acl', graph, function () {
            N3Parser.parse('', function (err, graph) {
              store.add('http://example.tld/example.ttl.acl', graph, function () {
                acl.can(user1, 'Write', 'http://example.tld/example.ttl', function (err) {
                  assert.notOk(err)
                  done()
                })
              })
            })
          })
        })
    })

    it('should "Read"/"Write"/"Append"/"Control" if specified on defaultForNew', function (done) {
      var store = new InMemoryStore()
      var acl = new ACL({
        store: store,
        suffix: '.acl'
      })
      N3Parser.parse(
        '<#0>\n' +
        ' <http://www.w3.org/ns/auth/acl#defaultForNew> <http://example.tld/>;\n' +
        ' <http://www.w3.org/ns/auth/acl#agent> <' + user1 + '>;\n' +
        ' <http://www.w3.org/ns/auth/acl#mode> <http://www.w3.org/ns/auth/acl#Read> .\n' +
        '<#1>\n' +
        ' <http://www.w3.org/ns/auth/acl#defaultForNew> <http://example.tld/>;\n' +
        ' <http://www.w3.org/ns/auth/acl#agent> <' + user2 + '>;\n' +
        ' <http://www.w3.org/ns/auth/acl#mode> <http://www.w3.org/ns/auth/acl#Read>, <http://www.w3.org/ns/auth/acl#Write>, <http://www.w3.org/ns/auth/acl#Control> .\n',
        function (err, graph) {
          store.add('http://example.tld/.acl', graph, function (err, graph) {

            async.waterfall([
              // User 1
              function (next) {
                acl.can(user1, 'Append', 'http://example.tld/example.ttl', function (err) {
                  assert.ok(err)
                  done()
                })
              },
              function (next) {
                acl.can(user1, 'Write', 'http://example.tld/example.ttl', function (err) {
                  assert.ok(err)
                  done()
                })
              },
              function (next) {
                acl.can(user1, 'Read', 'http://example.tld/example.ttl', function (err) {
                  assert.notOk(err)
                  done()
                })
              },
              function (next) {
                acl.can(user1, 'Control', 'http://example.tld/example.ttl', function (err) {
                  assert.ok(err)
                  done()
                })
              },
              // User 2
              function (next) {
                acl.can(user2, 'Append', 'http://example.tld/example.ttl', function (err) {
                  assert.notOk(err)
                  done()
                })
              },
              function (next) {
                acl.can(user2, 'Write', 'http://example.tld/example.ttl', function (err) {
                  assert.notOk(err)
                  done()
                })
              },
              function (next) {
                acl.can(user2, 'Read', 'http://example.tld/example.ttl', function (err) {
                  assert.notOk(err)
                  done()
                })
              },
              function (next) {
                acl.can(user2, 'Control', 'http://example.tld/example.ttl', function (err) {
                  assert.notOk(err)
                  done()
                })
              }], done)
          })
        })
    })

    it('should "Append" when only "Write" is granted in defaultForNew', function (done) {
      var store = new InMemoryStore()
      var acl = new ACL({
        store: store,
        suffix: '.acl'
      })
      N3Parser.parse(
        '<#0>\n' +
        ' <http://www.w3.org/ns/auth/acl#defaultForNew> <http://example.tld/>;\n' +
        ' <http://www.w3.org/ns/auth/acl#agent> <' + user1 + '>;\n' +
        ' <http://www.w3.org/ns/auth/acl#mode> <http://www.w3.org/ns/auth/acl#Write> .\n',
        function (err, graph) {
          store.add('http://example.tld/.acl', graph, function (err, graph) {
            acl.can(user1, 'Append', 'http://example.tld/example.ttl', function (err) {
              assert.notOk(err)
              done()
            })
          })
        })
    })
  })

  describe('Controlling an ACL file', function () {

    it('should "Read"/"Write"/"Append" an ACL file that the user "Control"-s', function (done) {
      var store = new InMemoryStore()
      var acl = new ACL({
        store: store,
        suffix: '.acl'
      })
      N3Parser.parse(
        '<#0>\n' +
        ' <http://www.w3.org/ns/auth/acl#accessTo> <http://example.tld/example.ttl>;\n' +
        ' <http://www.w3.org/ns/auth/acl#agent> <' + user1 + '>;\n' +
        ' <http://www.w3.org/ns/auth/acl#mode> <http://www.w3.org/ns/auth/acl#Control> .\n',
        function (err, graph) {
          store.add('http://example.tld/example.ttl.acl', graph, function (err, graph) {
            async.waterfall([
              function (next) {
                acl.can(user1, 'Control', 'http://example.tld/example.ttl.acl', function (err) {
                  assert.notOk(err)
                  done()
                })
              },
              function (next) {
                acl.can(user1, 'Read', 'http://example.tld/example.ttl.acl', function (err) {
                  assert.notOk(err)
                  done()
                })
              },
              function (next) {
                acl.can(user1, 'Write', 'http://example.tld/example.ttl.acl', function (err) {
                  assert.notOk(err)
                  done()
                })
              },
              function (next) {
                acl.can(user1, 'Append', 'http://example.tld/example.ttl.acl', function (err) {
                  assert.notOk(err)
                  done()
                })
              }], done)
          })
        })
    })

    it('should "Control" a new ACL file if "Control" is in defaultForNew', function (done) {
      var store = new InMemoryStore()
      var acl = new ACL({
        store: store,
        suffix: '.acl'
      })
      N3Parser.parse(
        '<#0>\n' +
        ' <http://www.w3.org/ns/auth/acl#defaultForNew> <http://example.tld/>;\n' +
        ' <http://www.w3.org/ns/auth/acl#agent> <' + user1 + '>;\n' +
        ' <http://www.w3.org/ns/auth/acl#mode> <http://www.w3.org/ns/auth/acl#Control> .\n',
        function (err, graph) {
          store.add('http://example.tld/.acl', graph, function (err, graph) {
            acl.can(user1, 'Write', 'http://example.tld/example.ttl.acl', function (err) {
              assert.notOk(err)
              done()
            })
          })
        })
    })
  })
})
