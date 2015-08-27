var ACL = require('../')
var rdf = require('rdf-ext')()
var InMemoryStore = require('rdf-store-inmemory')
var assert = require('chai').assert

describe('ACL Class', function () {
  var store = new InMemoryStore(rdf)

  var user1 = "https://user1.databox.me/profile/card#me";
  var user2 = "https://user2.databox.me/profile/card#me";
  var address = 'https://server.tld/test';

  describe('can', function () {
    it('should report a 404 error if no acl is found', function (done) {
      var acl = new ACL(store, {
        suffix: '.acl'
      });

      acl.can(user1, 'Read', 'example.ttl', function (err) {
        assert.ok(err)
        assert.equal(err.status, 404)
        done()
      })
    })
  })
})


    //     it('should report a 404 error if .acl cannot be parsed', function (done) {
    //         var acl = new ACL({
    //             ldp: ldp,
    //             origin: 'https://example.com',
    //             session: {
    //                 userId: user1,
    //                 identified: true
    //             },
    //             uri: address
    //         });
    //         write(
    //             "<#Owner>\n" +
    //             " <http://www.w3.org/ns/auth/acl#accessTo> <" +
    //                 address + "/" + ">, <" + address + ">;\n" +
    //             " XXXXXXXhttp://www.w3.org/ns/auth/acl#owner> <" + user1 + ">;\n" +
    //             " <http://www.w3.org/ns/auth/acl#mode> <http://www.w3.org/ns/auth/acl#Control> .\n",
    //             '.acl');

    //         acl.readACL(__dirname + '/resources/.acl', address, function (err, res) {
    //             rm('.acl');
    //             assert.equal(err.status, 500);
    //             assert.notOk(res);
    //             done();
    //         });
    //     });

    //     it('should return a parsed graph of the acl on success', function (done) {
    //         var acl = new ACL({
    //             ldp: ldp,
    //             origin: 'https://example.com',
    //             session: {
    //                 userId: user1,
    //                 identified: true
    //             },
    //             uri: address
    //         });
    //         write(
    //             "<#Owner>\n" +
    //             " <http://www.w3.org/ns/auth/acl#accessTo> <" +
    //                 address + "/" + ">, <" + address + ">;\n" +
    //             " <http://www.w3.org/ns/auth/acl#owner> <" + user1 + ">;\n" +
    //             " <http://www.w3.org/ns/auth/acl#mode> <http://www.w3.org/ns/auth/acl#Control> .\n",
    //             '.acl');

    //         acl.readACL(__dirname + '/resources/.acl', address, function (err, graph) {
    //             rm('.acl');
    //             assert.notOk(err);
    //             assert.ok(graph);
    //             done();
    //         });
    //     });

    //     it('should return a graph on empty ACL', function (done) {
    //         var acl = new ACL({
    //             ldp: ldp,
    //             origin: 'https://example.com',
    //             session: {
    //                 userId: user1,
    //                 identified: true
    //             },
    //             uri: address
    //         });
    //         write(
    //             "\n",
    //             '.acl');

    //         acl.readACL(__dirname + '/resources/.acl', address, function (err, graph) {
    //             rm('.acl');
    //             assert.notOk(err);
    //             assert.ok(graph);
    //             done();
    //         });
    //     });


    // });

    // describe('findACLInPath', function () {
    //     it('should allow user when permission is found in pathAcl/pathUri', function(done) {
    //         var acl = new ACL({
    //             ldp: ldp,
    //             origin: 'https://example.com',
    //             session: {
    //                 userId: user1,
    //                 identified: true
    //             },
    //             uri: address
    //         });

    //         write(
    //             "<#Owner>\n" +
    //             " <http://www.w3.org/ns/auth/acl#accessTo> <" +
    //                 address + "/" + ">, <" + address + ">;\n" +
    //             " <http://www.w3.org/ns/auth/acl#owner> <" + user1 + ">;\n" +
    //             " <http://www.w3.org/ns/auth/acl#mode> <http://www.w3.org/ns/auth/acl#Control> .\n",
    //             '.acl');

    //         acl.readACL(__dirname + '/resources/.acl', address, function (err, aclGraph) {
    //             async.parallel([
    //                 function(next) {
    //                     acl.findACLinPath('Read', __dirname + '/resources/.acl', address, aclGraph, 'accessTo', user1, function (err, result) {
    //                         assert.equal(result, true);
    //                         assert.notOk(err);
    //                         next();
    //                     });
    //                 },
    //                 function(next) {
    //                     acl.findACLinPath('Write', __dirname + '/resources/.acl', address, aclGraph, 'accessTo', user1, function (err, result) {
    //                         assert.equal(result, true);
    //                         assert.notOk(err);
    //                         next();
    //                     });
    //                 },
    //                 function(next) {
    //                     acl.findACLinPath('Append', __dirname + '/resources/.acl', address, aclGraph, 'accessTo', user1, function (err, result) {
    //                         assert.equal(result, true);
    //                         assert.notOk(err);
    //                         next();
    //                     });
    //                 }
    //             ], function(err) {
    //                 rm('.acl');
    //                 done(err);
    //             });
    //         });
    //     });

    //     it('should return 403 if user is not authorized', function(done) {
    //         var acl = new ACL({
    //             ldp: ldp,
    //             origin: 'https://example.com',
    //             session: {
    //                 userId: user1,
    //                 identified: true
    //             },
    //             uri: address
    //         });

    //         write(
    //             "<#Owner>\n" +
    //             " <http://www.w3.org/ns/auth/acl#accessTo> <" +
    //                 address + "/" + ">, <" + address + ">;\n" +
    //             " <http://www.w3.org/ns/auth/acl#owner> <" + user2 + ">;\n" +
    //             " <http://www.w3.org/ns/auth/acl#mode> <http://www.w3.org/ns/auth/acl#Control> .\n",
    //             '.acl');

    //         acl.readACL(__dirname + '/resources/.acl', address, function (err, aclGraph) {
    //             async.parallel([
    //                 function(next) {
    //                     acl.findACLinPath('Read', __dirname + '/resources/.acl', address, aclGraph, 'accessTo', user1, function (err, result) {
    //                         assert.equal(err.status, 403);
    //                         assert.notOk(result);
    //                         next();
    //                     });
    //                 },
    //                 function(next) {
    //                     acl.findACLinPath('Write', __dirname + '/resources/.acl', address, aclGraph, 'accessTo', user1, function (err, result) {
    //                         assert.equal(err.status, 403);
    //                         assert.notOk(result);
    //                         next();
    //                     });
    //                 },
    //                 function(next) {
    //                     acl.findACLinPath('Append', __dirname + '/resources/.acl', address, aclGraph, 'accessTo', user1, function (err, result) {
    //                         assert.equal(err.status, 403);
    //                         assert.notOk(result);
    //                         next();
    //                     });
    //                 }
    //             ], function(err) {
    //                 rm('.acl');
    //                 done(err);
    //             });
    //         });
    //     });
    //     it('should return 401 if user is not authenticated', function(done) {
    //         var acl = new ACL({
    //             ldp: ldp,
    //             origin: 'https://example.com',
    //             uri: address
    //         });

    //         write(
    //             "<#Owner>\n" +
    //             " <http://www.w3.org/ns/auth/acl#accessTo> <" +
    //                 address + "/" + ">, <" + address + ">;\n" +
    //             " <http://www.w3.org/ns/auth/acl#owner> <" + user2 + ">;\n" +
    //             " <http://www.w3.org/ns/auth/acl#mode> <http://www.w3.org/ns/auth/acl#Control> .\n",
    //             '.acl');

    //         acl.readACL(__dirname + '/resources/.acl', address, function (err, aclGraph) {
    //             async.parallel([
    //                 function(next) {
    //                     acl.findACLinPath('Read', __dirname + '/resources/.acl', address, aclGraph, 'accessTo', user1, function (err, result) {
    //                         assert.equal(err.status, 401);
    //                         assert.notOk(result);
    //                         next();
    //                     });
    //                 },
    //                 function(next) {
    //                     acl.findACLinPath('Write', __dirname + '/resources/.acl', address, aclGraph, 'accessTo', user1, function (err, result) {
    //                         assert.equal(err.status, 401);
    //                         assert.notOk(result);
    //                         next();
    //                     });
    //                 },
    //                 function(next) {
    //                     acl.findACLinPath('Append', __dirname + '/resources/.acl', address, aclGraph, 'accessTo', user1, function (err, result) {
    //                         assert.equal(err.status, 401);
    //                         assert.notOk(result);
    //                         next();
    //                     });
    //                 }
    //             ], function(err) {
    //                 rm('.acl');
    //                 done(err);
    //             });
    //         });
    //     });

    //     it('should report that ACL has not been found if aclGraph is empty', function(done) {
    //         var acl = new ACL({
    //             ldp: ldp
    //         });

    //         acl.findACLinPath('Read', __dirname + '/resources/.acl', address, $rdf.graph(), 'accessTo', user1, function (err, result) {
    //             assert.notOk(err);
    //             assert.equal(result, false);
    //             done();
    //         });
    //     });
    // });

    // describe('findACL', function () {
    //     it('should return no error if permission is found', function (done) {
    //         var acl = new ACL({
    //             ldp: ldp,
    //             origin: 'https://example.com',
    //             session: {
    //                 userId: user1,
    //                 identified: true
    //             },
    //             uri: address
    //         });

    //         write(
    //             "<#Owner>\n" +
    //             " <http://www.w3.org/ns/auth/acl#accessTo> <" +
    //                 address + "/" + ">, <" + address + ">;\n" +
    //             " <http://www.w3.org/ns/auth/acl#owner> <" + user1 + ">;\n" +
    //             " <http://www.w3.org/ns/auth/acl#mode> <http://www.w3.org/ns/auth/acl#Read> .\n",
    //             '.acl');

    //         acl.findACL('Read', '/', user1, function (err) {
    //             rm('.acl');
    //             assert.notOk(err);
    //             done();
    //         });
    //     });

    //     it('should return error error if user is allowed to `Read` but not to `Write`', function (done) {
    //         var acl = new ACL({
    //             ldp: ldp,
    //             origin: 'https://example.com',
    //             session: {
    //                 userId: user1,
    //                 identified: true
    //             },
    //             uri: address
    //         });

    //         write(
    //             "<#Owner>\n" +
    //             " <http://www.w3.org/ns/auth/acl#accessTo> <" +
    //                 address + "/" + ">, <" + address + ">;\n" +
    //             " <http://www.w3.org/ns/auth/acl#owner> <" + user1 + ">;\n" +
    //             " <http://www.w3.org/ns/auth/acl#mode> <http://www.w3.org/ns/auth/acl#Read> .\n",
    //             '.acl');

    //         acl.findACL('Write', '/', user1, function (err) {
    //             rm('.acl');
    //             assert.equal(err.status, 403);
    //             done();
    //         });
    //     });

    //     it('should return error 403 if user is not allowed', function (done) {
    //         var acl = new ACL({
    //             ldp: ldp,
    //             origin: 'https://example.com',
    //             session: {
    //                 userId: user1,
    //                 identified: true
    //             },
    //             uri: address
    //         });

    //         write(
    //             "<#Owner>\n" +
    //             " <http://www.w3.org/ns/auth/acl#accessTo> <" +
    //                 address + "/" + ">, <" + address + ">;\n" +
    //             " <http://www.w3.org/ns/auth/acl#owner> <" + user2 + ">;\n" +
    //             " <http://www.w3.org/ns/auth/acl#mode> <http://www.w3.org/ns/auth/acl#Control> .\n",
    //             '.acl');

    //         acl.findACL('Control', '/', user1, function (err) {
    //             rm('.acl');
    //             assert.equal(err.status, 403);
    //             done();
    //         });
    //     });

    //     it('should return no error if no permission rule is found', function (done) {
    //         var acl = new ACL({
    //             ldp: ldp,
    //             origin: 'https://example.com',
    //             session: {
    //                 userId: user1,
    //                 identified: true
    //             },
    //             uri: address
    //         });

    //         write(
    //             '',
    //             '.acl');

    //         acl.findACL('Control', '/', user1, function (err) {
    //             rm('.acl');
    //             assert.notOk(err);
    //             done();
    //         });
    //     });
    // });

    // describe('getUserId', function () {
    //     it('should return userId in session if On-Behalf-Of is not specified', function(done) {
    //         var acl = new ACL({
    //             ldp: ldp,
    //             origin: 'https://example.com',
    //             session: {
    //                 userId: 'https://user1.databox.me/profile/card#me',
    //                 identified: true
    //             }
    //         });

    //         acl.getUserId(function(err, userId) {
    //             assert.equal(userId, 'https://user1.databox.me/profile/card#me');
    //             done(err);
    //         });
    //     });

    //     it('should return userId in session if On-Behalf-Of is not valid', function(done) {
    //         var acl = new ACL({
    //             ldp: ldp,
    //             origin: 'https://example.com',
    //             session: {
    //                 userId: user1,
    //                 identified: true
    //             },
    //             onBehalfOf: ''
    //         });

    //         acl.getUserId(function(err, userId) {
    //             assert.equal(userId, user1);
    //             done(err);
    //         });
    //     });
    //     // TODO
    //     // it('should return On-Behalf-Of if is the delegatee', function(done) {
    //     //     var acl = new ACL({
    //     //         ldp: ldp,
    //     //         origin: 'https://example.com',
    //     //         session: {
    //     //             userId: user2,
    //     //             identified: true
    //     //         },
    //     //         onBehalfOf: '<' + user1 + '>'
    //     //     });

    //     //     acl.getUserId(function(err, userId) {
    //     //         assert.equal(userId, user1);
    //     //         done(err);
    //     //     });
    //     // });
    // });

    // describe('verifyDelegator', function () {
    //     // TODO
    // });
