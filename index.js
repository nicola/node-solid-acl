module.exports = ACL

var async = require('async')
var debug = require('debug')('solid:acl')
var utils = require('./lib/utils')
var string = require('string')

function ACL (store, opts) {
  var self = this
  opts = opts || {}
  self.store = store
  self.suffix = opts.suffix || '.acl'
}

ACL.prototype.isAcl = function (resource) {
  return !!string(resource).endsWith(this.suffix)
}

ACL.prototype.can = function (user, mode, resource, callback, options) {
  var self = this
  var accessType = 'accessTo'
  var uris = utils.possibleACLs(resource, self.suffix)

  // If it is an ACL, only look for control this resource
  if (self.isAcl(resource)) {
    mode = 'Control'
  }

  async.eachSeries(
    uris,
    function (uri, done) {
      self.store.graph(uri, function (graph, err) {
        if (err || !graph) return done(null)

        self.findRule(graph, user, mode, accessType, uri, function (err, allowed) {
          accessType = 'defaultForNew'
          done(err ? null : allowed)
        }, options)
      })
    },
    function (err) {
      // result is false when no policy is found
      // result is true if ACL statement is found
      if (typeof err === 'boolean') {
        debug(err ?
          'No ACL policies present - access allowed' :
          'ACL allowed')
        err = null
      }
      return callback(err)
    })
}

ACL.prototype.findSubgraphRule = function (graph, user, mode, uri, callback) {
  var self = this

  // Owner statement
  var ownerStatements = graph.match(
    uri,
    'http://www.w3.org/ns/auth/acl#owner',
    user)

  if (ownerStatements.length) {
    debug(mode + ' access allowed (as owner) for: ' + user)
    return callback(true)
  }

  // Agent statement
  var agentStatements = graph.match(
    uri,
    'http://www.w3.org/ns/auth/acl#agent',
    user)

  if (agentStatements.length) {
    debug(mode + ' access allowed (as agent) for: ' + user)
    return callback(true)
  }

  // Agent class statement
  var agentClassStatements = graph.match(
    uri,
    'http://www.w3.org/ns/auth/acl#agentClass',
    undefined)

  if (agentClassStatements.length === 0) {
    return callback(false)
  }

  async.some(agentClassStatements.toArray(), function (agentClassTriple, found) {
    // Check for FOAF groups
    debug('Found agentClass policy')
    if (agentClassTriple.sameTerm('http://xmlns.com/foaf/0.1/Agent')) {
      debug(mode + ' allowed access as FOAF agent')
      return found(true)
    }
    var groupURI = agentClassTriple.subject.toString()

    self.store.graph(groupURI, function (err, groupGraph) {
      if (err) return found(err)
      // Type statement
      var typeStatements = groupGraph.match(
        '',
        'http://www.w3.org/1999/02/22-rdf-syntax-ns#type',
        'http://xmlns.com/foaf/0.1/Group')

      if (groupGraph.length > 0 && typeStatements.length > 0) {
        var memberStatements = groupGraph.match(
          agentClassTriple.object.toString(),
          'http://xmlns.com/foaf/0.1/member',
          user)

        if (memberStatements.length) {
          debug(user + ' listed as member of the group ' + groupURI)
          return found(true)
        }
      }
      return found(false)
    })
  }, callback)
}

ACL.prototype.findRule = function (graph, user, accessType, mode, uri, callback, options) {
  var self = this

  // TODO check if this is necessary
  if (graph.length === 0) {
    debug('No policies found in ' + uri)
    return callback(null, false)
  }

  debug('Found policies in ' + uri)

  var statements = utils.getMode(graph, mode)

  if (mode === 'Append') {
    statements = statements
      .concat(utils.getMode(graph, 'Write'))
  }

  async.some(
    statements,
    function (statement, done) {
      var accesses = utils.getAccessType(graph, statementSubject, accessType, uri)

      var statementSubject = statement.subject.toString()
      async.some(accesses, function (access, found) {
        var origins = graph
          .match(
            statementSubject,
            'http://www.w3.org/ns/auth/acl#origin',
            undefined)
          .toArray()

        if (self.origin.length > 0 && origins.length > 0) {
          async.some(origins, function (origin, done) {
            if (options.origin === origin) {
              debug('Found policy for origin: ' + origin)
              return self.findSubgraphRule(graph, user, mode, statementSubject, done)
            }
            return done(false)
          }, found)
        } else {
          debug('No origin found, moving on.')
          self.findSubgraphRule(graph, user, mode, statementSubject, found)
        }
      }, done)

    },
    function (found) {
      if (!found) {
        var err = new Error()
        if (!user || user.length === 0) {
          debug('Authentication required')
          err.status = 401
          err.message = 'Access to ' + uri + ' requires authorization'
        } else {
          debug(mode + ' access denied for: ' + user)
          err.status = 403
          err.message = 'Access denied for ' + user
        }
        return callback(err)
      }
      return callback(null, true)
    })
}
