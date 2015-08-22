module.exports = ACL

var async = require('async')
var string = require('string')
var debug = require('debug')('solid:acl')

function ACL (rdf, opts) {
  var self = this
  opts = opts || {}
  self.suffix = opts.suffix || '.acl'
  opts.store = opts.store
}

function possibleACLs (uri, suffix) {
  var current = ''
  var uris = uri
    .split('/')
    .map(function (uri) {
      current += uri
      if (string(current).endsWith(suffix)) {
        return current
      }
      return current + suffix
    })
  return uris
}

ACL.prototype.find = function (user, mode, resource, callback) {
  var self = this
  var accessType = 'accessTo'
  var uris = possibleACLs(resource, self.suffix)

  async.eachSeries(
    uris,
    function (uri, done) {
      self.store.graph(uri, function (graph, err) {
        if (err) return done(err)

        self.findRule(graph, user, mode, accessType, uri, function (err, allowed) {
          accessType = 'defaultForNew'
          done(err || allowed)
        })
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

function getMode (graph, mode) {
  return graph
    .match(
      undefined,
      'http://www.w3.org/ns/auth/acl#mode',
      'http://www.w3.org/ns/auth/acl#' + mode)
    .toArray()
}

function getAccessType (graph, rule, accessType, uri) {
  return graph
    .match(
      rule,
      'http://www.w3.org/ns/auth/acl#' + accessType,
      uri)
    .toArray()
}

ACL.prototype.findModeRule = function (graph, user, accessType, mode, uri, callback) {
  var self = this
  var modeStatements = getMode(graph, mode)
  var controlStatements = getMode(graph, mode)
  var statements = controlStatements.concat(modeStatements)

  async.some(statements, function (statement, done) {
    var accesses = getAccessType(graph, statement, accessType, uri)

    async.some(accesses, function (access, found) {
      self.isAllowed(graph, user, mode, statement, found)
    }, done)

  }, callback)
}

ACL.prototype.isAllowed = function (graph, user, mode, uri, callback) {
  var self = this
  debug('In allow origin')

  // Owner statement
  var ownerStatements = graph
    .match(
      uri,
      'http://www.w3.org/ns/auth/acl#owner',
      user)

  if (ownerStatements.length) {
    debug(mode + ' access allowed (as owner) for: ' + user)
    return callback(true)
  }

  // Agent statement
  var agentStatements = graph
    .match(
      uri,
      'http://www.w3.org/ns/auth/acl#agent',
      user)

  if (agentStatements.length) {
    debug(mode + ' access allowed (as agent) for: ' + user)
    return callback(true)
  }

  // Agent class statement
  var agentClassStatements = graph
    .match(
      uri,
      'http://www.w3.org/ns/auth/acl#agentClass',
      undefined)

  if (agentClassStatements.length === 0) {
    return callback(false)
  }

  async.some(agentClassStatements, function (agentClassElem, found) {
    // Check for FOAF groups
    debug('Found agentClass policy')
    if (agentClassElem.sameTerm('http://xmlns.com/foaf/0.1/Agent')) {
      debug(mode + ' allowed access as FOAF agent')
      return found(true)
    }
    var groupURI = agentClassElem.subject.toString()

    self.store.graph(groupURI, function (err, groupGraph) {
      if (err) return found(err)
      // Type statement
      var typeStatements = groupGraph
        .match(
          agentClassElem,
          'http://www.w3.org/1999/02/22-rdf-syntax-ns#type',
          'http://xmlns.com/foaf/0.1/Group')

      if (groupGraph.statements.length > 0 && typeStatements.length > 0) {
        var memberStatements = groupGraph
          .match(
            agentClassElem,
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

ACL.prototype.findRule = function (graph, user, accessType, mode, uri, callback) {
  var self = this

  // TODO check if this is necessary
  if (graph.length === 0) {
    debug('No policies found in ' + uri)
    return callback(null, false)
  }

  debug('Found policies in ' + uri)

  self.findModeRule(graph, mode, user, accessType, uri, function (found) {

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
