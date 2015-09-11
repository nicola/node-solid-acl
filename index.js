module.exports = ACL

var async = require('async')
var debug = require('debug')('solid:acl')
var utils = require('./lib/utils')
var string = require('string')
var $rdf = require('rdflib')

function ACL (opts) {
  var self = this
  opts = opts || {}
  self.fetch = opts.store ? opts.store.graph : opts.fetch
  self.suffix = opts.suffix || '.acl'
}

ACL.prototype.isAcl = function (resource) {
  return !!string(resource).endsWith(this.suffix)
}

ACL.prototype.can = function (user, mode, resource, callback, options) {
  var self = this
  var accessType = 'accessTo'
  var acls = utils.possibleACLs(resource, self.suffix)
  options = options || {}

  // If it is an ACL, only look for control this resource
  if (self.isAcl(resource)) {
    mode = 'Control'
  }

  async.eachSeries(
    acls,
    // Looks for ACL, if found, looks for a rule
    function (acl, next) {

      // Let's see if there is a file..
      self.fetch(acl, function (graph, err) {
        if (err || !graph) {
          // If no file is found and we want to Control,
          // we should not be able to do that!
          // Control is only to Read and Write the current file!
          if (mode === 'Control') {
            return next(new Error("You can't Control an unexisting file"))
          }
          accessType = 'defaultForNew'
          return next()
        }
        self.findRule(
          graph, // The ACL graph
          user, // The webId of the user
          mode, // Read/Write/Append
          resource, // The resource we want to access
          accessType, // accessTo or defaultForNew
          acl, // The current Acl file!
          function (err, allowed) {
          return next(allowed || err)
        }, options)
      })
    },
    function (err) {
      if (err === false) {
        debug('No ACL resource found - access allowed')
      }

      if (err === true) {
        debug('ACL policy found')
        err = null
      }

      return callback(err)
    })
}

ACL.prototype.findAgentClass = function (graph, user, mode, resource, acl, callback) {
  var self = this

  // Agent class statement
  var agentClassStatements = graph.match(
    resource,
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

    var agentClassURI = agentClassTriple.subject.toString()
    self.fetch(agentClassURI, function (err, groupGraph) {
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
          debug(user + ' listed as member of the group ' + agentClassURI)
          return found(true)
        }
      }
      return found(false)
    })
  }, callback)
}

ACL.prototype.findRule = function (graph, user, mode, resource, accessType, acl, callback, options) {
  var self = this

  // TODO check if this is necessary
  if (graph.length === 0) {
    debug('ACL ' + acl + ' is empty')
    return callback(new Error('No policy found'))
  }

  debug('Found policies in ' + acl)

  // Check for mode
  var statements = utils.getMode(graph, mode)
  if (mode === 'Append') {
    statements = statements
      .concat(utils.getMode(graph, 'Write'))
  }

  async.some(
    statements,
    function (statement, done) {
      var statementSubject = statement.subject.toString()

      // Check for origin
      var matchOrigin = utils.matchOrigin(graph, statementSubject, options.origin)
      if (!matchOrigin) {
        return done(false)
      }

      // Check for accessTo/defaultForNew
      var accesses = utils.getAccessType(graph, statementSubject, accessType, resource)
      if (!accesses.length) {
        return done(false)
      }

      // Check for Agent
      var agentStatements = graph.match(
        statementSubject,
        'http://www.w3.org/ns/auth/acl#agent',
        user)
      if (agentStatements.length) {
        debug(mode + ' access allowed (as agent) for: ' + user)
        return done(true)
      }

      // Check for AgentClass
      return self.findAgentClass(graph, user, mode, resource, statementSubject, done)
    },
    function (found) {
      if (!found) {
        var err = new Error()
        if (!user || user.length === 0) {
          debug('Authentication required')
          err.status = 401
          err.message = 'Access to ' + resource + ' requires authorization'
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
