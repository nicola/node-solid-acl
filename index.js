module.exports = ACL

var async = require('async')
var debug = require('debug')('solid:acl')
var utils = require('./lib/utils')
var string = require('string')
var path = require('path')

// This is the default match
// That follows RDF-Interfaces
function match(graph, s, p, o) {
  return graph.match(s, p, o).toArray()
}

function ACL (opts) {
  var self = this
  opts = opts || {}
  if (opts.store && opts.store.graph && !opts.fetch) {
    // This hack has to be kept until RDF-EXT changes its graph,
    // err callback style
    self.fetch = function (uri, callback, options) {
      opts.store.graph(uri, function(graph, err) {
        callback(err, graph)
      }, options)
    }
  }
  self.fetch = self.fetch || opts.fetch
  self.match = opts.match || match
  self.suffix = opts.suffix || '.acl'
}

ACL.prototype.isAcl = function (resource) {
  return !!string(resource).endsWith(this.suffix)
}

ACL.prototype.can = function (user, mode, resource, callback, options) {
  debug('Can ' + user + ' ' + mode + ' ' + resource + '?')
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
      debug('Check if acl exist: ' + acl)

      // Let's see if there is a file..
      self.fetch(acl, function (err, graph) {
        if (err || !graph || graph.length === 0) {
          // TODO
          // If no file is found and we want to Control,
          // we should not be able to do that!
          // Control is only to Read and Write the current file!
          // if (mode === 'Control') {
          //   return next(new Error("You can't Control an unexisting file"))
          // }
          if (err) debug('Error: ' + err)
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
          function (err) {
          return next(!err || err)
        }, options)
      })
    },
    function (err) {
      if (err === false || err === null) {
        debug('No ACL resource found - access allowed')
        err = new Error('No Access Control Policy found')
      }

      if (err === true) {
        debug('ACL policy found')
        err = null
      }

      if (err) {
        debug('Error: ' + err.message)
        if (!user || user.length === 0) {
          debug('Authentication required')
          err.status = 401
          err.message = 'Access to ' + resource + ' requires authorization'
        } else {
          debug(mode + ' access denied for: ' + user)
          err.status = 403
          err.message = 'Access denied for ' + user
        }
      }

      return callback(err)
    })
}

ACL.prototype.findAgentClass = function (graph, user, mode, resource, acl, callback) {
  var self = this

  // Agent class statement
  var agentClassStatements = self.match(
    graph,
    acl,
    'http://www.w3.org/ns/auth/acl#agentClass',
    undefined)

  if (agentClassStatements.length === 0) {
    return callback(false)
  }

  async.some(agentClassStatements, function (agentClassTriple, found) {
    // Check for FOAF groups
    debug('Found agentClass policy')
    if (agentClassTriple.object.toString() === 'http://xmlns.com/foaf/0.1/Agent') {
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
  var statements = self.getMode(graph, mode)
  if (mode === 'Append') {
    statements = statements
      .concat(self.getMode(graph, 'Write'))
  }

  async.some(
    statements,
    function (statement, done) {
      var statementSubject = statement.subject.toString()

      // Check for origin
      var matchOrigin = self.matchOrigin(graph, statementSubject, options.origin)
      if (!matchOrigin) {
        debug('The request does not match the origin')
        return done(false)
      }

      // Check for accessTo/defaultForNew
      if (!self.isAcl(resource) || accessType === 'defaultForNew') {
        debug('Checking for accessType:' + accessType)
        var accesses = self.getAccessType(graph, statementSubject, accessType, resource)
        if (!accesses.length) {
          debug('Cannot find accessType ' + accessType)
          return done(false)
        }
      }

      // Check for Agent
      var agentStatements = self.match(
        graph,
        statementSubject,
        'http://www.w3.org/ns/auth/acl#agent',
        user)

      if (agentStatements.length) {
        debug(mode + ' access allowed (as agent) for: ' + user)
        return done(true)
      }

      debug('Inspect agentClass')
      // Check for AgentClass
      return self.findAgentClass(graph, user, mode, resource, statementSubject, done)
    },
    function (found) {
      if (!found) {
        return callback(new Error('Acl found but policy not found'))
      }
      return callback(null)
    })
}

// TODO maybe these functions can be integrated in the code
ACL.prototype.getMode = function getMode (graph, mode) {
  var self = this
  return self.match(
    graph,
    undefined,
    'http://www.w3.org/ns/auth/acl#mode',
    'http://www.w3.org/ns/auth/acl#' + mode)
}

ACL.prototype.getAccessType = function getAccessType (graph, rule, accessType, uri) {
  var self = this
  if (accessType === 'defaultForNew') {
    uri = path.dirname(uri) + '/'
  }
  return self.match(
    graph,
    rule,
    'http://www.w3.org/ns/auth/acl#' + accessType,
    uri)

}

ACL.prototype.matchOrigin = function getOrigins (graph, rule, origin) {
  var self = this
  var origins = self.match(
    graph,
    rule,
    'http://www.w3.org/ns/auth/acl#origin',
    undefined)

  if (origins.length) {
    return origins.some(function (triple) {
      return triple.object.toString() === origin
    })
  }

  return true
}
