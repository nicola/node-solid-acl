var string = require('string')

exports.possibleACLs = function possibleACLs (uri, suffix) {
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

exports.getMode = function getMode (graph, mode) {
  return graph.match(
    undefined,
    'http://www.w3.org/ns/auth/acl#mode',
    'http://www.w3.org/ns/auth/acl#' + mode)
  .toArray()
}

exports.getAccessType = function getAccessType (graph, rule, accessType, uri) {
  return graph.match(
    rule,
    'http://www.w3.org/ns/auth/acl#' + accessType,
    uri)
  .toArray()
}
