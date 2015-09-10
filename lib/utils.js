var string = require('string')
var url = require('url')
var path = require('path')

exports.possibleACLs = function possibleACLs (uri, suffix) {
  var urls = [uri + '.acl']
  var parsedUri = url.parse(uri)
  var baseUrl = (parsedUri.protocol ? parsedUri.protocol + '//' : '') + (parsedUri.host || '')

  if (baseUrl + '/' === uri) {
    return urls
  }

  var times = parsedUri.pathname.split('/').length
  for (var i = 0; i < times - 1; i++) {
    uri = path.dirname(uri)
    urls.push(uri + (uri[uri.length - 1] === '/' ? '.acl' : '/.acl'))
  }
  return urls
}

exports.getMode = function getMode (graph, mode) {
  return graph.match(
    undefined,
    'http://www.w3.org/ns/auth/acl#mode',
    'http://www.w3.org/ns/auth/acl#' + mode)
  .toArray()
}

exports.getAccessType = function getAccessType (graph, rule, accessType, uri) {

  console.log(graph.toString(), rule, accessType, uri)
  return graph.match(
    rule,
    'http://www.w3.org/ns/auth/acl#' + accessType,
    uri)
  .toArray()
}

exports.matchOrigin = function getOrigins (graph, rule, origin) {

  var origins = graph
    .match(
      rule,
      'http://www.w3.org/ns/auth/acl#origin',
      undefined)
    .toArray()

  if (origins.length) {
    return origins.some(function (triple) {
      return triple.object.toString() === origin
    })
  }

  return true
}
