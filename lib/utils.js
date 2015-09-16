var string = require('string')
var url = require('url')
var path = require('path')

exports.possibleACLs = function possibleACLs (uri, suffix) {
  var first = string(uri).endsWith(suffix) ? uri : uri + '.acl'
  var urls = [first]
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
