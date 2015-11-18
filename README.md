# solid-acl

Access Control List, the solid way

## Install

```
$ npm install --save solid-acl
```

## Usage


```javascript
var ACL = require('solid-acl')
var rdf = require('rdf-ext')
var FsStore = require('rdf-store-fs')

var store = new FsStore(rdf)
var acl = new ACL(rdf, store)

acl.allow(user, mode, resource, callback)
```

## Strategies

### AppendAcl

This is the default strategy. The idea is that each file `x` has an associated `x.acl` (where `.acl` can be specified in the options `suffix`).

The algorithm is the following:

```
can(user, mode, resource, options):
  acls = list possible acl paths
  // e.g.
  // http://foo.com/bar/yolo.acl
  // http://foo.com/bar/.acl
  // http://foo.com/.acl
  
  accessType = 'accessTo'
  for each acl path in acls:
    if acl file does not exist:
      // we look in the next acl that will be a parent path
      // and we look for defaultForNew presence
      accessType = 'defaultForNew'
      next
    
    policies = list policies in acl with mode == mode
    if mode == 'Append':
      policies = + list policies in acl with mode == 'Write'

    if policies in acl do not have accessTo the resource:
      return Error

    if options.origin is specified and acl does not have the same origin as the request the resource:
        return Error

    if acl has matching agent:
      return TRUE

    look for agentClass
    if agentClass found:
        return TRUE

    // if we are here it means that the file exists but has no matching policy
    return Error
  
  // if we are here,
  // it means no ACL file has been found
  return TRUE
```


## License

MIT
