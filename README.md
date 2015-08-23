# solid-acl

Access Control List, the solid way

## Install

```
$ npm install --save solid-acl
```

## Usage


```javascript
var ACL = require('solid-acl')
var rdf = require('rdf-ext')()
var FsStore = require('rdf-store-fs')

var store = new FsStore(rdf)
var acl = new ACL(rdf, store)

acl.allow(user, mode, resource, callback)
```

## License

MIT