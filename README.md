# hsd-ens-resolution

Resolve `.eth` names using the `hsd` DNS resolver.

### Usage

Clone the repository, run `$ npm install` and then start
the Handshake node.

```bash
$ ./hsd --plugins <path/to/hsd-ens-resolution/lib/plugin.js> \
    --ethurl <uri of ethereum node>
```

This plugin overwrites the `FullNode` recursive server
and hijacks any `.eth` request and sends the request via
RPC to the Ethereum node.

Do not use this in production, it was built at ETHDenver 2020
as a proof of concept.
