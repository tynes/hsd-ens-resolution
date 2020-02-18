/*!
 * recursive.js - recursive dns server for hsd
 * Copyright (c) 2020, Mark Tyneway (MIT License).
 * Copyright (c) 2017-2020, Christopher Jeffrey (MIT License).
 * https://github.com/handshake-org/hsd
 */

'use strict';

const assert = require('bsert');
const IP = require('binet');
const Logger = require('blgr');
const bns = require('bns');
const UnboundResolver = require('bns/lib/resolver/unbound');
const RecursiveResolver = require('bns/lib/resolver/recursive');
const secp256k1 = require('bcrypto/lib/secp256k1');
const LRU = require('blru');
const key = require('hsd/lib/dns/key');
const EthClient = require('ens-ethclient/lib/client');

const {
  DNSServer,
  hsig,
  util,
  wire
} = bns;

const {
  Message,
  Record,
  TXTRecord,
  opcodes,
  types
} = wire;

const RES_OPT = { inet6: false, tcp: true };

/**
 * ENSCache
 */

class ENSCache {
  constructor(size) {
    this.cache = new LRU(size);
  }

  set(name, type, msg) {
    const key = toKey(name, type);
    const raw = msg.compress();

    this.cache.set(key, {
      time: Date.now(),
      raw
    });

    return this;
  }

  get(name, type) {
    const key = toKey(name, type);
    const item = this.cache.get(key);

    if (!item)
      return null;

    if (Date.now() > item.time + 6 * 60 * 60 * 1000)
      return null;

    return Message.decode(item.raw);
  }
}

/**
 * RecursiveServer
 * @extends {DNSServer}
 */

class RecursiveServer extends DNSServer {
  constructor(options) {
    super(RES_OPT);

    this.ra = true;
    this.edns = true;
    this.dnssec = true;
    this.noAny = true;

    this.logger = Logger.global;
    this.key = secp256k1.privateKeyGenerate();

    this.host = '127.0.0.1';
    this.port = 5301;
    this.stubHost = '127.0.0.1';
    this.stubPort = 5300;

    this.cache = new ENSCache(500);
    this.ethurl = null;

    this.hns = new UnboundResolver({
      inet6: false,
      tcp: true,
      edns: true,
      dnssec: true,
      minimize: true
    });

    if (options)
      this.initOptions(options);

    this.ethClient = new EthClient({
      url: this.ethurl
    });

    this.initNode();

    this.hns.setStub(this.stubHost, this.stubPort, key.ds);
  }

  initOptions(options) {
    assert(options);

    this.parseOptions(options);

    if (options.logger != null) {
      assert(typeof options.logger === 'object');
      this.logger = options.logger.context('rs');
    }

    if (options.key != null) {
      assert(Buffer.isBuffer(options.key));
      assert(options.key.length === 32);
      this.key = options.key;
    }

    if (options.host != null) {
      assert(typeof options.host === 'string');
      this.host = IP.normalize(options.host);
    }

    if (options.port != null) {
      assert((options.port & 0xffff) === options.port);
      assert(options.port !== 0);
      this.port = options.port;
    }

    if (options.stubHost != null) {
      assert(typeof options.stubHost === 'string');

      this.stubHost = IP.normalize(options.stubHost);

      if (this.stubHost === '0.0.0.0' || this.stubHost === '::')
        this.stubHost = '127.0.0.1';
    }

    if (options.stubPort != null) {
      assert((options.stubPort & 0xffff) === options.stubPort);
      assert(options.stubPort !== 0);
      this.stubPort = options.stubPort;
    }

    if (options.noUnbound != null) {
      assert(typeof options.noUnbound === 'boolean');
      if (options.noUnbound) {
        this.hns = new RecursiveResolver({
          inet6: false,
          tcp: true,
          edns: true,
          dnssec: true,
          minimize: true
        });
      }
    }

    if (options.ethurl != null) {
      assert(typeof options.ethurl === 'string');
      this.ethurl = options.ethurl;
    }

    return this;
  }

  initNode() {
    this.hns.on('log', (...args) => {
      this.logger.debug(...args);
    });

    this.on('error', (err) => {
      this.logger.error(err);
    });

    this.on('query', (req, res) => {
      this.logMessage('DNS Request:', req);
      this.logMessage('DNS Response:', res);
    });

    return this;
  }

  logMessage(prefix, msg) {
    if (this.logger.level < 5)
      return;

    const logs = msg.toString().trim().split('\n');

    this.logger.spam(prefix);

    for (const log of logs)
      this.logger.spam(log);
  }

  signSize() {
    return 94;
  }

  sign(msg, host, port) {
    return hsig.sign(msg, this.key);
  }

  async open(...args) {
    await this.hns.open();

    await super.open(this.port, this.host);

    this.logger.info('Recursive server listening on port %d.', this.port);
  }

  async close() {
    await super.close();
    await this.hns.close();
  }

  async resolve(req, rinfo) {
    const [qs] = req.question;

    const labels = util.split(qs.name);
    const label = util.from(qs.name, labels, -1);

    // TODO(mark): this is a horrible hack but works
    // for a proof of concept
    if (label === 'eth.') {
      // Hit the cache first.
      const cache = this.cache.get(qs.name, types.TXT);

      if (cache)
        return cache;

      // resolveENS is sensitive to a trailing '.'
      const name = qs.name.slice(0, qs.name.length - 1);
      const res = await this.ethClient.resolveENS(name);

      if (!res) {
        // TODO: return NXDOMAIN
        // it currently errors and is caught by the node
      }

      // Render the TXT record data in OpenAlias format
      const data = ''
        + 'oa1:eth '
        + `recipient_address=${res}; `
        + `recipient_name=${name};`;

      const msg = new Message();
      msg.id = 0;
      msg.opcode = opcodes.QUERY;
      msg.ad = false; // not secure
      msg.question = [qs.clone()];
      msg.answer = [];

      const rr = new Record();
      const rd = new TXTRecord();
      rd.txt.push(data);

      rr.name = qs.name;
      rr.type = types.TXT;
      rr.ttl = 86000;
      rr.data = rd;

      msg.answer.push(rr);

      this.cache.set(qs.name, types.TXT, msg);

      return msg;
    }

    return this.hns.resolve(qs);
  }

  async lookup(name, type) {
    return this.hns.lookup(name, type);
  }
}

/*
 * Helpers
 */

function toKey(name, type) {
  let key = '';
  key += name.toLowerCase();
  key += ';';
  key += type.toString(10);

  return key;
}

module.exports = RecursiveServer;
