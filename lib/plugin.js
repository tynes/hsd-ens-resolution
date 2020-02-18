/*!
 * plugin.js - ens resolution plugin for hsd
 * Copyright (c) 2020, Mark Tyneway (MIT License).
 * https://github.com/tynes/hsd-ens-resolution
 */

'use strict';

const EventEmitter = require('events');
const RecursiveServer = require('./recursive');

/**
 * @exports wallet/plugin
 */

const plugin = exports;

/**
 * Plugin
 * @extends EventEmitter
 */

class Plugin extends EventEmitter {
  /**
   * Create a plugin.
   * @constructor
   * @param {Node} node
   */

  constructor(node) {
    super();

    this.node = node;
    this.network = node.network;
    this.logger = node.logger;

    node.rs = new RecursiveServer({
      logger: this.node.logger,
      key: this.node.identityKey,
      host: this.node.config.str('rs-host'),
      port: this.node.config.uint('rs-port', this.network.rsPort),
      stubHost: this.node.ns.host,
      stubPort: this.node.ns.port,
      noUnbound: this.node.config.bool('rs-no-unbound'),
      ethurl: node.config.str('ethurl')
    });

    this.init();
  }

  init() {
    this.node.rs.on('error', err => this.emit('error', err));
  }

  async open() {
    ;
  }

  async close() {
    ;
  }
}

/**
 * Plugin name.
 * @const {String}
 */

plugin.id = 'ens-resolution';

/**
 * Plugin initialization.
 * @param {Node} node
 * @returns {WalletDB}
 */

plugin.init = function init(node) {
  return new Plugin(node);
};
