// SPDX-License-Identifier: Apache-2.0
'use strict';

class XdiffError extends Error {
  constructor(code, message, detail) {
    super(message);
    this.name = 'XdiffError';
    this.code = code;
    this.detail = detail || null;
  }
}

class ConfigError extends XdiffError {
  constructor(message, detail) { super('E_CONFIG', message, detail); this.name = 'ConfigError'; }
}

class UsageError extends XdiffError {
  constructor(message, detail) { super('E_USAGE', message, detail); this.name = 'UsageError'; }
}

class ImplError extends XdiffError {
  constructor(message, detail) { super('E_IMPL', message, detail); this.name = 'ImplError'; }
}

/** 实现不可用（装不上 / 依赖缺失）与实现算错是两回事，分开表达。 */
class ImplUnavailable extends XdiffError {
  constructor(message, detail) { super('E_IMPL_UNAVAILABLE', message, detail); this.name = 'ImplUnavailable'; }
}

function toEnvelope(err) {
  if (err instanceof XdiffError) {
    return { error: { code: err.code, message: err.message, detail: err.detail } };
  }
  return { error: { code: 'E_INTERNAL', message: String(err && err.message ? err.message : err) } };
}

module.exports = { XdiffError, ConfigError, UsageError, ImplError, ImplUnavailable, toEnvelope };
