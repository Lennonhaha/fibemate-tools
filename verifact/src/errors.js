'use strict';
// SPDX-License-Identifier: Apache-2.0

/**
 * 类型化错误体系。客户端（CLI / HTTP）只看到 code + message + details，
 * 绝不泄漏堆栈或内部路径细节。
 */
class VerifactError extends Error {
  constructor(code, message, details) {
    super(message);
    this.name = 'VerifactError';
    this.code = code;
    this.details = details || {};
  }
  toJSON() {
    const out = { error: this.code, message: this.message };
    if (Object.keys(this.details).length) out.details = this.details;
    return out;
  }
}

class ConfigError extends VerifactError {
  constructor(message, details) { super('config_error', message, details); }
}
class UsageError extends VerifactError {
  constructor(message, details) { super('usage_error', message, details); }
}
class ResolveError extends VerifactError {
  constructor(message, details) { super('resolve_error', message, details); }
}
class GateError extends VerifactError {
  constructor(message, details) { super('gate_failed', message, details); }
}

module.exports = { VerifactError, ConfigError, UsageError, ResolveError, GateError };
