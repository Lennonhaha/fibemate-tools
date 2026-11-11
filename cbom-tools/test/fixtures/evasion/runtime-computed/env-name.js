// Known limitation: the name only exists at runtime.
const name = process.env.CRYPTO_SUITE_NAME;

module.exports = (crypto) => crypto.createHash(name).digest('hex');
