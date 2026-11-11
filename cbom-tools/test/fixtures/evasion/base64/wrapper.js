// Negative control 4: the name is a base64 payload.
const algorithm = Buffer.from('bWwta2VtLTc2OA==', 'base64').toString('utf8');

module.exports = { algorithm };
