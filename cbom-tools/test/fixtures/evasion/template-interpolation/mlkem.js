// Negative control 3: template literal with a literal interpolation.
const suite = `ml-kem-${'768'}`;

module.exports = async () => import('@noble/post-quantum/' + suite);
