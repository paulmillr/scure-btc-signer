export async function resolve(specifier, context, nextResolve) {
  const next = await nextResolve(specifier);
  // Very ugly hack to override dependency of 'micro-btc-signer' to use patched fork of noble-secp
  // with support of tiny-secp256k1 broken auxRand
  // Should be run as 'node --experimental-loader ./esm_loader.js index.test.js'
  if (specifier === '@noble/secp256k1') {
    const secp = import.meta.url.replace('esm-loader.js', 'noble-secp256k1-1.6.3-patched.js');
    return { url: secp, format: 'module' };
  }
  return next;
}
