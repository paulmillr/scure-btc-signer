import { hex } from '@scure/base';
import * as btc from '../../index.js';
// TODO: move to index.ts as compat layer for bitcoinjs-lib?
export function fromASM(asm) {
  const ops = asm.split(' ');
  const out = [];
  for (const op of ops) {
    if (op.startsWith('OP_')) {
      let opName = op.slice(3);
      if (opName === 'FALSE') opName = '0';
      if (opName === 'TRUE') opName = '1';
      // Handle numeric opcodes
      if (String(Number(opName)) === opName) opName = `OP_${opName}`;
      if (btc.OP[opName] === undefined) throw new Error(`Wrong opcode='${op}'`);
      out.push(opName);
    } else {
      out.push(hex.decode(op));
    }
  }
  return out;
}

export function getNet(network) {
  if (network === 'litecoin') return { pubKeyHash: 0x30, scriptHash: 0x32 };
  if (network === 'testnet') return { bech32: 'tb', pubKeyHash: 0x6f, scriptHash: 0xc4 };
  if (network === 'regtest') return { bech32: 'bcrt', pubKeyHash: 0x6f, scriptHash: 0xc4 };
}
