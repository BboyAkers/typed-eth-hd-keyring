import {
  arrToBufArr,
  bufferToHex,
  privateToPublic,
  publicToAddress,
} from '@ethereumjs/util';
import { normalize } from '@metamask/eth-sig-util';
import { wordlist } from '@metamask/scure-bip39/dist/wordlists/english';
import { Buffer } from 'buffer';
import { keccak256 } from 'ethereum-cryptography/keccak';

// const hdPathString = `m/44'/60'/0'/0`;ß
const type = 'HD Key Tree';

type HdKeyringOpts = {
  type: string;
  _wallets: unknown[];
};

type KeyringOptions = {
  // withAppKeyOrigin?: string;
  // version?: string;
  mnemonic?: string[];
  numberOfAccounts?: number;
  root: unknown;
};

// type Mnemonic = {
//   type: string;
//   data: string;
// };

export default class HdKeyring implements HdKeyringOpts {
  type: string;

  _wallets: any[]; // TODO: figure out what type this is

  root: unknown;

  constructor(opts: KeyringOptions = {}) {
    this.type = type;
    this._wallets = [];
    this.root = null;
    this.deserialize(opts);
  }

  getAccounts(): string[] {
    return this._wallets.map((wallet) => wallet.getAddressString());
  }

  deserialize(opts: KeyringOptions = {}) {
    if (opts.numberOfAccounts && !opts.mnemonic) {
      throw new Error(
        'Eth-Hd-Keyring: Deserialize method cannot be called with an opts value for numberOfAccounts and no menmonic',
      );
    }

    if (this.root) {
      throw new Error(
        'Eth-Hd-Keyring: Secret recovery phrase already provided',
      );
    }
    this.opts = opts;
    this._wallets = [];
    this.mnemonic = null;
    this.root = null;
    this.hdPath = opts.hdPath || hdPathString;

    if (opts.mnemonic) {
      this._initFromMnemonic(opts.mnemonic);
    }

    if (opts.numberOfAccounts) {
      return this.addAccounts(opts.numberOfAccounts);
    }

    return Promise.resolve([]);
  }

  // small helper function to convert publicKey in Uint8Array form to a publicAddress as a hex
  _addressfromPublicKey(publicKey: string) {
    return bufferToHex(
      publicToAddress(Buffer.from(publicKey), true),
    ).toLowerCase();
  }
}
