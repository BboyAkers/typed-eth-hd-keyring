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
  withAppKeyOrigin?: string;
  version?: string;
};

type Mnemonic = {
  type: string;
  data: string;
};

export default class HdKeyring implements HdKeyringOpts {
  type: string;

  _wallets: any[]; // TODO: figure out what type this is

  hdPath: string;

  // mnemonic: string;

  constructor() {
    this.type = type;
    this._wallets = [];
    this.hdPath = '';
    // this.mnemonic = '';
    // this.deserialize();
  }

  _stringToUint8Array(mnemonic: string) {
    const indices = mnemonic.split(' ').map((word) => wordlist.indexOf(word));
    return new Uint8Array(new Uint16Array(indices).buffer);
  }

  _mnemonicToUint8Array(mnemonic: Mnemonic) {
    const mnemonicData = mnemonic;
    // when encrypted/decrypted, buffers get cast into js object with a property type set to buffer
    if (mnemonic?.type === 'Buffer') {
      mnemonicData.data = mnemonic.data;
    }

    if (
      // this block is for backwards compatibility with vaults that were previously stored as buffers, number arrays or plain text strings
      typeof mnemonicData.data === 'string' ||
      Buffer.isBuffer(mnemonicData) ||
      Array.isArray(mnemonicData)
    ) {
      let mnemonicAsString = mnemonicData.data;
      if (Array.isArray(mnemonicData)) {
        mnemonicAsString = Buffer.from(mnemonicData).toString();
      } else if (Buffer.isBuffer(mnemonicData)) {
        mnemonicAsString = mnemonicData.toString();
      }
      return this._stringToUint8Array(mnemonicAsString);
    } else if (
      mnemonicData instanceof Object &&
      !(mnemonicData instanceof Uint8Array)
    ) {
      // when encrypted/decrypted the Uint8Array becomes a js object we need to cast back to a Uint8Array
      return Uint8Array.from(Object.values(mnemonicData.data));
    }
    return mnemonicData;
  }

  async serialize() {
    return Promise.resolve({
      mnemonic: this._mnemonicToUint8Array(this.mnemonic),
      numberOfAccounts: this._wallets.length,
      hdPath: this.hdPath,
    });
  }

  _getWalletForAccount(account: string, opts: KeyringOptions = {}) {
    const address = normalize(account);
    let wallet = this._wallets.find(({ publicKey }) => {
      return this._addressfromPublicKey(publicKey) === address;
    });
    if (!wallet) {
      throw new Error('HD Keyring - Unable to find matching address.');
    }

    if (opts.withAppKeyOrigin) {
      const { privateKey } = wallet;
      const appKeyOriginBuffer = Buffer.from(opts.withAppKeyOrigin, 'utf8');
      const appKeyBuffer = Buffer.concat([privateKey, appKeyOriginBuffer]);
      const appKeyPrivateKey = arrToBufArr(keccak256(appKeyBuffer));
      const appKeyPublicKey = privateToPublic(appKeyPrivateKey);
      wallet = { privateKey: appKeyPrivateKey, publicKey: appKeyPublicKey };
    }

    return wallet;
  }

  // small helper function to convert publicKey in Uint8Array form to a publicAddress as a hex
  _addressfromPublicKey(publicKey: string) {
    return bufferToHex(
      publicToAddress(Buffer.from(publicKey), true),
    ).toLowerCase();
  }
}
