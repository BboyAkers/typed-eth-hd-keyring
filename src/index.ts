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
  _wallets: any[];
};

type KeyringOptions = {
  withAppKeyOrigin?: string;
  version?: string;
};

export default class HdKeyring implements HdKeyringOpts {
  type: string;

  _wallets: any[];

  constructor() {
    this.type = type;
    this._wallets = [];
  }

  _stringToUint8Array(mnemonic: string) {
    const indices = mnemonic.split(' ').map((word) => wordlist.indexOf(word));
    return new Uint8Array(new Uint16Array(indices).buffer);
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
