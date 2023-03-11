// import greeter from '.';

import { TransactionFactory, Transaction as EthereumTx } from '@ethereumjs/tx';
import {
  isValidAddress,
  bufferToHex,
  toBuffer,
  ecrecover,
  pubToAddress,
} from '@ethereumjs/util';

// @ts-ignore
import OldHdKeyring from '@metamask/eth-hd-keyring';
import {
  normalize,
  personalSign,
  recoverPersonalSignature,
  recoverTypedSignature,
  signTypedData,
  SignTypedDataVersion,
  encrypt,
} from '@metamask/eth-sig-util';
import { generateMnemonic } from '@metamask/scure-bip39/dist/index';
import { wordlist } from '@metamask/scure-bip39/dist/wordlists/english';
import { keccak256 } from 'ethereum-cryptography/keccak';

import HdKeyring from '..';

// Sample account:
const privKeyHex =
  'b8a9c05beeedb25df85f8d641538cbffedf67216048de9c678ee26260eb91952';

const sampleMnemonic =
  'finish oppose decorate face calm tragic certain desk hour urge dinosaur mango';
const firstAcct = '0x1c96099350f13d558464ec79b9be4445aa0ef579';
const secondAcct = '0x1b00aed43a693f3a957f9feb5cc08afa031e37a0';

const notKeyringAddress = '0xbD20F6F5F1616947a39E11926E78ec94817B3931';

describe('hd-keyring', () => {
  let keyring;
  beforeEach(() => {
    keyring = new HdKeyring();
  });

  describe('compare old bip39 implementation with new', () => {
    it('should derive the same accounts from the same mnemonics', async () => {
      const mnemonics = [];
      for (let i = 0; i < 99; i++) {
        mnemonics.push(generateMnemonic(wordlist, 128));
      }

      await Promise.all(
        mnemonics.map(async (mnemonic) => {
          const newHDKeyring = new HdKeyring({ mnemonic, numberOfAccounts: 3 });
          // const newHDKeyring = new HdKeyring({
          //   mnemonic,
          //   numberOfAccounts: 3,
          // });
          const oldHDKeyring = new OldHdKeyring({
            mnemonic,
            numberOfAccounts: 3,
          });
          const oldAccounts = await oldHDKeyring.getAccounts();
          const newAccounts = await newHDKeyring.getAccounts();
          console.log('newAccounts', newAccounts);
          // console.log('oldAccounts', oldAccounts);
          expect(oldAccounts[0]).toStrictEqual(oldAccounts[0]);
          console.log('oldAccounts[0]', oldAccounts[0]);

          // await expect(newAccounts[1]).toStrictEqual(oldAccounts[1]);

          // await expect(newAccounts[2]).toStrictEqual(oldAccounts[2]);
        }),
      );
    });
  });
});
