"use strict";

const blindSignatures = require('blind-signatures');
const { Coin, COIN_RIS_LENGTH, IDENT_STR, BANK_STR } = require('./coin');
const utils = require('./utils');

const BANK_KEY = blindSignatures.keyGeneration({ b: 2048 });
const N = BANK_KEY.keyPair.n.toString();
const E = BANK_KEY.keyPair.e.toString();

function signCoin(blindedCoinHash) {
  return blindSignatures.sign({
    blinded: blindedCoinHash,
    key: BANK_KEY,
  });
}

function parseCoin(s) {
  let [cnst, amt, guid, leftHashes, rightHashes] = s.split('-');
  if (cnst !== BANK_STR) {
    throw new Error(`Invalid identity string: ${cnst} received, but ${BANK_STR} expected`);
  }
  return [leftHashes.split(','), rightHashes.split(',')];
}

function acceptCoin(coin) {
  const valid = blindSignatures.verify({
    unblinded: coin.signature,
    message: coin.toString(),
    N: coin.n,
    E: coin.e
  });

  if (!valid) throw new Error("Invalid signature on coin!");

  const [leftHashes, rightHashes] = parseCoin(coin.toString());
  let ris = [];

  for (let i = 0; i < COIN_RIS_LENGTH; i++) {
    let isLeft = utils.randInt(2) === 0;
    let ident = coin.getRis(isLeft, i);
    let actualHash = utils.hash(ident.toString('hex'));
    let expected = isLeft ? leftHashes[i] : rightHashes[i];
    if (actualHash !== expected) throw new Error("RIS verification failed!");
    ris.push(ident.toString('hex'));
  }

  return ris;
}

function determineCheater(guid, ris1, ris2) {
  for (let i = 0; i < COIN_RIS_LENGTH; i++) {
    if (ris1[i] !== ris2[i]) {
      let buf1 = Buffer.from(ris1[i], 'hex');
      let buf2 = Buffer.from(ris2[i], 'hex');
      let combined = Buffer.alloc(buf1.length);
      for (let j = 0; j < buf1.length; j++) {
        combined[j] = buf1[j] ^ buf2[j];
      }
      let result = combined.toString();
      if (result.startsWith(IDENT_STR)) {
        console.log(`Double-spender identified: ${result}`);
        return;
      } else {
        console.log("Merchant is cheating");
        return;
      }
    }
  }
  console.log("Same RIS, merchant duplicated it");
}

let coin = new Coin('alice', 20, N, E);
coin.signature = signCoin(coin.blinded);
coin.unblind();

let ris1 = acceptCoin(coin);
let ris2 = acceptCoin(coin);
determineCheater(coin.guid, ris1, ris2);
console.log();
determineCheater(coin.guid, ris1, ris1);