/* @flow */

import { TokenSigner } from 'jsontokens'
const blockstack = require('blockstack');
import process from 'process';
import bitcoinjs from 'bitcoinjs-lib';
import fs from 'fs';
const bigi = require('bigi')
const URL = require('url')
const bip39 = require('bip39')
const crypto = require('crypto')
const ZoneFile = require('zone-file')
const c32check = require('c32check')

import {
  parseZoneFile
} from 'zone-file';

import {
  getOwnerKeyInfo,
  getPaymentKeyInfo,
  getApplicationKeyInfo,
  STRENGTH,
} from './keys';

const Promise = require('bluebird');
Promise.onPossiblyUnhandledRejection(function(error){
    throw error;
});
const VERSION = '1.2.0'

import {
  getCLIOpts,
  printUsage,
  checkArgs,
  loadConfig,
  makeCommandUsageString,
  makeAllCommandsList,
  USAGE,
  DEFAULT_CONFIG_PATH,
  DEFAULT_CONFIG_REGTEST_PATH,
  DEFAULT_CONFIG_TESTNET_PATH,
  ADDRESS_PATTERN,
  ID_ADDRESS_PATTERN,
  STACKS_ADDRESS_PATTERN
} from './argparse';

import {
  CLINetworkAdapter,
  getNetwork
} from './network';

import {
  MultiSigKeySigner,
  SafetyError,
  JSONStringify,
  getPrivateKeyAddress,
  isSubdomain,
  canonicalPrivateKey,
  sumUTXOs,
  hash160,
  checkUrl,
  decodePrivateKey,
  gaiaConnect,
  makeProfileJWT,
  getPublicKeyFromPrivateKey,
  getECPairFromPrivateKey
} from './utils';

function nextMonth() {
  return new Date(
    new Date().setMonth(
      new Date().getMonth() + 1
    )
  )
}
function makeV1GaiaAuthToken(hubInfo: Object, signerKeyHex: string): string {
  const challengeText = hubInfo.challenge_text
  const handlesV1Auth = (hubInfo.latest_auth_version &&
                         parseInt(hubInfo.latest_auth_version.slice(1), 10) >= 1)
  const iss = blockstack.getPublicKeyFromPrivate(signerKeyHex)

  if (!handlesV1Auth) {
    return makeLegacyAuthToken(challengeText, signerKeyHex)
  }

  const salt = crypto.randomBytes(16).toString('hex')
  const payload = { gaiaChallenge: challengeText,
                    iss, salt }
  const token = new TokenSigner('ES256K', signerKeyHex).sign(payload)
  return `v1:${token}`
}

export function connectToGaiaHub(gaiaHubUrl: string,
                                 challengeSignerHex: string): Promise<GaiaHubConfig> {
  console.log(`connectToGaiaHub: ${gaiaHubUrl}/hub_info`)

  return fetch(`${gaiaHubUrl}/hub_info`)
    .then((response) => response.json())
    .then((hubInfo) => {
      const readURL = hubInfo.read_url_prefix
      const token = makeV1GaiaAuthToken(hubInfo, challengeSignerHex)
      const address = getECPairFromPrivateKey(challengeSignerHex +
                                        (challengeSignerHex.length === 64 ? '01' : ''))
            .getAddress()
      return { url_prefix: readURL,
               address,
               token,
               server: gaiaHubUrl }
    })
}
export function uploadToGaiaHub(filename: string, contents: any,
                                hubConfig: GaiaHubConfig,
                                contentType: string = 'application/octet-stream'): Promise<*> {
  console.log(`uploadToGaiaHub: uploading ${filename} to ${hubConfig.server}`)
  return fetch(`${hubConfig.server}/store/${hubConfig.address}/${filename}`,
        { method: 'POST',
          headers: {
            'Content-Type': contentType,
            Authorization: `bearer ${hubConfig.token}`
          },
          body: contents })
    .then((response) => response.text())
    .then((responseText) => JSON.parse(responseText))
    .then((responseJSON) => responseJSON.publicURL)
}

/**
 * Generates a signed authentication response token for an app. This
 * token is sent back to apps which use contents to access the
 * resources and data requested by the app.
 *
 * @param  {String} privateKey the identity key of the Blockstack ID generating
 * the authentication response
 * @param  {Object} profile the profile object for the Blockstack ID
 * @param  {String} username the username of the Blockstack ID if any, otherwise `null`
 * @param  {AuthMetadata} metadata an object containing metadata sent as part of the authentication
 * response including `email` if requested and available and a URL to the profile
 * @param  {String} coreToken core session token when responding to a legacy auth request
 * or `null` for current direct to gaia authentication requests
 * @param  {String} appPrivateKey the application private key. This private key is
 * unique and specific for every Blockstack ID and application combination.
 * @param  {Number} expiresAt an integer in the same format as
 * `new Date().getTime()`, milliseconds since the Unix epoch
 * @param {String} transitPublicKey the public key provide by the app
 * in its authentication request with which secrets will be encrypted
 * @param {String} hubUrl URL to the write path of the user's Gaia hub
 * @return {String} signed and encoded authentication response token
 */
export function makeAuthResponseMultisig(ownerPubKeys: Array<string>,
                                 m : number,
                                 profile: {} = {},
                                 username: ?string = null,
                                 metadata: AuthMetadata,
                                 coreToken: ?string = null,
                                 appPrivateKey: ?string = null,
                                 expiresAt: number = nextMonth().getTime(),
                                 transitPublicKey: ?string = null,
                                 hubUrl: ?string = null): string {
                                   console.log("hello");
  /* Convert the private key to a public key to an issuer */
  const pubkeys = ownerPubKeys.map((pubKey) => {
    return Buffer.from(pubKey, 'hex');
  });
  const redeemScript = bitcoinjs.script.multisig.output.encode(m, pubkeys);
  const address = bitcoinjs.address.toBase58Check(
          bitcoinjs.crypto.hash160(redeemScript),
          blockstack.config.network.layer1.scriptHash)

  /* See if we should encrypt with the transit key */
  let privateKeyPayload = appPrivateKey
  let coreTokenPayload = coreToken
  let additionalProperties = {}
  if (appPrivateKey !== undefined && appPrivateKey !== null) {
    console.log(`blockstack.js: generating v${VERSION} auth response`)
    if (transitPublicKey !== undefined && transitPublicKey !== null) {
      privateKeyPayload = encryptPrivateKey(transitPublicKey, appPrivateKey)
      if (coreToken !== undefined && coreToken !== null) {
        coreTokenPayload = encryptPrivateKey(transitPublicKey, coreToken)
      }
    }
    additionalProperties = {
      email: metadata.email ? metadata.email : null,
      profile_url: metadata.profileUrl ? metadata.profileUrl : null,
      hubUrl,
      version: VERSION
    }
  } else {
    console.log('blockstack.js: generating legacy auth response')
  }

  /* Create the payload */
  const payload = Object.assign({}, {
    jti: makeUUID4(),
    iat: Math.floor(new Date().getTime() / 1000), // JWT times are in seconds
    exp: Math.floor(expiresAt / 1000), // JWT times are in seconds
    iss: makeDIDFromAddress(address),
    private_key: privateKeyPayload,
    public_keys: ownerPubKeys,
    profile,
    username,
    core_token: coreTokenPayload
  }, additionalProperties)

                                   console.log(payload);
  /* Sign and return the token */
  const tokenSigner = new TokenSigner('ES256k', privateKey)
  return tokenSigner.sign(payload)
}

/*
 * Set up a session for Gaia.
 * Generate an authentication response like what the browser would do,
 * and store the relevant data to our emulated localStorage.
 */
function makeGaiaSessionToken(ownerPubKeys, m, hubURL: string | null) {
  const ownerPrivateKey = '24004db06ef6d26cdd2b0fa30b332a1b10fa0ba2b07e63505ffc2a9ed7df22b4';
  const transitPrivateKey = 'f33fb466154023aba2003c17158985aa6603db68db0f1afc0fcf1d641ea6c2cb';
  const transitPublicKey = '0496345da77fb5e06757b9c4fd656bf830a3b293f245a6cc2f11f8334ebb690f19582124f4b07172eb61187afba4514828f866a8a223e0d5c539b2e38a59ab8bb3';

  window.localStorage.setItem('blockstack-transit-private-key', transitPrivateKey)

  const authResponse = makeAuthResponseMultisig(
    ownerPubKeys,
    m,
    {type: '@Venture'},
    null,
    {},
    null,
    appPrivateKey,
    undefined,
    transitPublicKey,
    hubURL);

  return authResponse;
}

/*
 * Put a file into a Gaia hub (multisig-address)
 * args:
 * @hubUrl (string) the URL to the write endpoint of the gaia hub
 * @appPrivateKey (string) the private key used to authenticate to the gaia hub
 * @dataPath (string) the path (on disk) to the data to store
 * @gaiaPath (string) the path (in Gaia) where the data will be stored
 * @encrypt (string) OPTIONAL: if '1' or 'true', then encrypt the file
 * @sign (string) OPTIONAL: if '1' or 'true', then sign the file and store the signature too.
 */
export function gaiaPutFileMultiSig(network: Object, args: Array<string>) {
  const hubUrl = args[0];
  const appPrivateKeysArg = args[1].split(",");
  const dataPath = args[2];
  const gaiaPath = args[3].replace(/^\/+/, '');

  console.log(appPrivateKeysArg)
  const m = parseInt(appPrivateKeysArg[0]);
  const privkeys = appPrivateKeysArg.slice(1,appPrivateKeysArg.lenght);
  const pubkeys = privkeys.map((pk) => {
    return getPublicKeyFromPrivateKey(pk);
  });

  const data = fs.readFileSync(dataPath);

  return connectToGaiaHub(hubUrl,privkeys[1]).then((hubConfig) => {
    console.log(hubConfig);
    return uploadToGaiaHub(gaiaPath, data, hubConfig);
  }).then((urls) => {
      return JSONStringify({'urls': urls})
  })
}

