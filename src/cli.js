/* @flow */

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

import { gaiaPutFileMultiSig } from './multisig';

const Promise = require('bluebird');
Promise.onPossiblyUnhandledRejection(function(error){
    throw error;
});

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
  makeProfileJWT
} from './utils';

// global CLI options
let txOnly = false;
let estimateOnly = false;
let safetyChecks = true;
let receiveFeesPeriod = 52595;
let gracePeriod = 5000;

let BLOCKSTACK_TEST = process.env.BLOCKSTACK_TEST ? true : false;


/*
 * Easier-to-use getNameInfo.  Returns null if the name does not exist.
 */
function getNameInfo(network: Object, name: string) : Promise<*> {
  const nameInfoPromise = network.getNameInfo(name)
    .then((nameInfo) => nameInfo)
    .catch((error) => {
      if (error.message === 'Name not found') {
        return null;
      } else {
        throw error;
      }
    });

  return nameInfoPromise;
}

/*
 * Get a name's record information
 * args:
 * @name (string) the name to query
 */
function whois(network: Object, args: Array<string>) {
  const name = args[0];
  return network.getNameInfo(name)
    .then((nameInfo) => {
      if (BLOCKSTACK_TEST) {
        // the test framework expects a few more fields.
        // these are for compatibility with the old CLI.
        // you are not required to understand them.
        return Promise.all([network.getNameHistory(name), network.getBlockHeight()])
          .then(([nameHistory, blockHeight]) => {
            if (nameInfo.renewal_deadline > 0 && nameInfo.renewal_deadline <= blockHeight) {
              return {'error': 'Name expired'}
            }

            const blocks = Object.keys(nameHistory);
            const lastBlock = blocks.sort().slice(-1)[0];

            return Object.assign({}, nameInfo, {
              'owner_address': nameInfo.address,
              'owner_script': bitcoinjs.address.toOutputScript(
                network.coerceMainnetAddress(nameInfo.address)).toString('hex'),
              'last_transaction_height': lastBlock,
              'block_renewed_at': nameHistory[lastBlock].slice(-1)[0].last_renewed,
            });
          })
      }
      else {
        return nameInfo;
      }
    })
    .then(whoisInfo => JSONStringify(whoisInfo))
    .catch((error) => {
      if (error.message === 'Name not found') {
        return JSONStringify({'error': 'Name not found'}, true);
      }
      else {
        throw error;
      }
    });
}

/*
 * Get a name's price information
 * args:
 * @name (string) the name to query
 */
function price(network: Object, args: Array<string>) {
  const name = args[0];
  return network.getNamePrice(name)
    .then(priceInfo => JSONStringify(
      { units: priceInfo.units, amount: priceInfo.amount.toString() }));
}

/*
 * Get a namespace's price information 
 * args:
 * @namespaceID (string) the namespace to query
 */
function priceNamespace(network: Object, args: Array<string>) {
  const namespaceID = args[0];
  return network.getNamespacePrice(namespaceID)
    .then(priceInfo => JSONStringify(
      { units: priceInfo.units, amount: priceInfo.amount.toString() }));
}

/*
 * Get names owned by an address
 * args:
 * @address (string) the address to query
 */
function names(network: Object, args: Array<string>) {
  const IDaddress = args[0];
  if (!IDaddress.startsWith('ID-')) {
    throw new Error("Must be an ID-address");
  }

  const address = IDaddress.slice(3);
  return network.getNamesOwned(address)
    .then(namesList => JSONStringify(namesList));
}

/*
 * Look up a name's profile and zonefile
 * args:
 * @name (string) the name to look up
 */
function lookup(network: Object, args: Array<string>) {
  network.setCoerceMainnetAddress(true);

  const name = args[0];
  const nameInfoPromise = getNameInfo(network, name);
  const profilePromise = blockstack.lookupProfile(name)
    .catch(() => null);

  const zonefilePromise = nameInfoPromise.then((nameInfo) => nameInfo ? nameInfo.zonefile : null);

  return Promise.all([profilePromise, zonefilePromise, nameInfoPromise])
    .then(([profile, zonefile, nameInfo]) => {
      if (!nameInfo) {
        return JSONStringify({
          error: 'Name not found'
        });
      }
      if (nameInfo.hasOwnProperty('grace_period') && nameInfo.grace_period) {
        return JSONStringify({
          error: `Name is expired at block ${nameInfo.expire_block} and must be renewed by block ${nameInfo.renewal_deadline}`
        });
      }
      const ret = {
        zonefile: zonefile,
        profile: profile
      };
      return JSONStringify(ret);
    });
}

/*
 * Get a name's blockchain record
 * args:
 * @name (string) the name to query
 */
function getNameBlockchainRecord(network: Object, args: Array<string>) {
  const name = args[0];
  return Promise.resolve().then(() => {
    return network.getBlockchainNameRecord(name);
  })
  .then((nameInfo) => {
    return JSONStringify(nameInfo);
  })
  .catch((e) => {
    if (e.message === 'Bad response status: 404') {
      return JSONStringify({ 'error': 'Name not found'}, true);
    }
    else {
      throw e;
    }
  });
}

/*
 * Get a name's history entry or entries
 * args:
 * @name (string) the name to query
 * @startHeight (int) optional: the start of the history range
 * @endHeight (int) optional: the end of the history range
 */
function getNameHistoryRecord(network: Object, args: Array<string>) {
  const name = args[0];
  let startHeight = null;
  let endHeight = null;

  if (args.length >= 2) {
    startHeight = parseInt(args[1]);
  }
  if (args.length >= 3) {
    endHeight = parseInt(args[2]);
  }

  return Promise.resolve().then(() => {
    return network.getNameHistory(name, startHeight, endHeight);
  })
  .then((nameHistory) => {
    return JSONStringify(nameHistory);
  });
}

/*
 * Get a namespace's blockchain record
 * args:
 * @namespaceID (string) the namespace to query
 */
function getNamespaceBlockchainRecord(network: Object, args: Array<string>) {
  const namespaceID = args[0];
  return Promise.resolve().then(() => {
    return network.getNamespaceInfo(namespaceID);
  })
  .then((namespaceInfo) => {
    return JSONStringify(namespaceInfo);
  })
  .catch((e) => {
    if (e.message === 'Namespace not found') {
      return JSONStringify({'error': 'Namespace not found'}, true);
    }
    else {
      throw e;
    }
  });
}

/*
 * Get a name's zone file
 * args:
 * @name (string) the name to query
 */
function getNameZonefile(network: Object, args: Array<string>) {
  const name = args[0];
  return Promise.resolve().then(() => {
      return network.getNameInfo(name)
    })
    .then(nameInfo => nameInfo.zonefile);
}

/*
 * Generate and optionally send a name-preorder
 * args:
 * @name (string) the name to preorder
 * @IDaddress (string) the address to own the name
 * @paymentKey (string) the payment private key
 * @preorderTxOnly (boolean) OPTIONAL: used internally to only return a tx (overrides CLI)
 */
function txPreorder(network: Object, args: Array<string>, preorderTxOnly: ?boolean = false) {
  const name = args[0];
  const IDaddress = args[1];
  const paymentKey = decodePrivateKey(args[2]);
  const paymentAddress = getPrivateKeyAddress(network, paymentKey);

  if (!IDaddress.startsWith('ID-')) {
    throw new Error("Recipient ID-address must start with ID-");
  }
  const address = IDaddress.slice(3);

  const namespaceID = name.split('.').slice(-1)[0];

  const txPromise = blockstack.transactions.makePreorder(
    name, address, paymentKey);

  const paymentUTXOsPromise = network.getUTXOs(paymentAddress);

  const estimatePromise = paymentUTXOsPromise.then((utxos) => {
        const numUTXOs = utxos.length;
        return blockstack.transactions.estimatePreorder(
          name, network.coerceAddress(address), 
          network.coerceAddress(paymentAddress), numUTXOs);
      });

  if (estimateOnly) {
    return estimatePromise;
  }
  
  if (!safetyChecks) {
    if (txOnly || preorderTxOnly) {
      return txPromise;
    }
    else {
      return txPromise
        .then((tx) => {
          return network.broadcastTransaction(tx);
        });
    }
  }

  const paymentBalance = paymentUTXOsPromise.then((utxos) => {
    return sumUTXOs(utxos);
  });

  const nameInfoPromise = getNameInfo(network, name);
  const blockHeightPromise = network.getBlockHeight();

  const safetyChecksPromise = Promise.all([
      nameInfoPromise,
      blockHeightPromise,
      blockstack.safety.isNameValid(name),
      blockstack.safety.isNameAvailable(name),
      blockstack.safety.addressCanReceiveName(network.coerceAddress(address)),
      blockstack.safety.isInGracePeriod(name),
      network.getNamespaceBurnAddress(namespaceID, true, receiveFeesPeriod),
      network.getNamespaceBurnAddress(namespaceID, false, receiveFeesPeriod),
      paymentBalance,
      estimatePromise,
      blockstack.safety.namespaceIsReady(namespaceID),
      network.getNamePrice(name),
      network.getAccountBalance(paymentAddress, 'STACKS'),
    ])
    .then(([nameInfo,
            blockHeight,
            isNameValid,
            isNameAvailable,
            addressCanReceiveName, 
            isInGracePeriod,
            givenNamespaceBurnAddress,
            trueNamespaceBurnAddress,
            paymentBalance,
            estimate,
            isNamespaceReady,
            namePrice,
            STACKSBalance]) => {
      if (isNameValid && isNamespaceReady &&
          (isNameAvailable || !nameInfo) &&
          addressCanReceiveName && !isInGracePeriod && paymentBalance >= estimate &&
          trueNamespaceBurnAddress === givenNamespaceBurnAddress &&
          (namePrice.units === 'BTC' || (namePrice.units == 'STACKS'
           && namePrice.amount.compareTo(STACKSBalance) <= 0))) {
        return {'status': true};
      }
      else {
        return {
          'status': false,
          'error': 'Name cannot be safely preordered',
          'isNameValid': isNameValid,
          'isNameAvailable': isNameAvailable,
          'addressCanReceiveName': addressCanReceiveName,
          'isInGracePeriod': isInGracePeriod,
          'paymentBalanceBTC': paymentBalance,
          'paymentBalanceStacks': STACKSBalance.toString(),
          'nameCostUnits': namePrice.units,
          'nameCostAmount': namePrice.amount.toString(),
          'estimateCostBTC': estimate,
          'isNamespaceReady': isNamespaceReady,
          'namespaceBurnAddress': givenNamespaceBurnAddress,
          'trueNamespaceBurnAddress': trueNamespaceBurnAddress,
        };
      }
    });

  return safetyChecksPromise
    .then((safetyChecksResult) => {
      if (!safetyChecksResult.status) {
        if (preorderTxOnly) {
          // only care about safety checks or tx 
          return new Promise((resolve) => resolve(safetyChecksResult));
        }
        else {
          // expect a string either way
          return new Promise((resolve) => resolve(JSONStringify(safetyChecksResult, true)));
        }
      }

      if (txOnly || preorderTxOnly) {
        return txPromise;
      }

      return txPromise.then((tx) => {
        return network.broadcastTransaction(tx);
      })
      .then((txidHex) => {
        return txidHex;
      });
    });
}


/*
 * Generate and optionally send a name-register
 * args:
 * @name (string) the name to register
 * @IDaddress (string) the address that owns this name
 * @paymentKey (string) the payment private key
 * @zonefile (string) if given, the raw zone file or the path to the zone file data to use
 * @zonefileHash (string) if given, this is the raw zone file hash to use
 *  (in which case, @zonefile will be ignored)
 * @registerTxOnly (boolean) OPTIONAL: used internally to coerce returning only the tx
 */
function txRegister(network: Object, args: Array<string>, registerTxOnly: ?boolean = false) {
  const name = args[0];
  const IDaddress = args[1];
  const paymentKey = decodePrivateKey(args[2]);

  if (!IDaddress.startsWith('ID-')) {
    throw new Error("Recipient ID-address must start with ID-");
  }
  const address = IDaddress.slice(3);
  const namespaceID = name.split('.').slice(-1)[0];

  let zonefilePath = null;
  let zonefileHash = null;
  let zonefile = null;

  if (args.length > 3) {
    zonefilePath = args[3];
  }

  if (args.length > 4) {
    zonefileHash = args[4];
    zonefilePath = null;

    console.log(`Using zone file hash ${zonefileHash} instead of zone file`);
  }

  if (!!zonefilePath) {
    try {
      zonefile = fs.readFileSync(zonefilePath).toString();
    }
    catch(e) {
      // zone file path as raw zone file
      zonefile = zonefilePath
    }
  }

  const paymentAddress = getPrivateKeyAddress(network, paymentKey);
  const paymentUTXOsPromise = network.getUTXOs(paymentAddress);

  const estimatePromise = paymentUTXOsPromise.then((utxos) => {
        const numUTXOs = utxos.length;
        return blockstack.transactions.estimateRegister(
          name, network.coerceAddress(address),
          network.coerceAddress(paymentAddress), true, numUTXOs);
      });

  const txPromise = blockstack.transactions.makeRegister(
    name, address, paymentKey, zonefile, zonefileHash);

  if (estimateOnly) {
    return estimatePromise;
  }
 
  if (!safetyChecks) {
    if (txOnly || registerTxOnly) {
      return txPromise;
    }
    else {
      return txPromise
        .then((tx) => {
          return network.broadcastTransaction(tx);
        });
    }
  }

  const paymentBalancePromise = paymentUTXOsPromise.then((utxos) => {
    return sumUTXOs(utxos);
  });
 
  const nameInfoPromise = getNameInfo(network, name);
  const blockHeightPromise = network.getBlockHeight();

  const safetyChecksPromise = Promise.all([
      nameInfoPromise,
      blockHeightPromise,
      blockstack.safety.isNameValid(name),
      blockstack.safety.isNameAvailable(name),
      blockstack.safety.addressCanReceiveName(
        network.coerceAddress(address)),
      blockstack.safety.isInGracePeriod(name),
      blockstack.safety.namespaceIsReady(namespaceID),
      paymentBalancePromise,
      estimatePromise,
    ])
    .then(([nameInfo, 
            blockHeight,
            isNameValid,
            isNameAvailable, 
            addressCanReceiveName,
            isInGracePeriod,
            isNamespaceReady,
            paymentBalance,
            estimateCost]) => {
      if (isNameValid && isNamespaceReady &&
         (isNameAvailable || !nameInfo) &&
          addressCanReceiveName && !isInGracePeriod && estimateCost < paymentBalance) {
        return {'status': true};
      }
      else {
        return {
          'status': false,
          'error': 'Name cannot be safely registered',
          'isNameValid': isNameValid,
          'isNameAvailable': isNameAvailable,
          'addressCanReceiveName': addressCanReceiveName,
          'isInGracePeriod': isInGracePeriod,
          'isNamespaceReady': isNamespaceReady,
          'paymentBalanceBTC': paymentBalance,
          'estimateCostBTC': estimateCost,
        };
      }
    });
  
  return safetyChecksPromise
    .then((safetyChecksResult) => {
      if (!safetyChecksResult.status) {
        if (registerTxOnly) {
          // only care about safety checks or tx 
          return new Promise((resolve) => resolve(safetyChecksResult));
        }
        else {
          // expect a string either way
          return new Promise((resolve) => resolve(JSONStringify(safetyChecksResult, true)));
        }
      }

      if (txOnly || registerTxOnly) {
        return txPromise;
      }

      return txPromise.then((tx) => {
        return network.broadcastTransaction(tx);
      })
      .then((txidHex) => {
        return txidHex;
      });
    });
}

/*
 * Generate a zone file for a name, given its Gaia hub URL 
 */
function makeZonefile(network: Object, args: Array<string>) {
  const name = args[0];
  const idAddress = args[1];
  const gaiaHub = args[2];

  if (!idAddress.startsWith('ID-')) {
    throw new Error("ID-address must start with ID-");
  }

  const address = idAddress.slice(3);
  const mainnetAddress = network.coerceMainnetAddress(address);
  const profileUrl = `${gaiaHub}/hub/${mainnetAddress}/profile.json`;
  try {
    checkUrl(profileUrl);
  }
  catch(e) {
    return Promise.resolve().then(() => JSONStringify({
      'status': false,
      'error': e.message,
      'hints': [
        'Make sure the Gaia hub URL does not have any trailing /\'s',
        'Make sure the Gaia hub URL scheme is present and well-formed',
      ],
    }, true));
  }

  const zonefile = blockstack.makeProfileZoneFile(name, profileUrl);
  return Promise.resolve().then(() => zonefile)
}

/*
 * Generate and optionally send a name-update
 * args:
 * @name (string) the name to update
 * @zonefile (string) the path to the zonefile to use
 * @ownerKey (string) the owner private key
 * @paymentKey (string) the payment private key
 * @zonefileHash (string) the zone file hash to use, if given
 *   (will be used instead of the zonefile)
 */
function update(network: Object, args: Array<string>) {
  const name = args[0];
  let zonefilePath = args[1];
  const ownerKey = decodePrivateKey(args[2]);
  const paymentKey = decodePrivateKey(args[3]);

  let zonefile = null;
  let zonefileHash = null;

  if (args.length > 4) {
    zonefileHash = args[4];
    zonefilePath = null;
    console.log(`Using zone file hash ${zonefileHash} instead of zone file`);
  }

  if (zonefilePath) {
    zonefile = fs.readFileSync(zonefilePath).toString();
  }

  const ownerAddress = getPrivateKeyAddress(network, ownerKey);
  const paymentAddress = getPrivateKeyAddress(network, paymentKey);

  const ownerUTXOsPromise = network.getUTXOs(ownerAddress);
  const paymentUTXOsPromise = network.getUTXOs(paymentAddress);

  const estimatePromise = Promise.all([
      ownerUTXOsPromise, paymentUTXOsPromise])
    .then(([ownerUTXOs, paymentUTXOs]) => {
        const numOwnerUTXOs = ownerUTXOs.length;
        const numPaymentUTXOs = paymentUTXOs.length;
        return blockstack.transactions.estimateUpdate(
          name, network.coerceAddress(ownerAddress),
          network.coerceAddress(paymentAddress),
          numOwnerUTXOs + numPaymentUTXOs - 1);
      });

  const txPromise = blockstack.transactions.makeUpdate(
    name, ownerKey, paymentKey, zonefile, zonefileHash);

  if (estimateOnly) {
    return estimatePromise;
  }
 
  if (!safetyChecks) {
    if (txOnly) {
      return txPromise;
    }
    else {
      return txPromise
        .then((tx) => {
          return network.broadcastTransaction(tx);
        });
    }
  }

  const paymentBalancePromise = paymentUTXOsPromise.then((utxos) => {
    return sumUTXOs(utxos);
  });

  const safetyChecksPromise = Promise.all([
      blockstack.safety.isNameValid(name),
      blockstack.safety.ownsName(name, network.coerceAddress(ownerAddress)),
      blockstack.safety.isInGracePeriod(name),
      estimatePromise,
      paymentBalancePromise
    ])
    .then(([isNameValid, ownsName, isInGracePeriod, estimateCost, paymentBalance]) => {
      if (isNameValid && ownsName && !isInGracePeriod && estimateCost < paymentBalance) {
        return {'status': true};
      }
      else {
        return JSONStringify({
          'status': false,
          'error': 'Name cannot be safely updated',
          'isNameValid': isNameValid,
          'ownsName': ownsName,
          'isInGracePeriod': isInGracePeriod,
          'estimateCostBTC': estimateCost,
          'paymentBalanceBTC': paymentBalance,
        }, true);
      }
    });

  return safetyChecksPromise
    .then((safetyChecksResult) => {
      if (!safetyChecksResult.status) {
        return new Promise((resolve) => resolve(safetyChecksResult));
      }

      if (txOnly) {
        return txPromise;
      }

      return txPromise.then((tx) => {
        return network.broadcastTransaction(tx);
      })
      .then((txidHex) => {
        return txidHex;
      });
    });
}

/*
 * Generate and optionally send a name-transfer
 * args:
 * @name (string) the name to transfer
 * @IDaddress (string) the new owner address
 * @keepZoneFile (boolean) keep the zone file or not
 * @ownerKey (string) the owner private key
 * @paymentKey (string) the payment private key
 */
function transfer(network: Object, args: Array<string>) {
  const name = args[0];
  const IDaddress = args[1];
  const keepZoneFile = (args[2].toLowerCase() === 'true');
  const ownerKey = decodePrivateKey(args[3]);
  const paymentKey = decodePrivateKey(args[4]);
  const ownerAddress = getPrivateKeyAddress(network, ownerKey);
  const paymentAddress = getPrivateKeyAddress(network, paymentKey);

  if (!IDaddress.startsWith('ID-')) {
    throw new Error("Recipient ID-address must start with ID-");
  }
  const address = IDaddress.slice(3);

  const ownerUTXOsPromise = network.getUTXOs(ownerAddress);
  const paymentUTXOsPromise = network.getUTXOs(paymentAddress);

  const estimatePromise = Promise.all([
      ownerUTXOsPromise, paymentUTXOsPromise])
    .then(([ownerUTXOs, paymentUTXOs]) => {
        const numOwnerUTXOs = ownerUTXOs.length;
        const numPaymentUTXOs = paymentUTXOs.length;
        return blockstack.transactions.estimateTransfer(
          name, network.coerceAddress(address),
          network.coerceAddress(ownerAddress), 
          network.coerceAddress(paymentAddress),
          numOwnerUTXOs + numPaymentUTXOs - 1);
      });

  const txPromise = blockstack.transactions.makeTransfer(
    name, address, ownerKey, paymentKey, keepZoneFile);

  if (estimateOnly) {
    return estimatePromise;
  }
 
  if (!safetyChecks) {
    if (txOnly) {
      return txPromise;
    }
    else {
      return txPromise
        .then((tx) => {
          return network.broadcastTransaction(tx);
        });
    }
  }

  const paymentBalancePromise = paymentUTXOsPromise.then((utxos) => {
    return sumUTXOs(utxos);
  });
  
  const safetyChecksPromise = Promise.all([
      blockstack.safety.isNameValid(name),
      blockstack.safety.ownsName(name, network.coerceAddress(ownerAddress)),
      blockstack.safety.addressCanReceiveName(network.coerceAddress(address)),
      blockstack.safety.isInGracePeriod(name),
      paymentBalancePromise,
      estimatePromise,
    ])
    .then(([isNameValid, ownsName, addressCanReceiveName, 
            isInGracePeriod, paymentBalance, estimateCost]) => {
      if (isNameValid && ownsName && addressCanReceiveName &&
          !isInGracePeriod && estimateCost < paymentBalance) {
        return {'status': true};
      }
      else {
        return JSONStringify({
          'status': false,
          'error': 'Name cannot be safely transferred',
          'isNameValid': isNameValid,
          'ownsName': ownsName,
          'addressCanReceiveName': addressCanReceiveName,
          'isInGracePeriod': isInGracePeriod,
          'estimateCostBTC': estimateCost,
          'paymentBalanceBTC': paymentBalance,
        }, true);
      }
    });

  return safetyChecksPromise
    .then((safetyChecksResult) => {
      if (!safetyChecksResult.status) {
        return new Promise((resolve) => resolve(safetyChecksResult));
      }

      if (txOnly) {
        return txPromise;
      }

      return txPromise.then((tx) => {
        return network.broadcastTransaction(tx);
      })
      .then((txidHex) => {
        return txidHex;
      });
    });
}

/*
 * Generate and optionally send a name-renewal
 * args:
 * @name (string) the name to renew
 * @ownerKey (string) the owner private key
 * @paymentKey (string) the payment private key 
 * @address (string) OPTIONAL: the new owner address
 * @zonefilePath (string) OPTIONAL: the path to the new zone file
 * @zonefileHash (string) OPTINOAL: use the given zonefile hash.  Supercedes zonefile.
 */
function renew(network: Object, args: Array<string>) {
  const name = args[0];
  const ownerKey = decodePrivateKey(args[1]);
  const paymentKey = decodePrivateKey(args[2]);
  const ownerAddress = getPrivateKeyAddress(network, ownerKey);
  const paymentAddress = getPrivateKeyAddress(network, paymentKey);
  const namespaceID = name.split('.').slice(-1)[0];

  let newAddress = null;
  let zonefilePath = null;
  let zonefileHash = null;
  let zonefile = null;

  if (args.length >= 4) {
    // ID-address
    newAddress = args[3].slice(3);
  }
  else {
    newAddress = getPrivateKeyAddress(network, ownerKey);
  }

  if (args.length >= 5) {
    zonefilePath = args[4];
  }

  if (args.length >= 6) {
    zonefileHash = args[5];
    zonefilePath = null;
    console.log(`Using zone file hash ${zonefileHash} instead of zone file`);
  }

  if (zonefilePath) {
    zonefile = fs.readFileSync(zonefilePath).toString();
  }

  const ownerUTXOsPromise = network.getUTXOs(ownerAddress);
  const paymentUTXOsPromise = network.getUTXOs(paymentAddress);

  const estimatePromise = Promise.all([
      ownerUTXOsPromise, paymentUTXOsPromise])
    .then(([ownerUTXOs, paymentUTXOs]) => {
        const numOwnerUTXOs = ownerUTXOs.length;
        const numPaymentUTXOs = paymentUTXOs.length;
        return blockstack.transactions.estimateRenewal(
          name, network.coerceAddress(newAddress), 
          network.coerceAddress(ownerAddress),
          network.coerceAddress(paymentAddress), true, 
          numOwnerUTXOs + numPaymentUTXOs - 1);
      });

  const zonefilePromise = new Promise((resolve, reject) => {
    if (!!zonefile) {
      resolve(zonefile);
    } else if (!!zonefileHash) {
      // already have the hash 
      resolve(null);
    } else {
      return network.getNameInfo(name)
        .then((nameInfo) => {
          if (!!nameInfo.zonefile_hash) {
            return network.getZonefile(nameInfo.zonefile_hash)
              .then((zonefileData) => {
                resolve(zonefileData);
              })
              .catch((zonefileNetworkError) => reject(zonefileNetworkError));
          } else {
            // give an empty zonefile 
            resolve(null);
          };
        })
        .catch((nameNetworkError) => reject(nameNetworkError));
    }
  })
  .catch((e) => {
    console.error(e);
  });

  const txPromise = zonefilePromise.then((zonefileData) => {
    return blockstack.transactions.makeRenewal(
      name, newAddress, ownerKey, paymentKey, zonefileData, zonefileHash);
  });

  if (estimateOnly) {
    return estimatePromise;
  }
 
  if (!safetyChecks) {
    if (txOnly) {
      return txPromise;
    }
    else {
      return txPromise
        .then((tx) => {
          return network.broadcastTransaction(tx);
        });
    }
  }

  const paymentBalancePromise = paymentUTXOsPromise.then((utxos) => {
    return sumUTXOs(utxos);
  });

  const canReceiveNamePromise = Promise.resolve().then(() => {
    if (newAddress) {
      return blockstack.safety.addressCanReceiveName(network.coerceAddress(newAddress));
    }
    else {
      return true;
    }
  });

  const safetyChecksPromise = Promise.all([
      blockstack.safety.isNameValid(name),
      blockstack.safety.ownsName(name, network.coerceAddress(ownerAddress)),
      network.getNamespaceBurnAddress(namespaceID, true, receiveFeesPeriod),
      network.getNamespaceBurnAddress(namespaceID, false, receiveFeesPeriod),
      canReceiveNamePromise,
      network.getNamePrice(name),
      network.getAccountBalance(paymentAddress, 'STACKS'),
      estimatePromise,
      paymentBalancePromise,
    ])
    .then(([isNameValid, ownsName, givenNSBurnAddr, trueNSBurnAddr, 
           addressCanReceiveName, nameCost, 
           accountBalance, estimateCost, paymentBalance]) => {
      if (isNameValid && ownsName && addressCanReceiveName && 
          trueNSBurnAddr === givenNSBurnAddr &&
          (nameCost.units === 'BTC' || (nameCost.units == 'STACKS' &&
           nameCost.amount.compareTo(accountBalance) <= 0)) &&
          estimateCost < paymentBalance) {
        return {'status': true};
      }
      else {
        return JSONStringify({
          'status': false,
          'error': 'Name cannot be safely renewed',
          'isNameValid': isNameValid,
          'ownsName': ownsName,
          'addressCanReceiveName': addressCanReceiveName,
          'estimateCostBTC': estimateCost,
          'nameCostUnits': nameCost.units,
          'nameCostAmount': nameCost.amount.toString(),
          'paymentBalanceBTC': paymentBalance,
          'paymentBalanceStacks': accountBalance.toString(),
          'namespaceBurnAddress': givenNSBurnAddr,
          'trueNamespaceBurnAddress': trueNSBurnAddr,
        }, true);
      }
    });

  return safetyChecksPromise
    .then((safetyChecksResult) => {
      if (!safetyChecksResult.status) {
        return new Promise((resolve) => resolve(safetyChecksResult));
      }

      if (txOnly) {
        return txPromise;
      }

      return txPromise.then((tx) => {
        return network.broadcastTransaction(tx);
      })
      .then((txidHex) => {
        return txidHex;
      });
    });
}

/*
 * Generate and optionally send a name-revoke
 * args:
 * @name (string) the name to revoke
 * @ownerKey (string) the owner private key
 * @paymentKey (string) the payment private key
 */
function revoke(network: Object, args: Array<string>) {
  const name = args[0];
  const ownerKey = decodePrivateKey(args[1]);
  const paymentKey = decodePrivateKey(args[2]);
  const paymentAddress = getPrivateKeyAddress(network, paymentKey);
  const ownerAddress = getPrivateKeyAddress(network, ownerKey);

  const ownerUTXOsPromise = network.getUTXOs(ownerAddress);
  const paymentUTXOsPromise = network.getUTXOs(paymentAddress);

  const estimatePromise = Promise.all([
      ownerUTXOsPromise, paymentUTXOsPromise])
    .then(([ownerUTXOs, paymentUTXOs]) => {
        const numOwnerUTXOs = ownerUTXOs.length;
        const numPaymentUTXOs = paymentUTXOs.length;
        return blockstack.transactions.estimateRevoke(
          name, network.coerceAddress(ownerAddress),
          network.coerceAddress(paymentAddress),
          numOwnerUTXOs + numPaymentUTXOs - 1);
    });

  const txPromise =  blockstack.transactions.makeRevoke(
    name, ownerKey, paymentKey);

  if (estimateOnly) {
    return estimatePromise;
  }
 
  if (!safetyChecks) {
    if (txOnly) {
      return txPromise;
    }
    else {
      return txPromise
        .then((tx) => {
          return network.broadcastTransaction(tx);
        });
    }
  }

  const paymentBalancePromise = paymentUTXOsPromise.then((utxos) => {
    return sumUTXOs(utxos);
  });
 
  const safetyChecksPromise = Promise.all([
      blockstack.safety.isNameValid(name),
      blockstack.safety.ownsName(name, network.coerceAddress(ownerAddress)),
      blockstack.safety.isInGracePeriod(name),
      estimatePromise,
      paymentBalancePromise
    ])
    .then(([isNameValid, ownsName, isInGracePeriod, estimateCost, paymentBalance]) => {
      if (isNameValid && ownsName && !isInGracePeriod && estimateCost < paymentBalance) {
        return {'status': true};
      }
      else {
        return JSONStringify({
          'status': false,
          'error': 'Name cannot be safely revoked',
          'isNameValid': isNameValid,
          'ownsName': ownsName,
          'isInGracePeriod': isInGracePeriod,
          'estimateCostBTC': estimateCost,
          'paymentBalanceBTC': paymentBalance,
        }, true);
      }
    });

  return safetyChecksPromise
    .then((safetyChecksResult) => {
      if (!safetyChecksResult.status) {
        return new Promise((resolve) => resolve(safetyChecksResult));
      }

      if (txOnly) {
        return txPromise;
      }

      return txPromise.then((tx) => {
        return network.broadcastTransaction(tx);
      })
      .then((txidHex) => {
        return txidHex;
      });
    });
}

/*
 * Generate and optionally send a namespace-preorder
 * args:
 * @namespace (string) the namespace to preorder
 * @address (string) the address to reveal the namespace
 * @paymentKey (string) the payment private key
 */
function namespacePreorder(network: Object, args: Array<string>) {
  const namespaceID = args[0];
  const address = args[1];
  const paymentKey = decodePrivateKey(args[2]);
  const paymentAddress = getPrivateKeyAddress(network, paymentKey);

  const txPromise = blockstack.transactions.makeNamespacePreorder(
    namespaceID, address, paymentKey);

  const paymentUTXOsPromise = network.getUTXOs(paymentAddress);

  const estimatePromise = paymentUTXOsPromise.then((utxos) => {
        const numUTXOs = utxos.length;
        return blockstack.transactions.estimateNamespacePreorder(
          namespaceID, network.coerceAddress(address), 
          network.coerceAddress(paymentAddress), numUTXOs);
      });

  if (estimateOnly) {
    return estimatePromise;
  }
  
  if (!safetyChecks) {
    if (txOnly) {
      return txPromise;
    }
    else {
      return txPromise
        .then((tx) => {
          return network.broadcastTransaction(tx);
        });
    }
  }

  const paymentBalance = paymentUTXOsPromise.then((utxos) => {
    return sumUTXOs(utxos);
  });

  const safetyChecksPromise = Promise.all([
      blockstack.safety.isNamespaceValid(namespaceID),
      blockstack.safety.isNamespaceAvailable(namespaceID),
      network.getNamespacePrice(namespaceID),
      network.getAccountBalance(paymentAddress, 'STACKS'),
      paymentBalance,
      estimatePromise
    ])
    .then(([isNamespaceValid, isNamespaceAvailable, namespacePrice,
            STACKSBalance, paymentBalance, estimate]) => {
      if (isNamespaceValid && isNamespaceAvailable && 
          (namespacePrice.units === 'BTC' || 
            (namespacePrice.units === 'STACKS' && 
             namespacePrice.amount.compareTo(STACKSBalance) <= 0)) &&
          paymentBalance >= estimate) {
        return {'status': true};
      }
      else {
        return JSONStringify({
          'status': false,
          'error': 'Namespace cannot be safely preordered',
          'isNamespaceValid': isNamespaceValid,
          'isNamespaceAvailable': isNamespaceAvailable,
          'paymentBalanceBTC': paymentBalance,
          'paymentBalanceStacks': STACKSBalance.toString(),
          'namespaceCostUnits': namespacePrice.units,
          'namespaceCostAmount': namespacePrice.amount.toString(),
          'estimateCostBTC': estimate,
        }, true);
      }
    });

  return safetyChecksPromise
    .then((safetyChecksResult) => {
      if (!safetyChecksResult.status) {
        return new Promise((resolve) => resolve(safetyChecksResult));
      }

      if (txOnly) {
        return txPromise;
      }

      return txPromise.then((tx) => {
        return network.broadcastTransaction(tx);
      })
      .then((txidHex) => {
        return txidHex;
      });
    });
}

/*
 * Generate and optionally send a namespace-reveal
 * args:
 * @name (string) the namespace to reveal
 * @revealAddr (string) the reveal address
 * @version (int) the namespace version bits
 * @lifetime (int) the name lifetime
 * @coeff (int) the multiplicative price coefficient
 * @base (int) the price base
 * @bucketString (string) the serialized bucket exponents
 * @nonalphaDiscount (int) the non-alpha price discount
 * @noVowelDiscount (int) the no-vowel price discount
 * @paymentKey (string) the payment private key
 */
function namespaceReveal(network: Object, args: Array<string>) {
  const namespaceID = args[0];
  const revealAddr = args[1];
  const version = parseInt(args[2]);
  let lifetime = parseInt(args[3]);
  const coeff = parseInt(args[4]);
  const base = parseInt(args[5]);
  const bucketString = args[6];
  const nonalphaDiscount = parseInt(args[7]);
  const noVowelDiscount = parseInt(args[8]);
  const paymentKey = decodePrivateKey(args[9]);

  const buckets = bucketString.split(',')
    .map((x) => {return parseInt(x)});

  if (lifetime < 0) {
    lifetime = 2**32 - 1;
  }

  if (nonalphaDiscount === 0) {
    throw new Error("Cannot have a 0 non-alpha discount (pass 1 for no discount)");
  }

  if (noVowelDiscount === 0) {
    throw new Error("Cannot have a 0 no-vowel discount (pass 1 for no discount)");
  }

  const namespace = new blockstack.transactions.BlockstackNamespace(namespaceID);

  namespace.setVersion(version);
  namespace.setLifetime(lifetime);
  namespace.setCoeff(coeff);
  namespace.setBase(base);
  namespace.setBuckets(buckets);
  namespace.setNonalphaDiscount(nonalphaDiscount);
  namespace.setNoVowelDiscount(noVowelDiscount);

  const paymentAddress = getPrivateKeyAddress(network, paymentKey);
  const paymentUTXOsPromise = network.getUTXOs(paymentAddress);

  const estimatePromise = paymentUTXOsPromise.then((utxos) => {
        const numUTXOs = utxos.length;
        return blockstack.transactions.estimateNamespaceReveal(
          namespace, network.coerceAddress(revealAddr),
          network.coerceAddress(paymentAddress), numUTXOs);
      });

  const txPromise = blockstack.transactions.makeNamespaceReveal(
    namespace, revealAddr, paymentKey);

  if (estimateOnly) {
    return estimatePromise;
  }
 
  if (!safetyChecks) {
    if (txOnly) {
      return txPromise;
    }
    else {
      return txPromise
        .then((tx) => {
          return network.broadcastTransaction(tx);
        });
    }
  }

  const paymentBalancePromise = paymentUTXOsPromise.then((utxos) => {
    return sumUTXOs(utxos);
  });
 
  const safetyChecksPromise = Promise.all([
      blockstack.safety.isNamespaceValid(namespaceID),
      blockstack.safety.isNamespaceAvailable(namespaceID),
      paymentBalancePromise,
      estimatePromise
    ])
    .then(([isNamespaceValid, isNamespaceAvailable,
            paymentBalance, estimate]) => {

      if (isNamespaceValid && isNamespaceAvailable && 
          paymentBalance >= estimate) {
        return {'status': true};
      }
      else {
        return JSONStringify({
          'status': false,
          'error': 'Namespace cannot be safely revealed',
          'isNamespaceValid': isNamespaceValid,
          'isNamespaceAvailable': isNamespaceAvailable,
          'paymentBalanceBTC': paymentBalance,
          'estimateCostBTC': estimate,
        }, true);
      }
    });
  
  return safetyChecksPromise
    .then((safetyChecksResult) => {
      if (!safetyChecksResult.status) {
        return new Promise((resolve) => resolve(safetyChecksResult));
      }

      if (txOnly) {
        return txPromise;
      }

      return txPromise.then((tx) => {
        return network.broadcastTransaction(tx);
      })
      .then((txidHex) => {
        return txidHex;
      });
    });
}

/*
 * Generate and optionally send a namespace-ready
 * args:
 * @namespaceID (string) the namespace ID
 * @revealKey (string) the hex-encoded reveal key
 */
function namespaceReady(network: Object, args: Array<string>) {
  const namespaceID = args[0];
  const revealKey = decodePrivateKey(args[1]);
  const revealAddress = getPrivateKeyAddress(network, revealKey);

  const txPromise = blockstack.transactions.makeNamespaceReady(
    namespaceID, revealKey);

  const revealUTXOsPromise = network.getUTXOs(revealAddress);

  const estimatePromise = revealUTXOsPromise.then((utxos) => {
        const numUTXOs = utxos.length;
        return blockstack.transactions.estimateNamespaceReady(
          namespaceID, numUTXOs);
      });

  if (estimateOnly) {
    return estimatePromise;
  }
  
  if (!safetyChecks) {
    if (txOnly) {
      return txPromise;
    }
    else {
      return txPromise
        .then((tx) => {
          return network.broadcastTransaction(tx);
        });
    }
  }

  const revealBalancePromise = revealUTXOsPromise.then((utxos) => {
    return sumUTXOs(utxos);
  });

  const safetyChecksPromise = Promise.all([
      blockstack.safety.isNamespaceValid(namespaceID),
      blockstack.safety.namespaceIsReady(namespaceID),
      blockstack.safety.revealedNamespace(namespaceID, revealAddress),
      revealBalancePromise,
      estimatePromise
    ])
    .then(([isNamespaceValid, isNamespaceReady, isRevealer,
            revealerBalance, estimate]) => {
      if (isNamespaceValid && !isNamespaceReady && isRevealer &&
          revealerBalance >= estimate) {
        return {'status': true};
      }
      else {
        return JSONStringify({
          'status': false,
          'error': 'Namespace cannot be safely launched',
          'isNamespaceValid': isNamespaceValid,
          'isNamespaceReady': isNamespaceReady,
          'isPrivateKeyRevealer': isRevealer,
          'revealerBalanceBTC': revealerBalance,
          'estimateCostBTC': estimate
        }, true);
      }
    });

  return safetyChecksPromise
    .then((safetyChecksResult) => {
      if (!safetyChecksResult.status) {
        return new Promise((resolve) => resolve(safetyChecksResult));
      }

      if (txOnly) {
        return txPromise;
      }

      return txPromise.then((tx) => {
        return network.broadcastTransaction(tx);
      })
      .then((txidHex) => {
        return txidHex;
      });
    });
}

/*
 * Broadcast a transaction and a zone file.
 * Returns an object that encodes the success/failure of doing so.
 * If zonefile is None, then only the transaction will be sent.
 */
function broadcastTransactionAndZoneFile(network: Object, tx: String, zonefile: ?string = null) {
  let txid;
  return Promise.resolve().then(() => {
    return network.broadcastTransaction(tx);
  })
  .then((_txid) => {
    txid = _txid;
    if (zonefile) {
      return network.broadcastZoneFile(zonefile, txid);
    }
    else {
      return { 'status': true };
    }
  })
  .then((resp) => {
    if (!resp.status) {
      return {
        'status': false,
        'error': 'Failed to broadcast zone file',
        'txid': txid
      };
    }
    else {
      return {
        'status': true,
        'txid': txid
      };
    }
  })
  .catch((e) => {
    return {
      'status': false,
      'error': 'Caught exception sending transaction or zone file',
      'message': e.message,
      'stacktrace': e.stack
    }
  });
}


/*
 * Generate and send a name-import transaction
 * @name (string) the name to import
 * @IDrecipientAddr (string) the recipient of the name
 * @gaiaHubURL (string) the URL to the name's gaia hub
 * @importKey (string) the key to pay for the import
 * @zonefile (string) OPTIONAL: the path to the zone file to use (supercedes gaiaHubUrl)
 * @zonefileHash (string) OPTIONAL: the hash of the zone file (supercedes gaiaHubUrl and zonefile)
 */
function nameImport(network: Object, args: Array<string>) {
  const name = args[0];
  const IDrecipientAddr = args[1];
  const gaiaHubUrl = args[2];
  const importKey = decodePrivateKey(args[3]);
  let zonefilePath = args[4]
  let zonefileHash = args[5];
  let zonefile = null;

  if (safetyChecks && (typeof importKey !== 'string')) {
    // multisig import not supported, unless we're testing 
    throw new Error('Invalid argument: multisig is not supported at this time');
  }

  if (!IDrecipientAddr.startsWith('ID-')) {
    throw new Error("Recipient ID-address must start with ID-");
  }

  const recipientAddr = IDrecipientAddr.slice(3);

  if (zonefilePath && !zonefileHash) {
    zonefile = fs.readFileSync(zonefilePath).toString();
  }

  else if (!zonefileHash && !zonefilePath) {
    // make zone file and hash from gaia hub url
    const mainnetAddress = network.coerceMainnetAddress(recipientAddr);
    const profileUrl = `${gaiaHubUrl}/hub/${mainnetAddress}/profile.json`;
    try {
      checkUrl(profileUrl);
    }
    catch(e) {
      return Promise.resolve().then(() => JSONStringify({
        'status': false,
        'error': e.message,
        'hints': [
          'Make sure the Gaia hub URL does not have any trailing /\'s',
          'Make sure the Gaia hub URL scheme is present and well-formed',
        ],
      }, true));
    }

    zonefile = blockstack.makeProfileZoneFile(name, profileUrl);
    zonefileHash = hash160(Buffer.from(zonefile)).toString('hex');
  }

  const namespaceID = name.split('.').slice(-1);
  const importAddress = getPrivateKeyAddress(network, importKey);

  const txPromise = blockstack.transactions.makeNameImport(
    name, recipientAddr, zonefileHash, importKey);

  const importUTXOsPromise = network.getUTXOs(importAddress);

  const estimatePromise = importUTXOsPromise.then((utxos) => {
        const numUTXOs = utxos.length;
        return blockstack.transactions.estimateNameImport(
          name, recipientAddr, zonefileHash, numUTXOs);
      });

  if (estimateOnly) {
    return estimatePromise;
  }
 
  if (!safetyChecks) {
    if (txOnly) {
      return txPromise;
    }
    else {
      return txPromise
        .then((tx) => {
          return broadcastTransactionAndZoneFile(network, tx, zonefile)
        })
        .then((resp) => {
          if (resp.status && resp.hasOwnProperty('txid')) {
            // just return txid 
            return resp.txid;
          }
          else {
            // some error 
            return JSONStringify(resp, true);
          }
        });
    }
  }

  const importBalancePromise = importUTXOsPromise.then((utxos) => {
    return sumUTXOs(utxos);
  });

  const safetyChecksPromise = Promise.all([
      blockstack.safety.namespaceIsReady(namespaceID),
      blockstack.safety.namespaceIsRevealed(namespaceID),
      blockstack.safety.addressCanReceiveName(recipientAddr),
      importBalancePromise,
      estimatePromise
    ])
    .then(([isNamespaceReady, isNamespaceRevealed, addressCanReceive,
            importBalance, estimate]) => {
      if (!isNamespaceReady && isNamespaceRevealed && addressCanReceive &&
          importBalance >= estimate) {
        return {'status': true};
      }
      else {
        return JSONStringify({
          'status': false,
          'error': 'Name cannot be safetly imported',
          'isNamespaceReady': isNamespaceReady,
          'isNamespaceRevealed': isNamespaceRevealed,
          'addressCanReceiveName': addressCanReceive,
          'importBalanceBTC': importBalance,
          'estimateCostBTC': estimate
        }, true);
      }
  });

  return safetyChecksPromise
    .then((safetyChecksResult) => {
      if (!safetyChecksResult.status) {
        return new Promise((resolve) => resolve(safetyChecksResult));
      }

      if (txOnly) {
        return txPromise;
      }

      return txPromise
        .then((tx) => {
          return broadcastTransactionAndZoneFile(network, tx, zonefile)
        })
        .then((resp) => {
          if (resp.status && resp.hasOwnProperty('txid')) {
            // just return txid 
            return resp.txid;
          }
          else {
            // some error 
            return JSONStringify(resp, true);
          }
        });
    });
}


/*
 * Announce a message to subscribed peers by means of an Atlas zone file
 * @messageHash (string) the hash of the already-sent message
 * @senderKey (string) the key that owns the name that the peers have subscribed to
 */
function announce(network: Object, args: Array<string>) {
  const messageHash = args[0];
  const senderKey = decodePrivateKey(args[1]);

  const senderAddress = getPrivateKeyAddress(network, senderKey);

  const txPromise = blockstack.transactions.makeAnnounce(
    messageHash, senderKey);

  const senderUTXOsPromise = network.getUTXOs(senderAddress);

  const estimatePromise = senderUTXOsPromise.then((utxos) => {
    const numUTXOs = utxos.length;
    return blockstack.transactions.estimateAnnounce(messageHash, numUTXOs)
  });

  if (estimateOnly) {
    return estimatePromise;
  }
  
  if (!safetyChecks) {
    if (txOnly) {
      return txPromise;
    }
    else {
      return txPromise
        .then((tx) => {
          return network.broadcastTransaction(tx);
        });
    }
  }

  const senderBalancePromise = senderUTXOsPromise.then((utxos) => {
    return sumUTXOs(utxos);
  });

  const safetyChecksPromise = Promise.all(
     [senderBalancePromise, estimatePromise])
    .then(([senderBalance, estimate]) => {
      if (senderBalance >= estimate) {
        return {'status': true};
      }
      else {
        return JSONStringify({
          'status': false,
          'error': 'Announcement cannot be safely sent',
          'senderBalanceBTC': senderBalance,
          'estimateCostBTC': estimate
        }, true);
      }
  });

  return safetyChecksPromise
    .then((safetyChecksResult) => {
      if (!safetyChecksResult.status) {
        return new Promise((resolve) => resolve(safetyChecksResult));
      }

      if (txOnly) {
        return txPromise;
      }

      return txPromise.then((tx) => {
        return network.broadcastTransaction(tx);
      })
      .then((txidHex) => {
        return txidHex;
      });
    });
}


/*
 * Register a name the easy way.  Send the preorder
 * and register transactions to the broadcaster, as 
 * well as the zone file.  Also create and replicate
 * the profile to the Gaia hub.
 * @arg name (string) the name to register
 * @arg ownerKey (string) the hex-encoded owner private key (must be singlesig)
 * @arg paymentKey (string) the hex-encoded payment key to purchase this name
 * @arg gaiaHubUrl (string) the gaia hub URL to use
 * @arg zonefile (string) OPTIONAL the path to the zone file to give this name.
 *  supercedes gaiaHubUrl
 */
function register(network: Object, args: Array<string>) {
  const name = args[0];
  const ownerKey = decodePrivateKey(args[1]);
  const paymentKey = decodePrivateKey(args[2]);
  const gaiaHubUrl = args[3];

  const address = getPrivateKeyAddress(network, ownerKey);
  const mainnetAddress = network.coerceMainnetAddress(address)
  const emptyProfile = {type: '@Person', account: []};

  let zonefilePromise = null;

  if (args.length > 4) {
    const zonefilePath = args[4];
    zonefilePromise = Promise.resolve().then(() => fs.readFileSync(zonefilePath).toString());
  }
  else {
    // generate one
    zonefilePromise = makeZonefileFromGaiaUrl(network, name, gaiaHubUrl, ownerKey);
  }

  let preorderTx = "";
  let registerTx = "";
  let broadcastResult = null;
  let zonefile = null;

  return zonefilePromise.then((zf) => {

    zonefile = zf;

    // carry out safety checks for preorder and register
    const preorderSafetyCheckPromise = txPreorder(
      network, [name, `ID-${address}`, paymentKey], true);

    const registerSafetyCheckPromise = txRegister(
      network, [name, `ID-${address}`, paymentKey, zf], true);

    return Promise.all([preorderSafetyCheckPromise, registerSafetyCheckPromise])
  })
  .then(([preorderSafetyChecks, registerSafetyChecks]) => {
    if ((preorderSafetyChecks.hasOwnProperty('status') && !preorderSafetyChecks.status) || 
        (registerSafetyChecks.hasOwnProperty('status') && !registerSafetyChecks.status)) {
      // one or both safety checks failed 
      throw new SafetyError({
        'status': false,
        'error': 'Failed to generate one or more transactions',
        'preorderSafetyChecks': preorderSafetyChecks,
        'registerSafetyChecks': registerSafetyChecks,
      });
    }

    // will have only gotten back the raw tx (which we'll discard anyway,
    // since we have to use the right UTXOs)
    return blockstack.transactions.makePreorder(name, address, paymentKey);
  })
  .then((rawTx) => {
    preorderTx = rawTx;
    return rawTx;
  })
  .then((rawTx) => {
    // make it so that when we generate the NAME_REGISTRATION operation,
    // we consume the change output from the NAME_PREORDER.
    network.modifyUTXOSetFrom(rawTx);
    return rawTx;
  })
  .then(() => {
    // now we can make the NAME_REGISTRATION 
    return blockstack.transactions.makeRegister(name, address, paymentKey, zonefile);
  })
  .then((rawTx) => {
    registerTx = rawTx;
    return rawTx;
  })
  .then((rawTx) => {
    // make sure we don't double-spend the NAME_REGISTRATION before it is broadcasted
    network.modifyUTXOSetFrom(rawTx);
  })
  .then(() => {
    if (txOnly) {
      return Promise.resolve().then(() => { 
        const txData = {
          preorder: preorderTx,
          register: registerTx,
          zonefile: zonefile,
        };
        return txData;   
      });
    }
    else {
      return network.broadcastNameRegistration(preorderTx, registerTx, zonefile);
    }
  })
  .then((txResult) => {
    // sign and upload profile
    broadcastResult = txResult;
    const signedProfileData = makeProfileJWT(emptyProfile, ownerKey);
    return gaiaUploadProfileAll(
      network, [gaiaHubUrl], 'profile.json', signedProfileData, ownerKey);
  })
  .then((gaiaUrls) => {
    if (gaiaUrls.hasOwnProperty('error')) {
      return JSONStringify({
        'profileUrls': gaiaUrls,
        'txInfo': broadcastResult
      }, true);
    }
    return JSONStringify({
      'profileUrls': gaiaUrls.dataUrls, 
      'txInfo': broadcastResult
    });
  })
  .catch((e) => {
    if (e.hasOwnProperty('safetyErrors')) {
      // safety error; return as JSON 
      return e.message;
    }
    else {
      throw e;
    }
  });
}

/*
 * Register a name the easy way to an ID-address.  Send the preorder
 * and register transactions to the broadcaster, as 
 * well as the zone file.
 * @arg name (string) the name to register
 * @arg ownerAddress (string) the ID-address of the owner
 * @arg paymentKey (string) the hex-encoded payment key to purchase this name
 * @arg gaiaHubUrl (string) the gaia hub URL to use
 * @arg zonefile (string) OPTIONAL the path to the zone file to give this name.
 *  supercedes gaiaHubUrl
 */
function registerAddr(network: Object, args: Array<string>) {
  const name = args[0];
  const IDaddress = args[1];
  const paymentKey = decodePrivateKey(args[2]);
  const gaiaHubUrl = args[3];

  const address = IDaddress.slice(3);
  const mainnetAddress = network.coerceMainnetAddress(address)

  let zonefile = "";
  if (args.length > 4) {
    const zonefilePath = args[4];
    zonefile = fs.readFileSync(zonefilePath).toString();
  }
  else {
    // generate one 
    const profileUrl = `${gaiaHubUrl}/hub/${mainnetAddress}/profile.json`;
    try {
      checkUrl(profileUrl);
    }
    catch(e) {
      return Promise.resolve().then(() => JSONStringify({
        'status': false,
        'error': e.message,
        'hints': [
          'Make sure the Gaia hub URL does not have any trailing /\'s',
          'Make sure the Gaia hub URL scheme is present and well-formed',
        ],
      }));
    }

    zonefile = blockstack.makeProfileZoneFile(name, profileUrl);
  }

  let preorderTx = "";
  let registerTx = "";

  // carry out safety checks for preorder and register 
  const preorderSafetyCheckPromise = txPreorder(
    network, [name, `ID-${address}`, paymentKey], true);

  const registerSafetyCheckPromise = txRegister(
    network, [name, `ID-${address}`, paymentKey, zonefile], true);

  return Promise.all([preorderSafetyCheckPromise, registerSafetyCheckPromise])
    .then(([preorderSafetyChecks, registerSafetyChecks]) => {
      if ((preorderSafetyChecks.hasOwnProperty('status') && !preorderSafetyChecks.status) || 
          (registerSafetyChecks.hasOwnProperty('status') && !registerSafetyChecks.status)) {
        // one or both safety checks failed 
        throw new SafetyError({
          'status': false,
          'error': 'Failed to generate one or more transactions',
          'preorderSafetyChecks': preorderSafetyChecks,
          'registerSafetyChecks': registerSafetyChecks,
        });
      }

      // will have only gotten back the raw tx (which we'll discard anyway,
      // since we have to use the right UTXOs)
      return blockstack.transactions.makePreorder(name, address, paymentKey);
    })
    .then((rawTx) => {
      preorderTx = rawTx;
      return rawTx;
    })
    .then((rawTx) => {
      // make it so that when we generate the NAME_REGISTRATION operation,
      // we consume the change output from the NAME_PREORDER.
      network.modifyUTXOSetFrom(rawTx);
      return rawTx;
    })
    .then(() => {
      // now we can make the NAME_REGISTRATION 
      return blockstack.transactions.makeRegister(name, address, paymentKey, zonefile);
    })
    .then((rawTx) => {
      registerTx = rawTx;
      return rawTx;
    })
    .then((rawTx) => {
      // make sure we don't double-spend the NAME_REGISTRATION before it is broadcasted
      network.modifyUTXOSetFrom(rawTx);
    })
    .then(() => {
      if (txOnly) {
        return Promise.resolve().then(() => { 
          const txData = {
            preorder: preorderTx,
            register: registerTx,
            zonefile: zonefile,
          };
          return txData;   
        });
      }
      else {
        return network.broadcastNameRegistration(preorderTx, registerTx, zonefile);
      }
    })
    .then((txResult) => {
      // succcess! 
      return JSONStringify({
        'txInfo': txResult
      });
    })
    .catch((e) => {
      if (e.hasOwnProperty('safetyErrors')) {
        // safety error; return as JSON 
        return e.message;
      }
      else {
        throw e;
      }
    });
}


/*
 * Register a subdomain name the easy way.  Send the
 * zone file and signed subdomain records to the subdomain registrar.
 * @arg name (string) the name to register
 * @arg ownerKey (string) the hex-encoded owner private key (must be single-sig)
 * @arg gaiaHubUrl (string) the gaia hub URL to use
 * @arg registrarUrl (string) OPTIONAL the registrar URL
 * @arg zonefile (string) OPTIONAL the path to the zone file to give this name.
 *  supercedes gaiaHubUrl
 */
function registerSubdomain(network: Object, args: Array<string>) {
  const name = args[0];
  const ownerKey = decodePrivateKey(args[1]);
  const gaiaHubUrl = args[2];
  const registrarUrl = args[3];

  const address = getPrivateKeyAddress(network, ownerKey);
  const mainnetAddress = network.coerceMainnetAddress(address)
  const emptyProfile = {type: '@Person', account: []};
  const onChainName = name.split('.').slice(-2).join('.');
  const subName = name.split('.')[0];

  let zonefilePromise = null;

  // TODO: fix this once the subdomain registrar will tell us the on-chain name
  console.log(`WARNING: not yet able to verify that ${registrarUrl} is the registrar ` +
              `for ${onChainName}; assuming that it is...`);

  if (args.length > 4) {
    const zonefilePath = args[4];
    zonefilePromise = Promise.resolve().then(() => fs.readFileSync(zonefilePath).toString());
  }
  else {
    // generate one 
    zonefilePromise = makeZonefileFromGaiaUrl(network, name, gaiaHubUrl, ownerKey);
  }

  let broadcastResult = null;
  let api_key = process.env.API_KEY || null;

  const onChainNamePromise = getNameInfo(network, onChainName);
  const registrarStatusPromise = fetch(`${registrarUrl}/index`)
    .then((resp) => resp.json());

  const profileUploadPromise = Promise.resolve().then(() => {
      // sign and upload profile
      const signedProfileData = makeProfileJWT(emptyProfile, ownerKey);
      return gaiaUploadProfileAll(
        network, [gaiaHubUrl], 'profile.json', signedProfileData, ownerKey);
    })
    .then((gaiaUrls) => {
      if (gaiaUrls.hasOwnProperty('error')) {
        return JSONStringify(gaiaUrls, true);
      }
      else {
        return JSONStringify({
          'profileUrls': gaiaUrls.dataUrls, 
        });
      }
    });

  let safetyChecksPromise = null;
  if (safetyChecks) {
    safetyChecksPromise = Promise.all([
        onChainNamePromise,
        blockstack.safety.isNameAvailable(name),
        registrarStatusPromise
      ])
      .then(([onChainNameInfo, isNameAvailable, registrarStatus]) => {
        if (safetyChecks) {
          const registrarName =
            (!!registrarStatus && registrarStatus.hasOwnProperty('domainName')) ?
            registrarStatus.domainName :
            '<unknown>';

          if (!onChainNameInfo || !isNameAvailable || 
              (registrarName !== '<unknown>' && registrarName !== onChainName)) {
            return {
              'status': false,
              'error': 'Subdomain cannot be safely registered',
              'onChainNameInfo': onChainNameInfo,
              'isNameAvailable': isNameAvailable,
              'onChainName': onChainName,
              'registrarName': registrarName
            };
          }
        }
        return { 'status': true }
      });
  }
  else {
    safetyChecksPromise = Promise.resolve().then(() => {
      return {
        'status': true
      };
    });
  }

  return Promise.all([safetyChecksPromise, zonefilePromise])
  .then(([safetyChecks, zonefile]) => {
    if (safetyChecks.status) {
      const request = {
        'zonefile': zonefile,
        'name': subName,
        'owner_address': mainnetAddress
      };

      let options = {
        method: 'POST',
        headers: {
          'Content-type': 'application/json',
          'Authorization': ''
        },
        body: JSON.stringify(request)
      };

      if (!!api_key) {
        options.headers.Authorization = `bearer ${api_key}`;
      }

      const registerPromise = fetch(`${registrarUrl}/register`, options)
        .then(resp => resp.json())

      return Promise.all([registerPromise, profileUploadPromise])
        .then(([registerInfo, profileUploadInfo]) => {
          return JSONStringify({
            'txInfo': registerInfo,
            'profileUrls': profileUploadInfo.profileUrls,
          });
        });
    }
    else {
      return Promise.resolve().then(() => JSONStringify(safetyChecks, true))
    }
  });
}

/*
 * Sign a profile.
 * @path (string) path to the profile
 * @privateKey (string) the owner key (must be single-sig)
 */
function profileSign(network: Object, args: Array<string>) {
  const profilePath = args[0];
  const privateKey = decodePrivateKey(args[1]);
  const profileData = JSON.parse(fs.readFileSync(profilePath).toString());
  return Promise.resolve().then(() => makeProfileJWT(profileData, privateKey));
}

/*
 * Verify a profile with an address or public key
 * @path (string) path to the profile
 * @publicKeyOrAddress (string) public key or address
 */
function profileVerify(network: Object, args: Array<string>) {
  const profilePath = args[0];
  let publicKeyOrAddress = args[1];

  // need to coerce mainnet 
  if (publicKeyOrAddress.match(ID_ADDRESS_PATTERN)) {
    publicKeyOrAddress = network.coerceMainnetAddress(publicKeyOrAddress.slice(3));
  }
  
  const profileString = fs.readFileSync(profilePath).toString();
  
  return Promise.resolve().then(() => {
    let profileToken = null;
    
    try {
      const profileTokens = JSON.parse(profileString);
      profileToken = profileTokens[0].token;
    }
    catch (e) {
      // might be a raw token 
      profileToken = profileString;
    }

    if (!profileToken) {
      throw new Error(`Data at ${profilePath} does not appear to be a signed profile`);
    }
   
    const profile = blockstack.extractProfile(profileToken, publicKeyOrAddress);
    return JSONStringify(profile);
  });
}

/*
 * Upload profile data to a Gaia hub
 * @gaiaHubUrl (string) the base scheme://host:port URL to the Gaia hub
 * @gaiaData (string) the data to upload
 * @privateKey (string) the private key to use to sign the challenge
 */
function gaiaUploadProfile(network: Object,
                           gaiaHubURL: string, 
                           gaiaPath: string,
                           gaiaData: string,
                           privateKey: string) {
  return gaiaConnect(network, gaiaHubURL, privateKey)
    .then((hubConfig) => {
      return blockstack.uploadToGaiaHub(gaiaPath, gaiaData, hubConfig);
    });
}

/*
 * Upload profile data to all Gaia hubs, given a zone file
 * @network (object) the network to use
 * @gaiaUrls (array) list of Gaia URLs
 * @gaiaPath (string) the path to the file to store in Gaia
 * @gaiaData (string) the data to store
 * @privateKey (string) the hex-encoded private key
 * @return a promise with {'dataUrls': [urls to the data]}, or {'error': ...}
 */
function gaiaUploadProfileAll(network: Object, gaiaUrls: Array<string>, gaiaPath: string, 
  gaiaData: string, privateKey: string) : Promise<*> {

  const sanitizedGaiaUrls = gaiaUrls.map((gaiaUrl) => {
    const urlInfo = URL.parse(gaiaUrl);
    if (!urlInfo.protocol) {
      return '';
    }
    if (!urlInfo.host) {
      return '';
    }
    // keep flow happy
    return `${String(urlInfo.protocol)}//${String(urlInfo.host)}`;
  })
  .filter((gaiaUrl) => gaiaUrl.length > 0);

  const uploadPromises = sanitizedGaiaUrls.map((gaiaUrl) => 
    gaiaUploadProfile(network, gaiaUrl, gaiaPath, gaiaData, privateKey));

  return Promise.all(uploadPromises)
    .then((publicUrls) => {
      return { 'dataUrls': publicUrls };
    });
}

/*
 * Make a zone file from a Gaia hub---reach out to the Gaia hub, get its read URL prefix,
 * and generate a zone file with the profile mapped to the Gaia hub.
 *
 * @network (object) the network connection
 * @name (string) the name that owns the zone file
 * @gaiaHubUrl (string) the URL to the gaia hub write endpoint
 * @ownerKey (string) the owner private key
 *
 * Returns a promise that resolves to the zone file with the profile URL
 */
function makeZonefileFromGaiaUrl(network: Object, name: string, 
  gaiaHubUrl: string, ownerKey: string) {

  const address = getPrivateKeyAddress(network, ownerKey);
  const mainnetAddress = network.coerceMainnetAddress(address)

  return gaiaConnect(network, gaiaHubUrl, ownerKey)
    .then((hubConfig) => {
      if (!hubConfig.url_prefix) {
        throw new Error('Invalid hub config: no read_url_prefix defined');
      }
      const gaiaReadUrl = hubConfig.url_prefix.replace(/\/+$/, "");
      const profileUrl = `${gaiaReadUrl}/${mainnetAddress}/profile.json`;
      try {
        checkUrl(profileUrl);
      }
      catch(e) {
        throw new SafetyError({
          'status': false,
          'error': e.message,
          'hints': [
            'Make sure the Gaia hub read URL scheme is present and well-formed.',
            `Check the "read_url_prefix" field of ${gaiaHubUrl}/hub_info`
          ],
        });
      }
      return blockstack.makeProfileZoneFile(name, profileUrl);
    });
}

/*
 * Store a signed profile for a name or an address.
 * * verify that the profile was signed by the name's owner address
 * * verify that the private key matches the name's owner address
 *
 * Assumes that the URI records are all Gaia hubs
 *
 * @nameOrAddress (string) name or address that owns the profile
 * @path (string) path to the signed profile token
 * @privateKey (string) owner private key for the name
 * @gaiaUrl (string) this is the write endpoint of the Gaia hub to use
 */
function profileStore(network: Object, args: Array<string>) {
  let nameOrAddress = args[0];
  const signedProfilePath = args[1];
  const privateKey = decodePrivateKey(args[2]);
  const gaiaHubUrl = args[3];

  const signedProfileData = fs.readFileSync(signedProfilePath).toString();

  const ownerAddress = getPrivateKeyAddress(network, privateKey);
  let ownerAddressMainnet = network.coerceMainnetAddress(ownerAddress);

  let nameInfoPromise = null;

  if (nameOrAddress.startsWith('ID-')) {
    // ID-address
    nameInfoPromise = Promise.resolve().then(() => {
      return {
        'address': nameOrAddress.slice(3)
      }
    });
  }
  else {
    // name; find the address 
    nameInfoPromise = getNameInfo(network, nameOrAddress);
  }
  
  const verifyProfilePromise = profileVerify(network, 
    [signedProfilePath, `ID-${ownerAddressMainnet}`]);
   
  return Promise.all([nameInfoPromise, verifyProfilePromise])
    .then(([nameInfo, verifiedProfile]) => {
      if (safetyChecks && (!nameInfo ||
          network.coerceAddress(nameInfo.address) !== network.coerceAddress(ownerAddress))) {
        throw new Error(`Name owner address either could not be found, or does not match ` +
          `private key address ${ownerAddress}`);
      }
      return gaiaUploadProfileAll(
        network, [gaiaHubUrl], 'profile.json', signedProfileData, privateKey);
    })
    .then((gaiaUrls) => {
      if (gaiaUrls.hasOwnProperty('error')) {
        return JSONStringify(gaiaUrls, true);
      }
      else {
        return JSONStringify({'profileUrls': gaiaUrls.dataUrls});
      }
    });
}

/*
 * Push a zonefile to the Atlas network
 * @zonefileDataOrPath (string) the zonefile data to push, or the path to the data
 */
function zonefilePush(network: Object, args: Array<string>) {
  const zonefileDataOrPath = args[0];
  let zonefileData = null;

  try {
    zonefileData = fs.readFileSync(zonefileDataOrPath).toString();
  } catch(e) {
    zonefileData = zonefileDataOrPath;
  }

  return network.broadcastZoneFile(zonefileData)
    .then((result) => {
      return JSONStringify(result);
    });
}

/*
 * Get the app private key(s) from a backup phrase and an ID-address
 * args:
 * @mnemonic (string) the 12-word phrase
 * @idAddress (string) the ID-address
 * @appOrigin (string) the application's origin URL
 */
function getAppKeys(network: Object, args: Array<string>) {
  const mnemonic = args[0];
  const idAddress = args[1];
  const origin = args[2];
  const appKeyInfo = getApplicationKeyInfo(network, mnemonic, idAddress, origin);
  return Promise.resolve().then(() => JSONStringify(appKeyInfo));
}

/*
 * Get the owner private key(s) from a backup phrase
 * args:
 * @mnemonic (string) the 12-word phrase
 * @max_index (integer) (optional) the profile index maximum
 */
function getOwnerKeys(network: Object, args: Array<string>) {
  const mnemonic = args[0];
  let maxIndex = 1;
  if (args.length > 1) {
    maxIndex = parseInt(args[1]);
  }

  let keyInfo = [];
  for (let i = 0; i < maxIndex; i++) {
    keyInfo.push(getOwnerKeyInfo(network, mnemonic, i));
  }
  
  return Promise.resolve().then(() => JSONStringify(keyInfo));
}

/*
 * Get the payment private key from a backup phrase 
 * args:
 * @mnemonic (string) the 12-word phrase
 */
function getPaymentKey(network: Object, args: Array<string>) {
  const mnemonic = args[0];
  
  // keep the return value consistent with getOwnerKeys 
  const keyObj = getPaymentKeyInfo(network, mnemonic);
  const keyInfo = [];
  keyInfo.push(keyObj);
  return Promise.resolve().then(() => JSONStringify(keyInfo));
}

/*
 * Make a private key and output it 
 * args:
 * @mnemonic (string) OPTIONAL; the 12-word phrase
 */
function makeKeychain(network: Object, args: Array<string>) {
  let mnemonic = args[0];
  if (!mnemonic) {
    mnemonic = bip39.generateMnemonic(STRENGTH, crypto.randomBytes);
  }

  const ownerKeyInfo = getOwnerKeyInfo(network, mnemonic, 0);
  const paymentKeyInfo = getPaymentKeyInfo(network, mnemonic);
  return Promise.resolve().then(() => JSONStringify({
    'mnemonic': mnemonic,
    'ownerKeyInfo': ownerKeyInfo,
    'paymentKeyInfo': paymentKeyInfo
  }));
}

/*
 * Get an address's tokens and their balances
 * args:
 * @address (string) the balances
 */
function balance(network: Object, args: Array<string>) {
  let address = args[0];
  if (address.match(STACKS_ADDRESS_PATTERN)) {
    address = c32check.c32ToB58(address);
  }

  return Promise.resolve().then(() => {
    return network.getAccountTokens(address);
  })
  .then((tokenList) => {
    let tokenAndBTC = tokenList.tokens;
    if (!tokenAndBTC) {
      tokenAndBTC = [];
    }

    tokenAndBTC.push('BTC');

    return Promise.all(tokenAndBTC.map((tokenType) => {
      if (tokenType === 'BTC') {
        return Promise.resolve().then(() => {
          return network.getUTXOs(address);
        })
        .then((utxoList) => {
          return {
            'token': 'BTC',
            'amount': `${sumUTXOs(utxoList)}`
          };
        });
      }
      else {
        return Promise.resolve().then(() => {
          return network.getAccountBalance(address, tokenType)
        })
        .then((tokenBalance) => {
          return {
            'token': tokenType,
            'amount': tokenBalance.toString()
          };
        });
      }
    }));
  })
  .then((tokenBalances) => {
    let ret = {};
    for (let tokenInfo of tokenBalances) {
      ret[tokenInfo.token] = tokenInfo.amount;
    }
    return JSONStringify(ret);
  });
}

/*
 * Get a page of the account's history
 * args:
 * @address (string) the account address
 * @startBlockHeight (int) start of the block height range to query
 * @endBlockHeight (int) end of the block height range to query
 * @page (int) the page of the history to fetch
 */
function getAccountHistory(network: Object, args: Array<string>) {
  const address = c32check.c32ToB58(args[0]);
  const startBlockHeight = parseInt(args[1]);
  const endBlockHeight = parseInt(args[2]);
  const page = parseInt(args[3]);

  return Promise.resolve().then(() => {
    return network.getAccountHistoryPage(address, startBlockHeight, endBlockHeight, page);
  })
  .then(history => JSONStringify(history));
}

/*
 * Get the account's state(s) at a particular block height
 * args:
 * @address (string) the account address
 * @blockHeight (int) the height at which to query
 */
function getAccountAt(network: Object, args: Array<string>) {
  const address = c32check.c32ToB58(args[0]);
  const blockHeight = parseInt(args[1]);

  return Promise.resolve().then(() => {
    return network.getAccountAt(address, blockHeight);
  })
  .then(history => JSONStringify(history));
}

/*
 * Sends BTC from one private key to another address
 * args:
 * @recipientAddress (string) the recipient's address
 * @amount (string) the amount of BTC to send
 * @privateKey (string) the private key that owns the BTC
 */
function sendBTC(network: Object, args: Array<string>) {
  const destinationAddress = args[0]
  const amount = parseInt(args[1])
  const paymentKeyHex = decodePrivateKey(args[2]);

  if (amount <= 5500) {
    throw new Error("Invalid amount (must be greater than 5500)")
  }

  let paymentKey;
  if (typeof paymentKeyHex === 'string') {
    // single-sig
    paymentKey = blockstack.PubkeyHashSigner.fromHexString(paymentKeyHex);
  }
  else {
    // multi-sig 
    paymentKey = paymentKeyHex;
  }

  const txPromise = paymentKey.getAddress().then(
    (paymentAddress) =>
      Promise.all([network.getUTXOs(paymentAddress), network.getFeeRate()])
      .then(([utxos, feeRate]) => {
        const txB = new bitcoinjs.TransactionBuilder(network.layer1)
        const destinationIndex = txB.addOutput(destinationAddress, 0)

        const change = blockstack.addUTXOsToFund(txB, utxos, amount, feeRate, false)

        let feesToPay = feeRate * blockstack.estimateTXBytes(txB, 0, 0)
        const feeForChange = feeRate * (blockstack.estimateTXBytes(txB, 0, 1)) - feesToPay

        // it's worthwhile to add a change output
        if (change > feeForChange) {
          feesToPay += feeForChange
          txB.addOutput(paymentAddress, change - feesToPay)
        }

        if (amount + feesToPay > sumUTXOs(utxos)) {
          return {
            'status': false,
            'error': 'Not enough balance',
            'feesToPay': feesToPay,
            'balance': sumUTXOs(utxos),
            'amount': amount,
            'required': amount + feesToPay
          };
        }

        // we need to manually set the output values now
        txB.tx.outs[destinationIndex].value = amount

        // ready to sign.
        let signingPromise = Promise.resolve()
        for (let i = 0; i < txB.tx.ins.length; i++) {
          signingPromise = signingPromise.then(
            () => paymentKey.signTransaction(txB, i))
        }
        return signingPromise.then(() => txB)
      }))
    .then((signingTxBOrError) => {
      if (signingTxBOrError.error) {
        return signingTxBOrError;
      }
      return signingTxBOrError.build().toHex();
    });

  if (txOnly) {
    return txPromise.then((txOrError) => {
      if (txOrError.error) {
        return JSONStringify(txOrError, true);
      }
      else {
        return txOrError;
      }
    });
  }
  else {
    return txPromise.then((txOrError) => {
      if (txOrError.error) {
        return JSONStringify(txOrError, true);
      }
      else {
        return network.broadcastTransaction(txOrError)
          .then((txid) => {
            return txid;
          });
      }
    });
  }
}


/*
 * Send tokens from one account private key to another account's address.
 * args:
 * @recipientAddress (string) the recipient's account address
 * @tokenType (string) the type of tokens to send
 * @tokenAmount (int) the number of tokens to send
 * @privateKey (string) the hex-encoded private key to use to send the tokens
 * @memo (string) OPTIONAL: a 34-byte memo to include
 */
function sendTokens(network: Object, args: Array<string>) {
  const recipientAddress = c32check.c32ToB58(args[0]);
  const tokenType = args[1];
  const tokenAmount = bigi.fromByteArrayUnsigned(args[2]);
  const privateKey = decodePrivateKey(args[3]);
  let memo = "";

  if (args.length > 4) {
    memo = args[4];
  }

  const senderAddress = getPrivateKeyAddress(network, privateKey);
  const senderUTXOsPromise = network.getUTXOs(senderAddress);

  const txPromise = blockstack.transactions.makeTokenTransfer(
    recipientAddress, tokenType, tokenAmount, memo, privateKey);

  const estimatePromise = senderUTXOsPromise.then((utxos) => {
    const numUTXOs = utxos.length;
    return blockstack.transactions.estimateTokenTransfer(
      recipientAddress, tokenType, tokenAmount, memo, numUTXOs);
  });

  if (estimateOnly) {
    return estimatePromise;
  }

  if (!safetyChecks) {
    if (txOnly) {
      return txPromise;
    }
    else {
      return txPromise.then((tx) => {
        return network.broadcastTransaction(tx);
      });
    }
  }

  const btcBalancePromise = senderUTXOsPromise.then((utxos) => {
    return sumUTXOs(utxos);
  });

  const accountStatePromise = network.getAccountStatus(senderAddress, tokenType);
  const tokenBalancePromise = network.getAccountBalance(senderAddress, tokenType);
  const blockHeightPromise = network.getBlockHeight()

  const safetyChecksPromise = Promise.all(
    [tokenBalancePromise, estimatePromise, btcBalancePromise,
      accountStatePromise, blockHeightPromise])
    .then(([tokenBalance, estimate, btcBalance, 
      accountState, blockHeight]) => {
      if (btcBalance >= estimate && tokenBalance.compareTo(tokenAmount) >= 0 &&
          accountState.lock_transfer_block_id <= blockHeight) {
        return {'status': true};
      }
      else {
        return JSONStringify({
          'status': false,
          'error': 'TokenTransfer cannot be safely sent',
          'lockTransferBlockHeight': accountState.lock_transfer_block_id,
          'senderBalanceBTC': btcBalance,
          'estimateCostBTC': estimate,
          'tokenBalance': tokenBalance.toString(),
          'blockHeight': blockHeight,
        }, true);
      }
  });

  return safetyChecksPromise
    .then((safetyChecksResult) => {
      if (!safetyChecksResult.status) {
        return new Promise((resolve) => resolve(safetyChecksResult));
      }
      
      if (txOnly) {
        return txPromise;
      }

      return txPromise.then((tx) => {
        return network.broadcastTransaction(tx);
      })
      .then((txidHex) => {
        return txidHex;
      });
    });
}

/*
 * Get the number of confirmations of a txid.
 * args:
 * @txid (string) the transaction ID as a hex string
 */
function getConfirmations(network: Object, args: Array<string>) {
  const txid = args[0];
  return Promise.all([network.getBlockHeight(), network.getTransactionInfo(txid)])
    .then(([blockHeight, txInfo]) => {
      return JSONStringify({
        'blockHeight': txInfo.block_height,
        'confirmations': blockHeight - txInfo.block_height + 1,
      });
    })
    .catch((e) => {
      if (e.message.toLowerCase() === 'unconfirmed transaction') {
        return JSONStringify({
          'blockHeight': 'unconfirmed',
          'confirmations': 0,
        });
      }
      else {
        throw e;
      }
    });
}

/*
 * Get the address of a private key 
 * args:
 * @private_key (string) the hex-encoded private key or key bundle
 */
function getKeyAddress(network: Object, args: Array<string>) {
  const privateKey = decodePrivateKey(args[0]);
  return Promise.resolve().then(() => {
    const addr = getPrivateKeyAddress(network, privateKey);
    return JSONStringify({
      'BTC': addr,
      'STACKS': c32check.b58ToC32(addr),
    });
  });
}

/*
 * Set up a session for Gaia.
 * Generate an authentication response like what the browser would do,
 * and store the relevant data to our emulated localStorage.
 */
function makeGaiaSessionToken(appPrivateKey: string, hubURL: string | null) {  
  const ownerPrivateKey = '24004db06ef6d26cdd2b0fa30b332a1b10fa0ba2b07e63505ffc2a9ed7df22b4';
  const transitPrivateKey = 'f33fb466154023aba2003c17158985aa6603db68db0f1afc0fcf1d641ea6c2cb';
  const transitPublicKey = '0496345da77fb5e06757b9c4fd656bf830a3b293f245a6cc2f11f8334ebb690f19582124f4b07172eb61187afba4514828f866a8a223e0d5c539b2e38a59ab8bb3';

  window.localStorage.setItem('blockstack-transit-private-key', transitPrivateKey)

  const authResponse = blockstack.makeAuthResponse(
    ownerPrivateKey,
    {type: '@Person', accounts: []},
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
 * Get a file from Gaia.
 * args:
 * @username (string) the blockstack ID of the user who owns the data
 * @origin (string) the application origin
 * @path (string) the file to read
 * @appPrivateKey (string) OPTIONAL: the app private key to decrypt/verify with
 * @decrypt (string) OPTINOAL: if '1' or 'true', then decrypt
 * @verify (string) OPTIONAL: if '1' or 'true', then search for and verify a signature file
 *  along with the data
 */
function gaiaGetFile(network: Object, args: Array<string>) {
  const username = args[0];
  const origin = args[1];
  const path = args[2].replace(/^[\/]+/, '');
  let appPrivateKey = args[3];
  let decrypt = false;
  let verify = false;

  if (!!appPrivateKey && args.length > 4) {
    decrypt = (args[4].toLowerCase() === 'true' || args[4].toLowerCase() === '1');
  }

  if (!!appPrivateKey && args.length > 5) {
    verify = (args[5].toLowerCase() === 'true' || args[5].toLowerCase() === '1');
  }

  if (!appPrivateKey) {
    // make a fake private key (it won't be used)
    appPrivateKey = 'fda1afa3ff9ef25579edb5833b825ac29fae82d03db3f607db048aae018fe882';
  }

  const nameLookupUrl = `${network.blockstackAPIUrl}/v1/names/`;
  const gaiaSessionToken = makeGaiaSessionToken(appPrivateKey, null);

  // force mainnet addresses 
  blockstack.config.network.layer1 = bitcoinjs.networks.bitcoin;
  return blockstack.handlePendingSignIn(nameLookupUrl, gaiaSessionToken)
    .then((userData) => blockstack.getFile(path, {
        decrypt: decrypt,
        verify: verify,
        app: origin,
        username: username}))
    .then((data) => {
      if (data instanceof ArrayBuffer) {
        return Buffer.from(data);
      }
      else {
        return data;
      }
    })
}

/*
 * Put a file into a Gaia hub
 * args:
 * @hubUrl (string) the URL to the write endpoint of the gaia hub
 * @appPrivateKey (string) the private key used to authenticate to the gaia hub
 * @dataPath (string) the path (on disk) to the data to store 
 * @gaiaPath (string) the path (in Gaia) where the data will be stored
 * @encrypt (string) OPTIONAL: if '1' or 'true', then encrypt the file
 * @sign (string) OPTIONAL: if '1' or 'true', then sign the file and store the signature too.
 */
function gaiaPutFile(network: Object, args: Array<string>) {
  const hubUrl = args[0];
  const appPrivateKey = args[1];
  const dataPath = args[2];
  const gaiaPath = args[3].replace(/^\/+/, '');
  let encrypt = false;
  let sign = false;
  
  if (args.length > 4) {
    encrypt = (args[4].toLowerCase() === 'true' || args[4].toLowerCase() === '1');
  }
  if (args.length > 5) {
    sign = (args[5].toLowerCase() === 'true' || args[5].toLowerCase() === '1');
  }
  
  const data = fs.readFileSync(dataPath);

  const nameLookupUrl = `${network.blockstackAPIUrl}/v1/names/`;
  const gaiaSessionToken = makeGaiaSessionToken(appPrivateKey, hubUrl);

  // force mainnet addresses 
  blockstack.config.network.layer1 = bitcoinjs.networks.bitcoin;
  return blockstack.handlePendingSignIn(nameLookupUrl, gaiaSessionToken)
    .then((userData) => {      
      return blockstack.putFile(gaiaPath, data, { encrypt: encrypt, sign: sign });
    })
    .then((urls) => {
      return JSONStringify({'urls': urls})
    });
}

/*
 * Go in a tail-recursion loop to list a Gaia hub's files
 */
function gaiaListFilesLoop(hubConfig: Object, page: string | null, 
                           count: number, fileCount: number) {
  if (count > 65536) {
    // this is ridiculously huge 
    throw new Error('Too many entries to list');
  }

  let httpStatus;
  const pageRequest = JSON.stringify({ page: page });
  return fetch(`${hubConfig.server}/list-files/${hubConfig.address}`,
    {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': `${pageRequest.length}`,
        'Authorization': `bearer ${hubConfig.token}`,
      },
      body: pageRequest
    })
    .then((response) => {
      httpStatus = response.status;
      return response.text();
    })
    .then((responseText) => JSON.parse(responseText))
    .then((responseJSON) => {
      const entries = responseJSON.entries;
      const nextPage = responseJSON.page;
      if (entries === null || entries === undefined) {
        throw new Error('Malformed response: no entries');
      }
      for (let i = 0; i < entries.length; i++) {
        console.log(entries[i]);
      }
      if (nextPage && entries.length > 0) {
        // keep going 
        return gaiaListFilesLoop(hubConfig, nextPage, count+1, fileCount + entries.length);
      }
      else {
        return Promise.resolve(JSONStringify(fileCount));
      }
    });
}

/*
 * List files in a Gaia hub
 * args:
 * @hubUrl (string) the URL to the write endpoint of the gaia hub
 * @appPrivateKey (string) the private key used to authenticate to the gaia hub
 */
function gaiaListFiles(network: Object, args: Array<string>) {
  const hubUrl = args[0];
  const appPrivateKey = args[1];

  // force mainnet addresses 
  blockstack.config.network.layer1 = bitcoinjs.networks.bitcoin;
  return blockstack.connectToGaiaHub(hubUrl, canonicalPrivateKey(appPrivateKey))
    .then((hubConfig) => {
      return gaiaListFilesLoop(hubConfig, null, 0, 0);
    });
}

/*
 * Set the Gaia hub for an application for a blockstack ID
 * args:
 * @blockstackID (string) the blockstack ID of the user
 * @profileHubUrl (string) the URL to the write endpoint of the user's profile gaia hub
 * @appOrigin (string) the application's Origin
 * @hubUrl (string) the URL to the write endpoint of the app's gaia hub
 * @mnemonic (string) the 12-word backup phrase
 */
function gaiaSetHub(network: Object, args: Array<string>) {
  network.setCoerceMainnetAddress(true);

  const blockstackID = args[0];
  const ownerHubUrl = args[1];
  const appOrigin = args[2];
  const hubUrl = args[3];
  const mnemonic = args[4];

  const nameInfoPromise = getNameInfo(network, blockstackID)
    .then((nameInfo) => {
      if (!nameInfo) {
        throw new Error('Name not found');
      }
      return nameInfo;
    });

  const profilePromise = blockstack.lookupProfile(blockstackID);

  let profile;
  let ownerPrivateKey;
  let appAddress;

  return Promise.all([nameInfoPromise, profilePromise])
    .then(([nameInfo, nameProfile]) => {
      if (!nameProfile) {
        throw new Error("No profile found");
      }
      if (!nameInfo) {
        throw new Error('Name not found');
      }
      if (!nameInfo.zonefile) {
        throw new Error('No zone file found');
      }

      const parsedZoneFile = parseZoneFile(nameInfo.zonefile);
      if (!parsedZoneFile.uri) {
        throw new Error('No URI records in name zone file');
      }

      // get owner ID-address
      const ownerAddress = network.coerceMainnetAddress(nameInfo.address);
      const idAddress = `ID-${ownerAddress}`;
      
      // get owner and app key info 
      const appKeyInfo = getApplicationKeyInfo(network, mnemonic, idAddress, appOrigin);
      const ownerKeyInfo = getOwnerKeyInfo(network, mnemonic, appKeyInfo.ownerKeyIndex);
     
      let appPrivateKey = (appKeyInfo.keyInfo.privateKey === 'TODO' || !appKeyInfo.keyInfo.privateKey ?
                           appKeyInfo.legacyKeyInfo.privateKey :
                           appKeyInfo.keyInfo.privateKey);

      appPrivateKey = `${canonicalPrivateKey(appPrivateKey)}01`;
      appAddress = network.coerceMainnetAddress(getPrivateKeyAddress(network, appPrivateKey));

      profile = nameProfile;
      ownerPrivateKey = ownerKeyInfo.privateKey;
      
      const ownerGaiaHubPromise = gaiaConnect(network, ownerHubUrl, ownerPrivateKey);
      const appGaiaHubPromise = gaiaConnect(network, hubUrl, appPrivateKey);

      return Promise.all([ownerGaiaHubPromise, appGaiaHubPromise]);
    })
    .then(([ownerHubConfig, appHubConfig]) => {
      if (!ownerHubConfig.url_prefix) {
        throw new Error('Invalid owner hub config: no url_prefix defined');
      }

      if (!appHubConfig.url_prefix) {
        throw new Error('Invalid app hub config: no url_prefix defined');
      }

      const gaiaReadUrl = appHubConfig.url_prefix.replace(/\/+$/, '');

      const newAppEntry = {};
      newAppEntry[appOrigin] = `${gaiaReadUrl}/${appAddress}/`;

      const apps = Object.assign({}, profile.apps ? profile.apps : {}, newAppEntry)
      profile.apps = apps;

      // sign the new profile
      const signedProfile = makeProfileJWT(profile, ownerPrivateKey); 
      return gaiaUploadProfileAll(
        network, [ownerHubUrl], 'profile.json', signedProfile, ownerPrivateKey);
    })
    .then((profileUrls) => {
      return JSONStringify({
        'profileUrls': profileUrls
      });
    });
}
      
      
/*
 * Convert an address between mainnet and testnet, and between
 * base58check and c32check.
 * args:
 * @address (string) the input address.  can be in any format
 */
function addressConvert(network: Object, args: Array<string>) {
  const addr = args[0];
  let hash160String;
  let version;
  let b58addr;
  let c32addr;
  if (addr.match(STACKS_ADDRESS_PATTERN)) {
    c32addr = addr;
    b58addr = c32check.c32ToB58(c32addr);
  }
  else if (addr.match(/[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+/)) {
    c32addr = c32check.b58ToC32(addr);
    b58addr = addr;
  }
  else {
    throw new Error(`Unrecognized address ${addr}`);
  }

  return Promise.resolve().then(() => JSONStringify({STACKS: c32addr, BTC: b58addr}));
}

/*
 * Global set of commands
 */
const COMMANDS = {
  'announce': announce,
  'balance': balance,
  'convert_address': addressConvert,
  'gaia_getfile': gaiaGetFile,
  'gaia_putfile': gaiaPutFile,
  'gaia_listfiles': gaiaListFiles,
  'gaia_sethub': gaiaSetHub,
  'get_address': getKeyAddress,
  'get_account_at': getAccountAt,
  'get_account_history': getAccountHistory,
  'get_blockchain_record': getNameBlockchainRecord,
  'get_blockchain_history': getNameHistoryRecord,
  'get_confirmations': getConfirmations,
  'get_namespace_blockchain_record': getNamespaceBlockchainRecord,
  'get_app_keys': getAppKeys,
  'get_owner_keys': getOwnerKeys,
  'get_payment_key': getPaymentKey,
  'get_zonefile': getNameZonefile,
  'lookup': lookup,
  'make_keychain': makeKeychain,
  'make_zonefile': makeZonefile,
  'names': names,
  'name_import': nameImport,
  'namespace_preorder': namespacePreorder,
  'namespace_reveal': namespaceReveal,
  'namespace_ready': namespaceReady,
  'price': price,
  'price_namespace': priceNamespace,
  'profile_sign': profileSign,
  'profile_store': profileStore,
  'profile_verify': profileVerify,
  'register': register,
  'register_addr': registerAddr,
  'register_subdomain': registerSubdomain,
  'renew': renew,
  'revoke': revoke,
  'send_btc': sendBTC,
  'send_tokens': sendTokens,
  'transfer': transfer,
  'tx_preorder': txPreorder,
  'tx_register': txRegister,
  'update': update,
  'whois': whois,
  'zonefile_push': zonefilePush
};

/*
 * CLI main entry point
 */
export function CLIMain() {
  const argv = process.argv;
  const opts = getCLIOpts(argv);

  const cmdArgs = checkArgs(opts._);
  if (!cmdArgs.success) {
    console.error(cmdArgs.error);
    if (cmdArgs.usage) {
      if (cmdArgs.command) {
        console.log(makeCommandUsageString(cmdArgs.command));
        console.log(`Use "help" to list all commands.`);
      }
      else {
        console.log(USAGE);
        console.log(makeAllCommandsList());
      }
    }
    process.exit(1);
  }
  else {
    txOnly = opts['x'];
    estimateOnly = opts['e'];
    safetyChecks = !opts['U'];
    receiveFeesPeriod = opts['N'] ? parseInt(opts['N']) : receiveFeesPeriod;
    gracePeriod = opts['G'] ? parseInt(opts['G']) : gracePeriod;

    const consensusHash = opts['C'];
    const integration_test = opts['i'];
    const testnet = opts['t'];
    const apiUrl = opts['H'];
    const transactionBroadcasterUrl = opts['T'];
    const nodeAPIUrl = opts['I'];

    if (integration_test) {
      BLOCKSTACK_TEST = integration_test
    }

    const configPath = opts['c'] ? opts['c'] : 
      (integration_test ? DEFAULT_CONFIG_REGTEST_PATH : 
      (testnet ? DEFAULT_CONFIG_TESTNET_PATH : DEFAULT_CONFIG_PATH));

    const namespaceBurnAddr = opts['B'];
    const feeRate = opts['F'];
    const priceToPay = opts['P'];
    const priceUnits = opts['D'];

    const networkType = testnet ? 'testnet' : (integration_test ? 'regtest' : 'mainnet');

    const configData = loadConfig(configPath, networkType);
     
    // wrap command-line options
    const blockstackNetwork = new CLINetworkAdapter(
        getNetwork(configData, (!!BLOCKSTACK_TEST || !!integration_test || !!testnet)),
        consensusHash, feeRate, namespaceBurnAddr,
        priceToPay, priceUnits, receiveFeesPeriod, gracePeriod, 
        apiUrl, transactionBroadcasterUrl,
        nodeAPIUrl ? nodeAPIUrl : configData.blockstackNodeUrl);

    blockstack.config.network = blockstackNetwork;
    blockstack.config.logLevel = 'error';

    if (cmdArgs.command === 'help') {
      console.log(makeCommandUsageString(cmdArgs.args[0]));
      process.exit(0);
    }

    const method = COMMANDS[cmdArgs.command];
    let exitcode = 0;

    method(blockstackNetwork, cmdArgs.args)
    .then((result) => {
      try {
        // if this is a JSON object with 'status', set the exit code
        const resJson = JSON.parse(result);
        if (resJson.hasOwnProperty('status') && !resJson.status) {
          exitcode = 1;
        }
        return result;
      }
      catch(e) {
        return result;
      }
    })
    .then((result) => {
      if (result instanceof Buffer) {
        process.stdout.write(result);
      }
      else {
        console.log(result);
      }
    })
    .then(() => process.exit(exitcode))
    .catch((e) => {
       console.error(e.stack);
       console.error(e.message);
       process.exit(1);
     });
  }
}
