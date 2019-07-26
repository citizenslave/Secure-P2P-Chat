'use strict';

const CRYPTO = require('crypto');

function decryptRequest(req) {
	var iv = Buffer.from(req.body.iv, 'hex');
	var decryptor = CRYPTO.createDecipheriv('aes-256-cbc', req.session.sessionKey, iv);
	return JSON.parse(decryptor.update(req.body.payload, 'base64') + decryptor.final());
}

function encryptResponse(req, json) {
	var iv = CRYPTO.randomBytes(128/8);
	var encryptor = CRYPTO.createCipheriv('aes-256-cbc', req.session.sessionKey, iv);
	return {
		'iv': iv.toString('hex'),
		'encryptedPayload': encryptor.update(JSON.stringify(json), 'utf-8', 'base64') + encryptor.final('base64')
	};
}

function signToken(key, passphrase, token) {
	var signToken = CRYPTO.createSign('SHA256');
	signToken.write(token);
	signToken.end();
	return signToken.sign({ 'key': key, 'passphrase': passphrase }, 'hex');
}

function verifyToken(key, token, verification = 'TAXATION IS THEFT') {
	var verifyToken = CRYPTO.createVerify('SHA256');
	verifyToken.write(verification);
	verifyToken.end();
	return verifyToken.verify(key, token, 'hex');
}

function generateKeys(passphrase, length = 4096) {
	return new Promise((resolve, reject) => {
		CRYPTO.generateKeyPair('rsa', {
			'modulusLength': length,
			'publicKeyEncoding': {
				'type': 'spki',
				'format': 'pem'
			},
			'privateKeyEncoding': {
				'type': 'pkcs8',
				'format': 'pem',
				'cipher': 'aes-256-cbc',
				'passphrase': passphrase
			}
		}, (err, publicKey, privateKey) => {
			if (err) reject(err);
			else resolve({ 'publicKey': publicKey, 'privateKey': privateKey });
		});
	});
}

function derivePublicKey(privateKey, passphrase) {
	return CRYPTO.createPublicKey({
		'key': CRYPTO.createPrivateKey({
			'key': privateKey,
			'format': 'pem',
			'type': 'pkcs8',
			'cipher': 'aes-256-cbc',
			'passphrase': passphrase
		}),
		'type': 'spki',
		'format': 'pem'
	}).export({
		'type': 'spki',
		'format': 'pem'
	});
}

function rsaEncrypt(key, payload) {
	var payloadBuffer = Buffer.from(payload);
	var publicKey = CRYPTO.createPublicKey({
		'key': key,
		'format': 'pem',
		'type': 'pkcs1'
	});
	return CRYPTO.publicEncrypt({
		'key': publicKey,
		'padding': CRYPTO.constants.RSA_PKCS1_PADDING
	}, payloadBuffer).toString('base64');
}

function rsaDecrypt(key, passphrase, payload) {
	var payloadBuffer = Buffer.from(payload, 'base64');
	var privateKey = CRYPTO.createPrivateKey({
		'key': key,
		'format': 'pem',
		'type': 'pkcs8',
		'cipher': 'aes-256-cbc',
		'passphrase': passphrase
	});
	return CRYPTO.privateDecrypt({
		'key': privateKey,
		'padding': CRYPTO.constants.RSA_PKCS1_PADDING,
		'cipher': 'aes-256-cbc',
		'passphrase': passphrase
	}, payloadBuffer).toString();
}

function saltPassword(hash, pwSalt = '', length = 1024/8) {
	pwSalt = pwSalt.length ? pwSalt : random(length);
	var saltedHash = CRYPTO.pbkdf2Sync(hash, pwSalt, 1, length, 'sha1').toString('hex');
	return { 'hash': saltedHash, 'pwSalt': pwSalt };
}

function random(length = 1024/8) {
	return CRYPTO.randomBytes(length).toString('hex');
}

exports.decryptRequest = decryptRequest;
exports.encryptResponse = encryptResponse;
exports.signToken = signToken;
exports.verifyToken = verifyToken;
exports.generateKeys = generateKeys;
exports.derivePublicKey = derivePublicKey;
exports.rsaEncrypt = rsaEncrypt;
exports.rsaDecrypt = rsaDecrypt;
exports.saltPassword = saltPassword;
exports.random = random;