const ENCRYPTION = require('./encryption');
const inspect = require('util').inspect;
const readline = require('readline');
const yargs = require('yargs');
const fs = require('fs');
const net = require('net');

class Transaction {
	toKey;
	fromKey;
	payload;
	signature;

	constructor(toKey, fromKey, payload) {
		this.toKey = toKey;
		this.fromKey = fromKey;
		this.payload = payload;
	}

	toString() {
		return `${this.toKey}:${this.fromKey}:::${this.payload}`;
	}

	signTransaction(key, passphrase) {
		this.signature = ENCRYPTION.signToken(key, passphrase, this.toString());
	}

	verifyTransaction() {
		return ENCRYPTION.verifyToken(this.fromKey, this.signature, this.toString());
	}
}

class Mailbox {
	publicKey;
	privateKey;
	passphrase;
	blockchain;
	aliases = {};

	constructor(passphrase, privateKey = '', blockchain) {
		this.passphrase = passphrase;
		this.blockchain = blockchain;
		if (privateKey && privateKey.length) return this.loadMailbox(privateKey);
		ENCRYPTION.generateKeys(passphrase, 4096).then(keys => {
			this.publicKey = keys.publicKey;
			this.privateKey = keys.privateKey;
			console.log(`Mailbox (${Mailbox.formatKey(this.publicKey)}) created...\nEncrypted Private Key:\n${this.privateKey}`);
		});
	}

	loadMailbox(privateKey) {
		this.privateKey = privateKey;
		this.publicKey = ENCRYPTION.derivePublicKey(privateKey, this.passphrase);
	}

	sendMessage(toKey, payload, isDataBlock = true) {
		if (!this.publicKey || !this.privateKey) return console.error(`Mailbox not ready...`);
		if (this.aliases[toKey]) toKey = this.aliases[toKey];
		let cipher = {
			'session': {
				'sessionKey': ENCRYPTION.random(128/8)
			}
		};
		let data = ENCRYPTION.encryptResponse(cipher, JSON.stringify(payload));
		let encryptedCipher = ENCRYPTION.rsaEncrypt(toKey, JSON.stringify(cipher));
		let encryptedPayload = {
			'cipher': encryptedCipher,
			'payload': data
		};
		let tx = new Transaction(toKey, this.publicKey, encryptedPayload);
		tx.signTransaction(this.privateKey, this.passphrase);
		this.blockchain.addBlock(tx, isDataBlock);
	}

	recvMessage(transaction) {
		if (!transaction) return;
		if (!transaction.verifyTransaction())
			return console.warn(`Unverified message from\n${Mailbox.formatKey(transaction.fromKey)}:\n${transaction.payload}`);
		// console.log(`Verified message from\n${Mailbox.formatKey(transaction.fromKey)}\nto\n${Mailbox.formatKey(this.publicKey)}:`);
		// console.log(inspect(transaction.payload, false, null, true));
		let encryptedPayload = transaction.payload;
		let decryptedCipher = JSON.parse(ENCRYPTION.rsaDecrypt(this.privateKey, this.passphrase, encryptedPayload.cipher));
		decryptedCipher['body'] = {
			'iv': encryptedPayload.payload.iv,
			'payload': encryptedPayload.payload.encryptedPayload
		};
		return JSON.parse(ENCRYPTION.decryptRequest(decryptedCipher));
	}

	getMessages() {
		let msgs = this.blockchain.getBlocksFor(this.publicKey).map(this.recvMessage.bind(this));
		// console.log(msgs);
		return msgs;
	}

	getConfig() {
		let configs = this.blockchain.getConfigBlocksFor(this.publicKey).map(this.recvMessage.bind(this));
		this.processConfigs(configs);
	}

	processConfigs(configs) {
		if (!configs || !configs.length) return;
		configs.forEach(config => {
			if (config && config.type === 'alias') {
				if (!this.aliases[config.alias] || this.aliases[config.alias].timestamp < config.timestamp) {
					this.aliases[config.alias] = config;
					console.log(`Alias updated for ${config.alias}: ${config.timestamp}`);
				}
			} else {
				console.log(`Unknown config type: ${config.type}\n(${config})`);
			}
		});
	}

	reloadBlockChain(bcData) {
		let bcUpdate = BlockChain.parse(bcData, Mailbox.parse);
		if (!bcUpdate) return;
		if (bcUpdate.chain.length > this.blockchain.chain.length) this.blockchain = bcUpdate;
		this.getConfig();
		console.log('Mailbox blockchain updated');
	}

	static parse(txData) {
		if (txData.data === '') return txData;
		let tx = new Transaction(txData.data.toKey, txData.data.fromKey, txData.data.payload);
		tx.signature = txData.data.signature;
		txData.data = tx;
		txData.hash = txData.calcHash();
		return txData;
	}

	static formatKey(key) {
		return key.split('\n').slice(1,-2).join('');
	}
}

class Block {
	data;
	salt;
	prevHash;
	isDataBlock;
	timestamp;
	hash;

	constructor(data = '', prevHash = 0, salt = ENCRYPTION.random()) {
		this.data = data;
		this.salt = salt;
		this.prevHash = prevHash;
		this.isDataBlock = false;
		this.timestamp = (Date.now());
		this.hash = this.calcHash();
	}

	toString() {
		return JSON.stringify({
			'data': this.data.toString(),
			'salt': this.salt,
			'prevHash': this.prevHash,
			'isDataBlock': this.isDataBlock,
			'timestamp': this.timestamp,
			'hash': this.hash
		});
	}

	calcHash() {
		let blockData = `${this.data.toString()}:::${this.salt}:${this.timestamp}:${this.prevHash}`;
		return ENCRYPTION.saltPassword(blockData, this.salt).hash;
	}

	static parse(blockString) {
		let block = new Block(blockString.data, blockString.prevHash, blockString.salt);
		block.isDataBlock = blockString.isDataBlock;
		block.timestamp = blockString.timestamp;
		block.hash = block.calcHash();
		return block;
	}
}

class BlockChain {
	chain;
	initStamp;
	initSalt;

	constructor(genesisBlock = new Block()) {
		this.chain = [ genesisBlock ];
		this.initStamp = this.chain[0].timestamp;
		this.initSalt = this.chain[0].salt;
	}

	toString() {
		return JSON.stringify({
			'chain': JSON.stringify(this.chain),
			'initStamp': this.initStamp,
			'initSalt': this.initSalt
		});
	}

	isValid() {
		let dummyGenesis = new Block();
		dummyGenesis.timestamp = this.initStamp;
		dummyGenesis.salt = this.initSalt;
		dummyGenesis.hash = dummyGenesis.calcHash();

		if (this.chain[0].toString() !== dummyGenesis.toString()) return false;
		for (let i=1; i<this.chain.length; i++) {
			if (this.chain[i].prevHash !== this.chain[i-1].hash) return false;
			if (this.chain[i].hash !== this.chain[i].calcHash()) return false;
			if (!this.chain[i].data.verifyTransaction()) return false;
		}

		return true;
	}

	addBlock(data, isDataBlock) {
		let latestHash = this.chain[this.chain.length-1].hash;
		let block = new Block(data, latestHash);
		block.isDataBlock = isDataBlock;
		this.chain.push(block);
	}

	getBlocksFor(publicKey) {
		return this.chain.filter(block => (block.data.toKey === publicKey) && (block.isDataBlock)).map(block => block.data);
	}

	getConfigBlocksFor(publicKey) {
		return this.chain.filter(block => (block.data.toKey === publicKey) && (!block.isDataBlock)).map(block => block.data);
	}

	static parse(bcString, dataParser) {
		let bcData = JSON.parse(bcString);
		bcData.chain = JSON.parse(bcData.chain);
		let bc = new BlockChain(bcData.chain[0]);
		bc.chain = bcData.chain.map(Block.parse).map(dataParser);
		bc.initStamp = bcData.initStamp;
		bc.initSalt = bcData.initSalt;
		if (bc.isValid()) return bc;
		else console.error('Invalid blockchain');
	}
}

const rl = readline.createInterface({
	'input': process.stdin,
	'output': process.stdout,
	'prompt': ''
});
rl.on('line', input => {
	CommandProcessor.processCommand(input);
});
rl.on('close', input => {
	CommandProcessor.processCommand('/chain dump chain');
	console.log('Exiting...');
	process.exit(0);
});

class CommandProcessor {
	static blockchain;
	static peerSockets = {};
	static mailboxes = {};
	static activeMailboxKey;
	static sendTo = null;

	static processCommand(cmd) {
		let parsedCommand = yargs.parse(cmd);
		switch(parsedCommand._[0]) {
		case '/mailbox':
			CommandProcessor.selectMailbox(parsedCommand._);
			break;
		case '/savekey':
			CommandProcessor.saveKey(parsedCommand._);
			break;
		case '/alias':
			CommandProcessor.createAlias(parsedCommand._, parsedCommand);
			break;
		case '/chain':
			CommandProcessor.chainCommands(parsedCommand._);
			break;
		case '/read':
			CommandProcessor.readMessages();
			break;
		case '/peer':
			CommandProcessor.connectPeer(parsedCommand._);
			break;
		case '/send':
			CommandProcessor.sendMode(parsedCommand._);
			break;
		case undefined:
			if (CommandProcessor.sendTo) {
				CommandProcessor.disconnectSend();
				break;
			}
		default:
			if (CommandProcessor.sendTo) {
				CommandProcessor.send(cmd);
				return;
			}
			console.log(`Unknown command:\n${cmd}`);
		}
	}

	static readMessages() {
		if (!CommandProcessor.activeMailboxKey) {
			console.log('No mailbox active');
			return;
		}
		let msgs = CommandProcessor.mailboxes[CommandProcessor.activeMailboxKey].getMessages();
		msgs.forEach(msg => {
			console.log(msg);
		});
	}

	static sendMode(parsedCommand) {
		if (!CommandProcessor.activeMailboxKey) {
			console.log('No mailbox active');
			return;
		}
		if (!parsedCommand[1]) {
			console.log('No delivery mailbox specified');
			return;
		}
		if (CommandProcessor.mailboxes[CommandProcessor.activeMailboxKey].aliases[parsedCommand[1]]) {
			console.log(`Sending to alias "${parsedCommand[1]}":`);
			console.log(CommandProcessor.mailboxes[CommandProcessor.activeMailboxKey].aliases[parsedCommand[1]].publicKey);
			CommandProcessor.sendTo = {
				'alias': parsedCommand[1],
				'key': CommandProcessor.mailboxes[CommandProcessor.activeMailboxKey].aliases[parsedCommand[1]].publicKey
			};
			return;
		} else {
			console.log(`No alias "${parsedCommand[1]}" found in current mailbox.  Using as public key`);
			CommandProcessor.sendTo = {
				'alias': null,
				'key': parsedCommand[1]
			};
			return;
		}
	}

	static send(text) {
		if (!CommandProcessor.activeMailboxKey) {
			console.log('No mailbox active');
			return;
		}
		CommandProcessor.mailboxes[CommandProcessor.activeMailboxKey].sendMessage(
				CommandProcessor.sendTo.key, text);
	}

	static disconnectSend() {
		if (!CommandProcessor.sendTo) return;

		console.log(`---Disconnected ${CommandProcessor.sendTo.alias?`from "${CommandProcessor.sendTo.alias}"`:''}---`);
		CommandProcessor.sendTo = null;
	}

	static selectMailbox(parsedCommand) {
		CommandProcessor.disconnectSend();
		if (parsedCommand[1] && this.mailboxes[parsedCommand[1]]) {
			CommandProcessor.activeMailboxKey = parsedCommand[1];
			CommandProcessor.mailboxes[CommandProcessor.activeMailboxKey].blockchain = CommandProcessor.blockchain;
			CommandProcessor.mailboxes[CommandProcessor.activeMailboxKey].getConfig();
			console.log(`Selected mailbox ${parsedCommand[1]}`);
			return;
		}
		if (!parsedCommand[1]) {
			console.log('No mailbox specified');
			return;
		}
		if (!parsedCommand[2]) {
			console.log(`No password provided for mailbox ${parsedCommand[1]}`);
			return;
		}
		let privateKey = false;
		if (parsedCommand[3]) {
			console.log(`Opening mailbox ${parsedCommand[1]} using encrypted private key at:\n${parsedCommand[3]}`);
			privateKey = fs.readFileSync(parsedCommand[3], { 'encoding': 'utf8' });
		} else {
			console.log(`Creating new mailbox ${parsedCommand[1]}`);
		}
		CommandProcessor.mailboxes[parsedCommand[1]] = new Mailbox(parsedCommand[2], privateKey, CommandProcessor.blockchain);
		CommandProcessor.activeMailboxKey = parsedCommand[1];
		CommandProcessor.mailboxes[CommandProcessor.activeMailboxKey].getConfig();
	}

	static saveKey(parsedCommand) {
		if (!CommandProcessor.activeMailboxKey) {
			console.log('No mailbox active');
			return;
		}
		if (!parsedCommand[1]) {
			console.log('No key specified');
			return;
		}
		if (![ 'private', 'public' ].includes(parsedCommand[1])) {
			console.log(`Invalid key "${parsedCommand[1]}" specified`);
			return;
		}
		if (!parsedCommand[2]) {
			console.log('No destination file specified');
			return;
		}
		if (fs.existsSync(parsedCommand[2])) {
			console.log(`Destination file "${parsedCommand[2]}" already exists`);
			return; 
		} else {
			fs.writeFileSync(parsedCommand[2],
					CommandProcessor.mailboxes[CommandProcessor.activeMailboxKey][parsedCommand[1] === 'private'?'privateKey':'publicKey']);
		}
	}

	static createAlias(parsedCommand, flags) {
		if (!CommandProcessor.activeMailboxKey) {
			console.log('No mailbox active');
			return;
		}
		if (flags.list) {
			Object.keys(CommandProcessor.mailboxes[CommandProcessor.activeMailboxKey].aliases).forEach(alias => console.log(alias));
			return;
		}
		if (!parsedCommand[1]) {
			console.log('No alias provided');
			return;
		}
		if (!parsedCommand[2] && !flags.file) {
			console.log(`No public key provided for alias "${parsedCommand[1]}"`);
			return;
		}
		let publicKey;
		if (flags.file) {
			try {
				publicKey = fs.readFileSync(flags.file, { 'encoding': 'utf8' });
			} catch (e) {
				console.log(`Invalid public key file "${flags.file}" for alias "${parsedCommand[1]}"`);
				return;
			}
		} else {
			publicKey = parsedCommand[2];
		}
		let aliasConfig = {
			'type': 'alias',
			'alias': parsedCommand[1],
			'publicKey': publicKey,
			'timestamp': Date.now()
		};
		console.log(aliasConfig);
		CommandProcessor.mailboxes[CommandProcessor.activeMailboxKey]
				.sendMessage(CommandProcessor.mailboxes[CommandProcessor.activeMailboxKey].publicKey, aliasConfig, false);
		console.log(`Alias created for "${parsedCommand[1]}":\n${publicKey}`);
		CommandProcessor.mailboxes[CommandProcessor.activeMailboxKey].getConfig();
	}

	static chainCommands(parsedCommand) {
		if (!CommandProcessor.activeMailboxKey) {
			console.log('No active mailbox');
			return;
		}
		if (!parsedCommand[1]) {
			console.log('No chain command issued');
			return;
		}
		if (![ 'dump', 'load' ].includes(parsedCommand[1])) {
			console.log(`Invalid chain command ${parsedCommand[1]}`);
			return;
		}
		if (!parsedCommand[2]) {
			console.log(`No filename provided for chain ${parsedCommand[1]} command`);
			return;
		}
		if (parsedCommand[1] === 'load') {
			CommandProcessor.loadBlockchainFromDisk(parsedCommand[2]);
				// CommandProcessor.mailboxes[CommandProcessor.activeMailboxKey].reloadBlockChain(fs.readFileSync(parsedCommand[2]));
			return;
		} else {
			fs.writeFileSync(parsedCommand[2], CommandProcessor.blockchain.toString());
			console.log(`Dumped chain to ${parsedCommand[2]}`);
			return;
		}
	}

	static loadBlockchainFromDisk(file) {
		if (fs.existsSync(file)) {
			let bc = BlockChain.parse(fs.readFileSync(file), Mailbox.parse);
			if (bc.isValid() && (!CommandProcessor.blockchain || bc.chain.length > CommandProcessor.blockchain.chain.length)) {
				CommandProcessor.blockchain = bc;
				console.log(`Blockchain loaded from ${file}`);
				return;
			} else {
				console.log(`Blockchain from ${file} is invalid or stale`);
				return;
			}
		} else {
			console.log(`File ${file} does not exist`);
			return;
		}
	}

	static connectPeer(parsedCommand) {
		if (!parsedCommand[1]) {
			console.log('No peer host identified');
			return;
		}
		if (parsedCommand[2] === 'send' && CommandProcessor.peerSockets[parsedCommand[1]]) {
			console.log(`Sending: ${parsedCommand.slice(3).join(' ')}`);
			CommandProcessor.peerSockets[parsedCommand[1]].write(JSON.stringify(parsedCommand.slice(3).join(' ')));
			return;
		}
		const host = parsedCommand[1].split(':');
		if (host.length !== 2 || !Number(host[1])) {
			console.log(`Invalid host ${parsedCommand} provided`);
			return;
		}
		const socket = CommandProcessor.peerSockets[parsedCommand[1]] = net.connect(host[1], host[0], () => {
			console.log(`Socket connected to ${parsedCommand[1]}`);
			socket.on('data', data => {
				let payload = JSON.parse(data);
				console.log(`Rec'd data: ${payload}`);
			});
			socket.on('error', e => {
				console.log('socket:', e);
			});
		});
	}
}

CommandProcessor.loadBlockchainFromDisk('chain');

const server = net.createServer(socket => {

	console.log('client connected');
	let connectedHost = `${socket.remoteAddress.replace(/^.*:/, '').replace('127.0.0.1', 'localhost')}:${socket.remotePort}`;
	console.log(connectedHost);
	CommandProcessor.peerSockets[connectedHost] = socket;
	socket.on('end', () => {
		console.log('client disconnected');
	});
	socket.on('error', e => {
		console.log('socket:', e);
	})
	socket.write('"connected"');
	socket.on('data', data => {
		let payload = JSON.parse(data);
		console.log(`Rec'd data: ${payload}`);
	})
});
server.listen(() => {
	console.log('listening...');
	console.log(server.address());
});
server.on('error', (e) => {
	console.log('server:', e);
});
// let bc1 = new BlockChain();
// let bc2 = new BlockChain();
// let testMailbox1 = new Mailbox('test', '', bc1);
// let testMailbox2 = new Mailbox('test', '', bc2);
// setTimeout(() => {
// 	testMailbox1.sendMessage(testMailbox2.publicKey, 'test');
// 	testMailbox1.sendMessage(testMailbox1.publicKey, {'type':'alias','alias':'me'});
// 	console.log(testMailbox1.getMessages());
// 	testMailbox2.reloadBlockChain(bc1.toString());
// 	console.log(testMailbox2.getMessages());
// 	testMailbox1.getConfig();
// 	console.log(testMailbox1.aliases);
// }, 5000);