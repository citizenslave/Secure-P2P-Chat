# Secure-P2P-Chat
A secure P2P chat using RSA and AES encryption and a blockchain.

`npm install`

`npm start`

Notice the port, start another session in a fresh terminal.

`/peer localhost:<PORT>`

You have now established a P2P connection.  You can test this with:

`/peer localhost:<PORT> send <SOME MESSAGE>`

The message should be broadcast to the other peer.

Now set up some mailboxes.

`/mailbox test1 test`

This will setup a mailbox called `test1`, generate an RSA keypair using the passphrase `test`, and set it as the active mailbox.

`/savekey public pub1`

This will save your public key to a file so it can be accessed from the other terminal.

`/savekey private pvt1`

This will save your encrypted private key to a file so it can be reloaded after you exit the program rather than regenerating a new mailbox.

`/mailbox test1 test pvt1`

Now set up your other terminal with a new mailbox.

`/mailbox test2 test`

Save your keys.

`/savekey public pub2`

`/savekey private pvt2`

Now set up some aliases so you can send messages easily to the other terminal.

`/alias me --file pub2`

`/alias him --file pub1`

Broadcast the changes to the blockchain.  There is an outstanding issue with forking the chain, so you don't want the terminals to be competing to add a block at the same index.

`/chain broadcast`

Do the same in the other terminal, which should have updated its own blockchain.

`/alias me --file pub1`

`/alias him --file pub2`

Broadcast the chain again.

`/chain broadcast`

Now we can finally send some messages.

`/send him`

`<MESSAGE TEXT>`

`<\n>`

The last empty line closes the connection.  Now broadcast the chain.

`/chain broadcast`

The other terminal should now be able to read the messages you sent.

`/read`

When in doubt, broadcast the chain.  With the existing forking issue, the chains getting out of sync between peers will cause problems, and the peers will think you are broadcasting a stale chain when in fact you have different blocks not included in their chain.
