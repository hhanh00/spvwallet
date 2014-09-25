SPVWALLET
=========
A minimalistic standalone Bitcoin wallet compatible with
Electrum deterministic wallets.

- Enter an electrum master public key
- Let the tool sync up with the Bitcoin network
- See your addresses used
- Get your total balance
- Get an unused receive address
- Monitor changes to your wallet

INSTALLATION
----

```sh
git clone [repo-url] spvwallet
sbt packageBin
cd target/universal/stage
bin/spvwallet [master-pub-key] [starting height]
```

The starting height is where the scanner should start looking at the content of blocks. To get it, go to a blockchain explorer and type in your first address.
Get the block height of the first transaction and **substract 3000** to be on the safe side.

The first scan will take a minute or two, more if you have a low starting height. The tool uses a bloom filter so only a fraction of the blockchain is downloaded and validated.
Afterwards, only new blocks are processed. If you need to reset the state, delete the journal and snapshots directories.


License
======
MIT
