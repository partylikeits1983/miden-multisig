# install miden-node
cargo install miden-node

mkdir node-data
cd node-data

mkdir data 
mkdir accounts

miden-node store bootstrap --data-directory data --accounts-directory accounts

# Bootstrap the node.
miden-node bundled bootstrap \
  --data-directory data \
  --accounts-directory .