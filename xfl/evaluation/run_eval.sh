#!/bin/bash
pushd .
cd /root/desyl/src/

LS=(512 1024 2048 4096)
EMBEDS=('dexter', 'palmtree_official', 'safe2', 'asm2vec')

for E in "${EMBEDS[@]}"; do
    for L in "${LS[@]}"; do 
        echo "Running python3 ./classes/pfastreXML.py $L $E"
        python3 ./classes/pfastreXML.py $L $E
    done
done

popd
