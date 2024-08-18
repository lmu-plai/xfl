#!/bin/sh


grep '' res/minimal-test/*.log

export PGPASSWORD='123';
dropdb -h "$POSTGRES_HOST" -U desyl -p 5432  xfl
pg_restore --create -h "$POSTGRES_HOST" -U desyl -d postgres  -p 5432 ../Tables/minimalExample.pgsql -v

python3 genExp.py
python3 dexter.py -d=minimal-test -learn -dim=20 -subDim=40 -epochs=10 -batchSize=64
python3 dexter.py -d=minimal-test -validate
python3 dexter.py -d=minimal-test -exportEpoch=10
python3 pfastreXML.py -d=minimal-test -l=1024 -trees=60
python3 pfastreXML.py -d=minimal-test -l=1024 -trees=30 -f


grep '' res/minimal-test/*.log

