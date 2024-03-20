# XFL-R 

XFL-R is a refactoring of the original XFL source code that streamlines setup and experimentation.

## Installation Steps

Follow the steps in [INSTALL.md](INSTALL.md) to install XFL-R and to download pre-trained models and PSQL dumps.

## Usage

### Insert library prototypes into the PSQL DB (1h, 4 Gb of memory)

```shell
conda activate XFL
cd Tables/
unzip XFL_Prototypes.zip
cd ../XFL/
python3 transferPrototypesToDB.py
cd ../Tables/
rm libraries.pck 
rm libraryPrototypes.pck
```

### Minimal example (1h, 4 Gb of memory)

```shell
conda activate XFL
cd XFL/
export PGPASSWORD='123';
dropdb -h localhost -U desyl -p 5432  xfl
pg_restore --create -h localhost -U desyl -d postgres  -p 5432 ../Tables/minimalExample.pgsql -v

python3 genExp.py
python3 dexter.py -d=minimal-test -learn -dim=20 -subDim=40 -epochs=10 -batchSize=64
python3 dexter.py -d=minimal-test -validate
python3 dexter.py -d=minimal-test -exportEpoch=10
python3 pfastreXML.py -d=minimal-test -l=1024 -trees=60
python3 pfastreXML.py -d=minimal-test -l=1024 -trees=30 -f
```

### Use XFL pretrained models

You first need to identify all dynamic calls prototypes in your binary dataset. Either they are present in our set of known libraries, or you need to identify and analyze them.

```shell
conda activate XFL
cd XFL/
python3 add_libraries.py PATH_TO_YOUR_LIBRARIES
```

Then, you need to preprocess your binaries, which can take some time.

```shell
python3 add_binaries.py --p PATH_TO_YOUR_DATASET --fast
```

Next, use the DEXTER pretrained model inside the origin directory.

```shell
cp res/origin/experimentsSettings res/
mv res/origin/embeddings res/origin/embeddingsSave
mv res/origin/nlpData res/origin/nlpDataSave
python3 dexter.py -d=origin -exportEpoch=50 -newSplit
```

Now, embeddings are inside the file `res/origin/embeddings` and a table is inside the file `res/origin/nlpData`. You are now able to use a pre-trained PfastreXML model (such as XFL with 1024 labels).

```shell
python3 pfastreXML.py -d=origin -evaluate -pfastreModel=desyl-pfastrexml-1024-functions-split -threshold=0.230
```
Logs are available in the file `res/origin/desyl-pfastrexml-1024-functions-split/deduction.log`.

At this point, you can also learn a PfastreXML model using your own dataset.

```shell
python3 pfastreXML.py -d=origin -l=1024
```

Logs are available in the file `res/origin/dexter-1024-R-False-F-False-I-False.log`.

### Insert preprocessed binaries into the PSQL DB. (1h, 32 Gb of memory)

```shell
cd Tables/
unzip XFL_Functions.zip
cd ../XFL/
conda activate XFL
python3  transferFunctionsToDB.py
cd ../Tables/
rm binaries.pck 
rm functions.pck
```

### Scripts

- **transferPrototypesToDB.py** - Transfers the dump of library prototypes to the PSQL DB.
- **transferFunctionsToDB.py** - Transfers the dump of preprocessed binaries and functions to the PSQL DB.
- **add_libraries.py path** - Search for libraries from the path and save function prototypes to the PSQL DB.
- **add_binaries.py -p path** - Search for any binaries from the path, analyze functions, and save the results to the PSQL DB. This requires all dynamic call prototypes to be known in principle.
- **genExp.py** - Generates a complete configuration for your current database. It also handles the training split, and data collection for one hot encoding of various features.
- **dexter.py** - Train DEXTER autoencoder and embed functions. Please refer to the script for customization.
- **pfastreXML.py** - Train PfastreXML to predict function names and save logs. Please refer to the script for customization.

### Tips for cleaning experiments

To remove binaries and functions.
```shell
sudo -u postgres psql
\c xfl
TRUNCATE TABLE functions,binaries,embedding_binnet;
```

To delete function prototypes from the database.

```shell
sudo -u postgres psql
\c xfl
TRUNCATE TABLE library_prototypes,library_p;
```

