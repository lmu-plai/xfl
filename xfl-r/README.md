# XFL-R

XFL-R is a refactoring of the original XFL source code that streamlines setup and experimentation.

## Installation

Follow the steps in [INSTALL.md](INSTALL.md) to install XFL-R and to download pre-trained models and PSQL dumps.

## User Manual

XFL relies on a PSQL database to manage your experiments.

### Step 0: Pick data from our collection

Insert library prototypes into the PSQL database (1 hour, 4 GB of memory):

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

Insert our preprocessed binaries into the PSQL database (1 hour, 32 GB of memory):

```shell
conda activate XFL
cd Tables/
unzip XFL_Functions.zip
cd ../XFL/
python3 transferFunctionsToDB.py
cd ../Tables/
rm binaries.pck 
rm functions.pck
```


### Step 1: Identify Dynamic Calls

If all dynamic calls are not in our collection, you need to find the corresponding libraries and analyze them.

```shell
conda activate XFL
cd XFL/
python3 add_libraries.py PATH_TO_YOUR_LIBRARIES
```

### Step 2: Preprocess Binaries

Preprocess your own binaries, which can be time-consuming.

```shell
python3 add_binaries.py --p PATH_TO_YOUR_DATASET --fast
```

### Step 3: Experiment Configuration

Create a configuration for your experiment. A script handles dataset splitting and data collection for one-hot encoding of various features.

```shell
python3 genExp.py
```

### Step 4: Train DEXTER Autoencoder

Specify a folder to contain your subexperiment results. Train the DEXTER autoencoder, adjusting the hyperparameters as needed (e.g., 10 epochs with a batch size of 64).

```shell
python3 dexter.py -d=minimal-test -learn -epochs=10 -batchSize=64
```

### Step 5: Validate and Export Embeddings

After training, find the model with minimal loss on the validation set.

```shell
python3 dexter.py -d=minimal-test -validate
```

Assuming the best model is at epoch 10, compute DEXTER function embeddings.

```shell
python3 dexter.py -d=minimal-test -exportEpoch=10
```

### Step 6: Predict Function Names

Embeddings are stored in `res/minimal-test/embeddings` and a table in `res/minimal-test/nlpData`. Use PfastreXML to predict function names.

```shell
python3 pfastreXML.py -d=minimal-test -l=1024 -trees=60
```

Logs are saved in `res/minimal-test/dexter-1024-R-False-F-False-I-False.log`.

### Quick Start Example (1 hour, 4 GB of memory)

Validate and try XFL quickly using our minimal PSQL database dump.

```shell
conda activate XFL
cd XFL/
export PGPASSWORD='123';
dropdb -h localhost -U desyl -p 5432 xfl
pg_restore --create -h localhost -U desyl -d postgres -p 5432 ../Tables/minimalExample.pgsql -v

python3 genExp.py
python3 dexter.py -d=minimal-test -learn -epochs=10 -batchSize=64
python3 dexter.py -d=minimal-test -validate
python3 dexter.py -d=minimal-test -exportEpoch=10
python3 pfastreXML.py -d=minimal-test -l=1024 -trees=60
```

### Pretrained XFL Models

If all dynamic call prototypes are not in our collection, you need to find the corresponding libraries and analyze them.

```shell
conda activate XFL
cd XFL/
python3 add_libraries.py PATH_TO_YOUR_LIBRARIES
```

Preprocess binaries:

```shell
python3 add_binaries.py --p PATH_TO_YOUR_DATASET --fast
```

Use the DEXTER pretrained model:

```shell
cp res/origin/experimentsSettings res/
mv res/origin/embeddings res/origin/embeddingsSave
mv res/origin/nlpData res/origin/nlpDataSave
python3 dexter.py -d=origin -exportEpoch=50 -newSplit
```

Embeddings are stored in `res/origin/embeddings` and a table in `res/origin/nlpData`. Use a pre-trained PfastreXML model (such as XFL with 1024 labels):

```shell
python3 pfastreXML.py -d=origin -evaluate -pfastreModel=desyl-pfastrexml-1024-functions-split -threshold=0.230
```

Logs are available in `res/origin/desyl-pfastrexml-1024-functions-split/deduction.log`.

To learn a PfastreXML model using your own dataset:

```shell
python3 pfastreXML.py -d=origin -l=1024
```

Logs are available in `res/origin/dexter-1024-R-False-F-False-I-False.log`.


### Scripts Overview

- **transferPrototypesToDB.py**: Transfers a dump of library prototypes to the PSQL DB.
- **transferFunctionsToDB.py**: Transfers a dump of preprocessed binaries and functions to the PSQL DB.
- **add_libraries.py path**: Analyzes libraries from the specified path and saves function prototypes to the PSQL DB.
- **add_binaries.py -p path**: Analyzes binaries from the specified path, saving the results to the PSQL DB.
- **genExp.py**: Generates a complete configuration for the current database, including training splits and one-hot encoding.
- **dexter.py**: Trains the DEXTER autoencoder and embeds functions, with customizable hyperparameters.
- **pfastreXML.py**: Trains PfastreXML to predict function names and save logs.

### Cleaning Up Experiments

To remove binaries and functions:

```shell
sudo -u postgres psql
\c xfl
TRUNCATE TABLE functions, binaries, embedding_binnet;
```

To delete function prototypes from the database:

```shell
sudo -u postgres psql
\c xfl
TRUNCATE TABLE library_prototypes, library_p;
```

To remove the current configuration:

```shell
rm XFL/res/experimentsSettings
```
