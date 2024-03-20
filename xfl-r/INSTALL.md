# Installation Steps

Follow the steps below to install XFL-R.

## 0. Install Conda
If you don't have Conda, you can install it by following the instructions [on the Conda website](https://docs.conda.io/projects/conda/en/latest/user-guide/install/linux.html).

## 1. Install Software Packages

```shell
sudo apt install zip tar g++ libpq-dev python3-dev graphviz libgraphviz-dev pkg-config openjdk-17-jdk
```

## 2. Install radare2

```shell
wget https://github.com/radareorg/radare2/archive/refs/tags/5.5.4.zip
unzip radare2-5.5.4
cd radare2-5.5.4
sudo chmod -R 777 .
bash sys/install.sh
```

## 3. Install PSQL 13

```shell
sudo apt install postgresql-13
sudo locale-gen en_US
sudo locale-gen en_US.UTF-8
sudo update-locale 
```

To run and stop the server as a service:
```shell
sudo service postgresql start
sudo service postgresql stop
```

Configure the database:
```shell
sudo -u postgres psql
CREATE DATABASE xfl;
CREATE USER desyl;
ALTER USER desyl with password '123';
ALTER DATABASE xfl OWNER TO desyl;
GRANT ALL PRIVILEGES on DATABASE xfl TO desyl;
ALTER ROLE desyl WITH CREATEDB;
exit
sudo service postgresql restart
sudo -u postgres psql -d xfl -a -f XFL_DB.sql
```


## 4. Setup the Conda Environment

```shell
conda create --name XFL --file requirements_XFL.txt
conda activate XFL
pip3 install setuptools --upgrade
pip3 install importlib-metadata
pip3 install importlib-resources
pip3 install archinfo==9.0.5327
pip3 install cachetools==4.2.4
pip3 install capstone==4.0.2
pip3 install claripy==9.0.5327
pip3 install coloredlogs==15.0
pip3 install datasketch==1.6.4
pip3 install dill==0.3.3
pip3 install intervaltree==3.1.0
pip3 install ipython==7.19.0
pip3 install joblib==1.0.0
pip3 install karateclub==1.3.3
pip3 install lief==0.11.3
pip3 install networkx==2.5
pip3 install nltk==3.5
pip3 install numpy==1.22.4
pip3 install progressbar==2.5
pip3 install psycopg2==2.9.1
pip3 install pygraphviz==1.6
pip3 install pyvex==9.0.5327
pip3 install r2pipe==1.5.3
pip3 install redis==3.5.3
pip3 install rzpipe==0.6.0
pip3 install scipy==1.10.1
pip3 install sklearn==0.0
pip3 install tensorflow==2.13.1
pip3 install tqdm==4.55.1
pip3 install timeout_decorator
pip3 install bson
pip3 install pyenchant
pip3 install psycopg2-binary
pip3 install pydot
```

```shell
python3
import nltk
nltk.download('words')
nltk.download('stopwords')
```

## 5. Install Ghidra

```shell
wget https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_10.4_build/ghidra_10.4_PUBLIC_20230928.zip
sudo unzip ghidra_10.4_PUBLIC_20230928.zip  -d /opt/
sudo mv /opt/ghidra_10.4_PUBLIC /opt/ghidra 
rm -r ghidra_10.4_PUBLIC_20230928.zip
```

If you had to install ghidra in another directory than `/opt/`, change the ghidraSupportDir variable in ghidra.py:
```
        self.ghidraSupportDir    = "/opt/ghidra/support/" # Set ghidra support directory <!>
```

## 6. Install PfastreXML

Download PfastreXML from the [official webpage](http://manikvarma.org/code/PfastreXML/download.html) using the provided Google Drive link for the C++ 11 source code.
Unzip the source code into this directory.

Then compile it with the following commands.

```shell
conda deactivate
cd Tree_Extreme_Classifiers/Tree_Extreme_Classifiers/PfastreXML
make
mv PfastreXML_train ../../../XFL/res/
mv PfastreXML_predict ../../../XFL/res/
```

## 7. Download models and tables

Pre-trained models as well as PSQL dumps have to be downloaded from the Zenodo record.

```shell
wget https://zenodo.org/records/10733597/files/XFL-R_Models_Tables.zip
unzip XFL-R_Models_Tables.zip
rm XFL-R_Models_Tables.zip
```

### Minimal test (15m, 4Gb of memory)

```shell
conda activate XFL
cd XFL/
bash minimalTest.sh
```

Results are inside the directory `XFL/res/minimal-test`.

