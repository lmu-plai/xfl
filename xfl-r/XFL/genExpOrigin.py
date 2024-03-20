
"""

Copyright 2017-2024 by James Patrick-Evans, Moritz Dannehl, Tristan Benoit, and Johannes Kinder.

This file is part of XFL.

XFL is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

XFL is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with XFL. If not, see <https://www.gnu.org/licenses/>. 

"""

#!/usr/bin/python3

from config import Config
from database import PostgresDB
from experiment import Experiment
from loadDexterFeatures import makeScaler

from utils import read_file_lines
import pickle

def readSelectedId(config, path):
	pathsS = [f for f in read_file_lines(path)]
	db = PostgresDB(config)
	db.connect()
	idS = db.binary_ids_from_paths(pathsS)
	return set(idS)

config = Config()
exp = Experiment(config)
exp.pdb.connect()

config.logger.info("Going back to the old XFL splits")

with open(config.res+"/origin/originTrainValTestSplit", "rb") as f:
	oldSplits  = pickle.load(f) # ['train', 'test', 'val']

allBinaries = set(exp.pdb.binary_ids())
pathsTobId = {}
for bId in allBinaries:
	pathsTobId[exp.pdb.binary_paths_from_ids([bId])[0]]  = bId

for split in oldSplits:
	for i in range(len(oldSplits[split])):
		if oldSplits[split][i] in pathsTobId:
			oldSplits[split][i] = pathsTobId[oldSplits[split][i]]

config.logger.info("OLD TRAIN: "+str(len(oldSplits["train"])))
config.logger.info("OLD VAL: "+str(len(oldSplits["val"])))
config.logger.info("OLD TEST: "+str(len(oldSplits["test"])))

exp.training_binary_ids	= list(allBinaries.intersection(set(oldSplits["train"])))
exp.validation_binary_ids  = list(allBinaries.intersection(set(oldSplits["val"])))
exp.testing_binary_ids	 = list(allBinaries.intersection(set(oldSplits["test"])))

config.logger.info("TRAIN: "+str(len(exp.training_binary_ids)))
config.logger.info("VAL: "+str(len(exp.validation_binary_ids)))
config.logger.info("TEST: "+str(len(exp.testing_binary_ids)))

exp.gen_settings(filter_bin_ids=readSelectedId(config, config.res+"/origin/originDataset.txt"), predetermined_dataset_split=True)
exp.save_settings(config.res)
