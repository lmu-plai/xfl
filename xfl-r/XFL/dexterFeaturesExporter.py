
"""

Copyright 2017-2024 by James Patrick-Evans, Moritz Dannehl, Tristan Benoit, and Johannes Kinder.

This file is part of XFL.

XFL is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

XFL is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with XFL. If not, see <https://www.gnu.org/licenses/>. 

"""

#!/usr/bin/python3

from config import Config
from experiment import Experiment
from loadDexterFeatures import makeScaler, loadDexterFeaturesVectors
from autoencoder import Autoencoder
import NLP


from argparse import ArgumentParser
import numpy as np
import pickle
import os
from tqdm import tqdm
from math import ceil
from random import shuffle
import time
import logging
import gc

import tensorflow as tf

parser = ArgumentParser()
parser.add_argument('-v', '--verbose', action='store_true', help='Enable DEBUG logging')
parser.add_argument('-d', '--directory', required=True, help="DEXTER model directory")

args = parser.parse_args()
argsD = vars(args)
	
conf = Config()
conf.logger.setLevel(logging.ERROR)	
if args.verbose:
	conf.logger.setLevel(logging.INFO)

exp = Experiment(conf)

# Loading data and paramters
conf.logger.info("Loading data and paramters")

directory = conf.res + "/" + args.directory	
directoryExist = os.path.isdir(directory)

exp.load_settings(directory)

with open(directory + "/argsD", "rb") as f:			
	argsD = pickle.load(f)

argsD["directory"] = directory

data = loadDexterFeaturesVectors([], argsD, full=True)

conf.logger.setLevel(logging.INFO)	
conf.logger.info("DEXTER parameters:")
conf.logger.info(str(argsD))

conf.logger.info("Number of functions: {}".format(len(data)))


def sampleLoader(i):	
	qF, cF   =  data[i][1]
	qB, cB   =  data[i][2]
	qCF, cCF =  data[i][3]
	fId      =  data[i][0]
	return qF, qB, qCF, cF, cB, cCF, fId

conf.logger.info("About to save features...")

features_path       = directory + "/features"
features = {}

for i in range(len(data)):	
	qF, qB, qCF, cF, cB, cCF, fId = sampleLoader(i)	
	features[fId] = (qF, qB, qCF, cF, cB, cCF)

with open(features_path, "wb") as f:
	pickle.dump(features, f)

