
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
from NLP import NLP
from database import PostgresDB

from sklearn.preprocessing import StandardScaler
import numpy as np

import joblib
from tqdm import tqdm
from copy import deepcopy
from math import ceil
from random import shuffle
import time
import logging

def chunkify(l, n):
    for i in range(0, n):
        yield l[i::n]

def shortName(s):	
	return s.real_name

def binaryV(qZ, cZ, functionsFeatures):
	qB, cB = deepcopy(qZ), deepcopy(cZ)	
	for n in functionsFeatures:
		q, c = functionsFeatures[n]
		qB += q
		cB += c

	if len(functionsFeatures) != 0:
		qB = qB / len(functionsFeatures)
		cB = cB / len(functionsFeatures)
	return (qB, cB)

def functionV(qZ, cZ, s, functionsFeatures):
	qF, cF = deepcopy(qZ), deepcopy(cZ)
	i = 0	
	for n in s.callers.union(s.callees):
		if not(n in functionsFeatures):
			continue	
		q, c = functionsFeatures[n]
		qF += q
		cF += c
		i += 1
	
	if i != 0:
		qF = qF/i
		cF = cF/i
	return (qF, cF)

def loadSymbolsQVectors(chunk, argsD):
	conf = Config()
	conf.logger.setLevel(logging.ERROR)
	exp = Experiment(conf)
	exp.load_settings(conf.res)
	nlp = NLP(conf)

	functionsFeatures = []
	for symbols, known, _ in chunk:
		for s in symbols:
			q, _ = s.to_vec(exp, nlp, known, argsD)
			q = q.squeeze()
			functionsFeatures += [q]
	return functionsFeatures

def makeScaler(argsD):
	conf = Config()
	conf.logger.setLevel(logging.ERROR)
	exp = Experiment(conf)
	exp.load_settings(conf.res)
	db = PostgresDB(conf)
	db.connect()

	symbols = []
	for path in tqdm(db.binary_paths_from_ids(exp.training_binary_ids), desc='Loading symbols from DB'):
		symbols += [db.binary_symbols(path)]
	
	shuffle(symbols)
	chunks = list(chunkify(symbols, conf.analysis.THREAD_POOL_THREADS))
	res = joblib.Parallel(n_jobs=conf.analysis.THREAD_POOL_THREADS)(joblib.delayed(loadSymbolsQVectors)(chunk, argsD) for chunk in chunks )
	functionsFeatures = []
	for r in tqdm(res, desc='Loading vectors'):
		for q in r:
			functionsFeatures += [q]
	
	shuffle(functionsFeatures)
	functionsFeatures = np.stack( functionsFeatures, axis=0 )

	scaler = StandardScaler()
	batch_size  = 1024
	niters      = ceil(functionsFeatures.shape[0] / batch_size)
	for ind in tqdm(range(niters), total=niters, desc='Calculating normalization'):
		scaler          = scaler.partial_fit(functionsFeatures[ind*batch_size:(ind+1)*batch_size])

	joblib.dump(scaler, argsD["directory"] + '/dexterScaler')    


def loadSymbolsVectors(chunk, argsD):
	conf = Config()
	conf.logger.setLevel(logging.ERROR)
	exp = Experiment(conf)
	exp.load_settings(conf.res)
	nlp = NLP(conf)

	scaler = joblib.load(argsD["directory"] + '/dexterScaler')

	dexterFeatures = []
	for symbols, known, fIds in tqdm(chunk, desc='Loading vectors'):
		if len(symbols) == 0:
			continue
			
		functionsFeatures = {}
		for s in symbols:
			n   = shortName(s)
			q, c = s.to_vec(exp, nlp, known, argsD)
			functionsFeatures[n] = (scaler.transform(q), c)

		qZ, cZ = 0*deepcopy(functionsFeatures[n][0]), 0*deepcopy(functionsFeatures[n][1])
		binaryContext = binaryV(qZ, cZ, functionsFeatures)
		for i in range(len(symbols)):			
			n   = shortName(symbols[i])
			fId = fIds[i]
			functionContext = functionV(qZ, cZ, symbols[i], functionsFeatures)
			dexterFeatures += [ [fId, functionsFeatures[n], binaryContext, functionContext] ]
	return dexterFeatures

def loadDexterFeaturesVectors(binsID, argsD, full=False):
	conf = Config()
	conf.logger.setLevel(logging.ERROR)
	db = PostgresDB(conf)
	db.connect()

	paths = db.binary_paths() if full else db.binary_paths_from_ids(binsID)	
	symbols = []
	for path in tqdm(paths, desc='Loading symbols from DB'):
		symbols += [db.binary_symbols(path)]

	shuffle(symbols)
	chunks = list(chunkify(symbols, conf.analysis.THREAD_POOL_THREADS))
	res = joblib.Parallel(n_jobs=conf.analysis.THREAD_POOL_THREADS)(joblib.delayed(loadSymbolsVectors)(chunk, argsD) for chunk in chunks )

	dexterFeatures = []
	for r in tqdm(res, desc='Loading vectors'):
		for vs in r:
			dexterFeatures += [vs]
	shuffle(dexterFeatures)
	return dexterFeatures



