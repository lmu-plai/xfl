
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

def convert_sparse_matrix_to_list(x):
	coo = x.tocoo()
	indices = coo.col #np.mat([coo.row, coo.col]).transpose()
	return indices #tf.sparse.reorder(tf.SparseTensor(indices, coo.data, coo.shape))

parser = ArgumentParser()
parser.add_argument('-v', '--verbose', action='store_true', help='Enable DEBUG logging')

# Objective
parser.add_argument('-d', '--directory', required=True, help="DEXTER model directory")
parser.add_argument('-learn', '--learn', action='store_true', help='Learn model with training data')
parser.add_argument('-validate', '--validate', action='store_true', help='Show best epoch with validation data')
parser.add_argument('-exportEpoch', '--export-epoch', default=0, type=int, help='Export embeddings using the given epoch')
parser.add_argument('-newSplit', '--new-split', action='store_true', help='When exporting, prepare a new train-val-test split (useful for using pretrained models)')


# Hyperparameters
parser.add_argument('-lr', '--learning-rate', default=1e-4, type=float)
parser.add_argument('-dim', '--dim', default=512, type=int)
parser.add_argument('-subDim', '--sub-dim', default=768, type=int)
parser.add_argument('-batchSize', '--batch_size', default=2048, type=int)
parser.add_argument('-epochs', '--epochs', default=50, type=int)

# Hashing
parser.add_argument('-hash', '--hashing', action='store_true', help='Enable hashing for categorical sparse features')
parser.add_argument('-hashDim', '--hashing-dim', default=1024, type=int)

# Quant
parser.add_argument('-small', '--small-vec', action='store_false', help='Disable')
parser.add_argument('-jumpkinds', '--jumpkinds-vec', action='store_false', help='Disable')
parser.add_argument('-operations', '--operations-vec', action='store_false', help='Disable')
parser.add_argument('-icfg', '--icfg-vec', action='store_false', help='Disable')
parser.add_argument('-node', '--node-vec', action='store_false', help='Disable')
parser.add_argument('-taintedRegisterTypes', '--tainted-register-types', action='store_false', help='Disable')

# Cat
parser.add_argument('-opHash', '--opcode-hashes-vec', action='store_false', help='Disable')
parser.add_argument('-opMinhash', '--opcode-minhashes-vec', action='store_false', help='Disable')
parser.add_argument('-consts', '--consts-vec', action='store_false', help='Disable')
parser.add_argument('-callees', '--callees-vec', action='store_false', help='Disable')
parser.add_argument('-callers', '--callers-vec', action='store_false', help='Disable')
parser.add_argument('-closure', '--closure-vec', action='store_false', help='Disable')
parser.add_argument('-dataRefs', '--data-refs-vec', action='store_false', help='Disable')
parser.add_argument('-tflows', '--tflows-vec', action='store_false', help='Disable')


args = parser.parse_args()
argsD = vars(args)
	
conf = Config()
conf.logger.setLevel(logging.ERROR)	
if args.verbose:
	conf.logger.setLevel(logging.INFO)

if int(args.learn) + int(args.validate) + int(args.export_epoch > 0) != 1: 
	conf.logger.critical("Enter either learn, validate, or export_epoch!")
	exit()

exp = Experiment(conf)

# Loading data and paramters
conf.logger.info("Loading data and paramters")

directory = conf.res + "/" + args.directory	
directoryExist = os.path.isdir(directory)

argsD["directory"] = directory
data = None

if args.learn: # Compute model training parameters and save parameters
	exp.load_settings(conf.res)

	if directoryExist:
		conf.logger.critical("The directory was already used for learning a model!")
		exit()	
	os.mkdir(directory)
	makeScaler(argsD)
	data = loadDexterFeaturesVectors(exp.training_binary_ids, argsD)		
	epoch_batches       = ceil(len(data) /args.batch_size)
	save_freq           = epoch_batches
	max_batches         = epoch_batches * args.epochs
	argsD["epoch_batches"] = epoch_batches
	argsD["save_freq"]     = save_freq
	argsD["max_batches"] = max_batches
	
	with open(directory + "/argsD", "wb") as f:			
		pickle.dump(argsD, f)
	
	# Save global settings of the experiments in case the directory is exported
	exp.save_settings(directory)

elif (args.validate or args.export_epoch > 0): # Load prevous parameters
	if directoryExist == False:
		conf.logger.critical("Learn before validation or exporting_epoch!")
		exit()
		
	exp.load_settings(directory)

	with open(directory + "/argsD", "rb") as f:			
		argsD = pickle.load(f)
	
	argsD["directory"] = directory
	argsD["learn"] = args.learn
	argsD["validate"] = args.validate	
	argsD["export_epoch"] = args.export_epoch
	argsD["new_split"] = args.new_split
	argsD["batch_size"] = args.batch_size
	
	with open(directory + "/argsD", "wb") as f:			
		pickle.dump(argsD, f)

	if args.validate:
		data = loadDexterFeaturesVectors(exp.validation_binary_ids, argsD)
	else:			
		data = loadDexterFeaturesVectors([], argsD, full=True)

conf.logger.setLevel(logging.INFO)	
conf.logger.info("DEXTER parameters:")
conf.logger.info(str(argsD))

conf.logger.info("Number of functions: {}".format(len(data)))

# Hasher
hashing = argsD["hashing"]
hasher = tf.keras.layers.Hashing(num_bins=argsD["hashing_dim"], output_mode="count")

tf.config.threading.set_inter_op_parallelism_threads    = conf.analysis.THREAD_POOL_THREADS
	
def sampleLoader(i):
	i = i.numpy() # Decoding from the EagerTensor object
	
	qF, cF   =  data[i][1]
	qB, cB   =  data[i][2]
	qCF, cCF =  data[i][3]
	fId      =  data[i][0]
	
	if hashing:
		cF  = convert_sparse_matrix_to_list(cF)
		cB  = convert_sparse_matrix_to_list(cB)
		cCF = convert_sparse_matrix_to_list(cCF)

		cF  = hasher(cF)
		cB  = hasher(cB)
		cCF = hasher(cCF)
	else:
		cF    = np.array(cF.todense())
		cB    = np.array(cB.todense())
		cCF   = np.array(cCF.todense())
	
	v = np.concatenate((qF, cF, qB, cB, qCF,  cCF), axis=None)
	v = np.expand_dims(v, axis=0)
	v = tf.convert_to_tensor(v, dtype=tf.float32)
	return v, fId

# Hyper parameters
learning_rate        = argsD["learning_rate"]
intermediate_dim     = argsD["dim"]
sub_intermediate_dim = argsD["sub_dim"]
batch_size           = argsD["batch_size"]

# Model
em_dim              = (sampleLoader(tf.constant(0))[0].shape[1])/3
in_dim              = (1, em_dim * 3)
out_dim             = in_dim

# Model training/saving parameters
checkpoint_path       = directory + "/checkpoint.{}.ckpt"
embeddings_path       = directory + "/embeddings"
nlp_path              = directory + "/nlpData"
epoch_batches         = argsD["epoch_batches"]
save_freq             = argsD["save_freq"]
epochs                = argsD["epochs"]
max_batches           = argsD["max_batches"]
checkpoint            = argsD["export_epoch"] * epoch_batches

conf.logger.info("Features dimension: {} x 3 = {}".format(int(em_dim), int(em_dim*3)))

z = list(range(len(data)))
dataset = tf.data.Dataset.from_generator(lambda: z, tf.int64)
dataset = dataset.shuffle(buffer_size=len(z), seed=0, reshuffle_each_iteration=True)
dataset = dataset.map(lambda i: tf.py_function(func=sampleLoader,  inp=[i],  Tout=[tf.float32,tf.float32]),  num_parallel_calls=tf.data.AUTOTUNE)
dataset = dataset.batch(batch_size)
dataset = dataset.prefetch(tf.data.AUTOTUNE)

if argsD["learn"]:
	conf.logger.info("About to train autoencoder...")		
	dataset = dataset.repeat()
	autoencoder = Autoencoder(intermediate_dim=intermediate_dim, sub_intermediate_dim=sub_intermediate_dim, out_dim=out_dim[1], training=True)
	opt = tf.optimizers.Adam(learning_rate=learning_rate)
	loss    = tf.keras.losses.MeanSquaredError()
	g_it    = 0
	for step, batch in enumerate(dataset):
		start = time.time()			
		X, _ = batch
		with tf.GradientTape() as tape:
			loss_values = loss(X, autoencoder(X))
			gradients = tape.gradient(loss_values, autoencoder.trainable_variables)
		gradient_variables = zip(gradients, autoencoder.trainable_variables)
		opt.apply_gradients(gradient_variables)
		loss_value = loss_values.numpy()
		elapsed = time.time() - start
		conf.logger.info("[+] Batch: {}, Loss: {}, T: {}s".format(g_it, loss_value, elapsed))

		g_it += 1
		if g_it > max_batches:
			autoencoder.save_weights(checkpoint_path.format(g_it+1))
			break
		if g_it % save_freq == 0:
			autoencoder.save_weights(checkpoint_path.format(g_it))
			del X
			del batch
			del loss_values
			del gradients
			del gradient_variables
			gc.collect()

elif argsD["validate"]:
	conf.logger.info("About to validate autoencoder...")
	loss    = tf.keras.losses.MeanSquaredError()	
	for checkpoint in range(epoch_batches * 1, epoch_batches*epochs, epoch_batches):
		weightsPath = checkpoint_path.format(checkpoint)
		if os.path.isfile(weightsPath+".index") == False:
			continue
		epoch = int(checkpoint / epoch_batches)
		autoencoder = Autoencoder(intermediate_dim=intermediate_dim, sub_intermediate_dim=sub_intermediate_dim, out_dim=out_dim[1], training=False)
		autoencoder.load_weights(weightsPath)
		lossS = 0.0
		for batch in tqdm(dataset):
			X, _ = batch
			loss_values = loss(X, autoencoder(X))
			loss_value = loss_values.numpy()
			lossS += loss_value
		conf.logger.info("[+] Epoch: {}, Loss: {}".format(epoch, lossS))

elif argsD["export_epoch"] > 0:
	conf.logger.info("About to save embeddings from autoencoder...")
	weightsPath = checkpoint_path.format(checkpoint)
	epoch = int(checkpoint / epoch_batches)
	autoencoder = Autoencoder(intermediate_dim=intermediate_dim, sub_intermediate_dim=sub_intermediate_dim, out_dim=out_dim[1], training=False)
	autoencoder.load_weights(weightsPath)		
	embeddings = {}
	for batch in tqdm(dataset):
		X, fIdS = batch
		Y    = autoencoder.encoder(X)
		Y    = Y.numpy()
		fIdS = list(fIdS.numpy())
		for i, fId in enumerate(fIdS):
			embeddings[int(fId)] = np.squeeze(Y[i])
	with open(embeddings_path, "wb") as f:
		pickle.dump(embeddings, f)

	
	exp.pdb.connect()	
	
	if argsD["new_split"]:
		exp.train_val_test_split()
		exp.save_settings(directory)

	conf.logger.info("About to save names for experiments...")
	nlp	= NLP.NLP(conf)
	nlpData = []
	for split in [exp.training_binary_ids, exp.validation_binary_ids, exp.testing_binary_ids]:
		dataS = []
		for path in tqdm(exp.pdb.binary_paths_from_ids(split)):		
			for [bId, fId, name, real_name] in exp.pdb.binary_functions_names(path):
				canonSet, canonName = nlp.canonical_set_name(name)				
				dataS += [[path, bId, fId, name, real_name, canonSet, canonName]]
		nlpData += [dataS]

	with open(nlp_path, "wb") as f:
		pickle.dump(nlpData, f)
