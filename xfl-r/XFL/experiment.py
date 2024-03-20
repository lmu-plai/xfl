
"""

Copyright 2017-2024 by James Patrick-Evans, Moritz Dannehl, Tristan Benoit, and Johannes Kinder.

This file is part of XFL.

XFL is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

XFL is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with XFL. If not, see <https://www.gnu.org/licenses/>. 

"""

import numpy as np
from scipy.sparse import csr_matrix, lil_matrix, dok_matrix, csc_matrix
import functools
from joblib import Parallel, delayed
from itertools import chain
import pickle
import tqdm
import collections
from sklearn.model_selection import train_test_split
import hashlib

import utils
import config
import database
import NLP


class Experiment():
	def __init__(self, config):
		utils._desyl_init_class_(self, config)

		self.pdb = database.PostgresDB(config)
		self.operations_vector  = []
		self.jumpkinds_vector   = []
		self.label_vector	   = []
		self.func_arg_vector	= []
		self.name_vector		= []
		self.known_name_vector  = []
		self.token_vector	   = []
		self.constants_vector   = []
		self.minhashes_vector   = []
		self.hashes_vector	  = []		
		self.imported_data_refs_vector = []
		
		self.operations_vector_dims = 0
		self.jumpkinds_vector_dims  = 0
		self.label_vector_dims	  = 0
		self.func_arg_vector_dims   = 0
		self.name_vector_dims	   = 0
		self.known_name_vector_dims = 0
		self.token_vector_dims	  = 0
		self.constants_vector_dims  = 0
		self.minhashes_vector_dims  = 0
		self.hashes_vector_dims	 = 0
		self.imported_data_refs_dims = 0

		##frequent operations, build cache as dict
		##caches are built lazily
		self.operations_vector_index_cache  = {}
		self.jumpkinds_vector_index_cache   = {}
		self.label_vector_index_cache	   = {}
		self.func_arg_vector_index_cache	= {}
		self.name_vector_index_cache		= {}
		self.known_name_vector_index_cache  = {}
		self.token_vector_index_cache	   = {}
		self.constants_vector_index_cache   = {}
		self.minhashes_vector_index_cache   = {}
		self.hashes_vector_index_cache	  = {}
		self.imported_data_refs_vector_index_cache	  = {}

		self.symbol2vec		 = {}
		self.assumed_known = set([
			'csu_fini', 'csu_init', 'register_tm_clones', 'deregister_tm_clones', 
			'start', 'fini', 'init', 'do_global_dtors_aux', 'frame_dummy'
		])

	def load_settings(self, path):
		self.logger.debug("Loading experiment settings")
		with open(path + "/experimentsSettings", "rb") as f:			
			res = pickle.load(f)

		for k in [ 'operations_vector', 'jumpkinds_vector', 'label_vector', 'name_vector', 'token_vector', 'constants_vector', 'minhashes_vector', 'hashes_vector', 'imported_data_refs_vector', 'known_name_vector']:
			if k in res:
				setattr(self, k, res[k])
				setattr(self, k+'_dims', len(res[k]))
			else:
				self.logger.warning("Missing key in experiment settings: `{}`".format(k))

		self.constants = set(self.constants_vector)
		self.minhashes = set(self.minhashes_vector)
		self.hashes = set(self.hashes_vector)
		self.imported_data_refs = set(self.imported_data_refs_vector)
		self.minhashes = set(self.minhashes_vector)

		##dataset settings
		self.training_binary_ids	= res['training_binary_ids']
		self.validation_binary_ids	= res['validation_binary_ids']
		self.testing_binary_ids	= res['testing_binary_ids']

	
	@staticmethod
	def _mp_symbols2_to_labels(chunk):
		"""
			Process a chnk of names into labels
		"""
		c = config.Config()
		nlp = NLP.NLP(c)
		return [nlp.canonical_set(i) for i in chunk]

	def train_val_test_split(self, filter_bin_ids: set = set([]), train_size=0.8, val_size=0.1):
		"""
			Generate random train:val:test split. Ratio of 80:10:10
		"""
		test_size = 1.0 - (train_size + val_size)
		self.logger.info("Splitting binaries into: training::{}, validation::{}, testing::{}".format(train_size, val_size, test_size))
		bin_ids = set(self.pdb.binary_ids())
		self.logger.debug("{} binaries in the database".format(len(bin_ids)))

		if len(bin_ids) == 0:
			raise RuntimeError("No analysed binaries in database.")

		##limit to set of binary ids
		if len(filter_bin_ids) > 0:
			bin_ids &= filter_bin_ids

		self.logger.debug("{} binaries in dataset after filter applied".format(len(bin_ids)))
		train, Z	= train_test_split(list(bin_ids), train_size=train_size)
		mod_test_size = test_size / (test_size + val_size)
		val, test   = train_test_split(Z, test_size=mod_test_size)

		self.training_binary_ids	= train
		self.validation_binary_ids  = val
		self.testing_binary_ids	 = test
		self.logger.info("{} binaries in the training set, {} binaries in the validation dataset, {} binaries in the testing set".format(len(train), len(val), len(test)))
		return train, val, test

	def gen_settings(self, filter_bin_ids=False, predetermined_dataset_split=False):
		"""
			Generate configuration and feature vectors value for an experiment instance.
				- For a given dataset, generate sets of known and unknown names, hashes, CFGs, ..., etc

				arg: predetermined_dataset_split:bool: Use preset values for training, validation, and testing sets
				farg: filter_bin_ids: List of binary ids to limit dataset

				filter_bin_ids has no effect when predetermined_dataset_split is true
		"""
		ML_NAME_VEC_DIM = 8192 + 4096
		self.logger.debug("Generating experiment settings for current configuration! This may take some time.")

		if not self.pdb.conn:
			self.pdb.connect()

		m_bin_filter = filter_bin_ids
		if isinstance(filter_bin_ids, bool) and not filter_bin_ids:
			m_bin_filter	= set([])
		
		#Compute dataset split from a list of binaries
		if not predetermined_dataset_split:
			self.train_val_test_split(filter_bin_ids=m_bin_filter)
		else:
			for k in ('training_binary_ids', 'validation_binary_ids', 'testing_binary_ids'):
				assert(isinstance(getattr(self, k), list))
				assert(len(getattr(self, k)) > 0)

		#self.parseFastTextvecFile(self.config.desyl + '/res/model.vec')
		
		#self.training_binary_ids = [21]
		
		curr = self.pdb.conn.cursor()
		for name, key, group in [
				('token_vector', 'name', False),
				('operations_vector', 'vex -> \'operations\'', True),
				('jumpkinds_vector', 'vex -> \'jumpkinds\'', True),				
				('imported_data_refs_vector', 'imported_data_refs', False),				
				]:
			self.logger.debug("Fetching all {}".format(key))
			query   = "SELECT {} AS field FROM public.functions".format(key)

			#limit query to specific binaries
			query   += " WHERE public.functions.binary_id IN ({})".format(",".join(map(lambda x: str(x), self.training_binary_ids)))

			if group:
				query   += " GROUP BY field"

			self.logger.debug("Executing SQL: {}".format(query))
			curr.execute(query)
			res = list(map(lambda x: x[0], curr.fetchall()))
			if not res:
				raise RuntimeError("Failed to generate distinct {} for experiment".format(name))

			if name in ['operations_vector', 'jumpkinds_vector', 'imported_data_refs_vector']:
				res = list(functools.reduce(lambda x, y: x | set(y), res, set([])))

			elif name == 'token_vector':
				self.logger.info("Generating name token vector")
				nlp	 = NLP.NLP(self.config)
				##need to fetch all callees
				res2	= self.pdb.all_callees(filter_bin_ids=self.training_binary_ids)
				##append generators
				chunks  = utils.n_chunks(list(chain(res, res2)), 512)
				mod_res = Parallel(n_jobs=self.config.analysis.THREAD_POOL_THREADS)(delayed(Experiment._mp_symbols2_to_labels)(c) for c in chunks)
				c = collections.Counter()
				for r in tqdm.tqdm(mod_res, desc='Function name tokenization processing'):
					for s in r:
						c.update(s)
				
				c_tok_k, c_tok_v = zip(*c.most_common(ML_NAME_VEC_DIM))
				res = list(c_tok_k)

			setattr(self, name, res)
			setattr(self, name + '_dims', len(res))

		self.logger.info("Building name vectors...")
		self.known_name_vector	  = list(self.pdb.all_known_functions(filter_bin_ids=self.training_binary_ids))
		self.known_name_vector_dims = len(self.known_name_vector)

		self.unknown_name_vector	  = list(self.pdb.all_unknown_functions(filter_bin_ids=self.training_binary_ids))
		self.unknown_name_vector_dims = len(self.unknown_name_vector)

		self.name_vector	  = list(set(self.known_name_vector) | set(self.unknown_name_vector))
		self.name_vector_dims = len(self.name_vector)

		self.logger.info("Building imported_data_refs vectors...")
		self.imported_data_refs = set(self.imported_data_refs_vector)

		self.logger.info("Building constants vectors...")
		tfidf_consts				= self.tfidf_constants(min_freq=5, max_freq=5000, filter_bin_ids=filter_bin_ids)
		self.constants_vector	   = list(tfidf_consts.keys())
		self.constants_vector_dims  = len(self.constants_vector)
		self.constants = set(self.constants_vector)

		self.logger.info("Building opcode hash vectors...")
		##build vector of most frequent opcode hashes
		freq_hashes				 = self.freq_opcode_hashes(freq=5, filter_bin_ids=self.training_binary_ids)
		self.hashes_vector		  = list(freq_hashes.keys())
		self.hashes_vector_dims	 = len(self.hashes_vector)
		self.hashes				 = set(self.hashes_vector)

		self.logger.info("Building opcode minhash vectors...")
		##build vector of most frequent opcode minhashes
		freq_minhashes				 = self.freq_opcode_minhashes(freq=5, filter_bin_ids=self.training_binary_ids)
		self.minhashes_vector		  = list(freq_minhashes.keys())
		self.minhashes_vector_dims	 = len(self.minhashes_vector)
		self.minhashes				 = set(self.minhashes_vector)
		


	def tfidf_constants(self, min_freq=3, max_freq=100, filter_bin_ids=None):
		###calculate term frequency inverse document frequency of constants
		self.logger.info("Fetching all symbol constants!")
		f_idf_consts = self.pdb.constants_freq(max_freq=max_freq, min_freq=min_freq, filter_bin_ids=filter_bin_ids)
		return f_idf_consts

	def freq_opcode_hashes(self, freq=25, filter_bin_ids=None):
		self.logger.info("Fetching all opcode hashes!")
		curr = self.pdb.conn.cursor()
		query   = "SELECT opcode_hash FROM public.functions"
		if filter_bin_ids:
			query += " WHERE public.functions.binary_id IN ({})".format(",".join(map(lambda x: str(x), filter_bin_ids)))

		curr.execute(query)
		opcode_hashes = list(map(lambda x: bytes(x[0]), curr.fetchall()))

		hash_freqs = collections.Counter(opcode_hashes)

		hashes = {}
		for key, value in tqdm.tqdm(hash_freqs.items(), desc="Opcode Hash Frequencies"):
			if value > freq:
				hashes[key] = value

		return hashes



	def freq_opcode_minhashes(self, freq=25, filter_bin_ids=None):
		self.logger.info("Fetching all opcode minhashes!")
		curr = self.pdb.conn.cursor()
		query   = "SELECT opcode_minhash FROM public.functions"
		if filter_bin_ids:
			query += " WHERE public.functions.binary_id IN ({})".format(",".join(map(lambda x: str(x), filter_bin_ids)))

		curr.execute(query)
		opcode_minhashes = list(map(lambda x: hashlib.md5(utils.py_obj_from_bytes(x[0]).view(np.uint8)).hexdigest(), curr.fetchall()))

		minhash_freqs = collections.Counter(opcode_minhashes)

		hashes = {}
		for key, value in tqdm.tqdm(minhash_freqs.items(), desc="Opcode Minhash Frequencies"):
			if value > freq:
				hashes[key] = value
		return hashes

	def save_settings(self, path):
		with open(path  + "/experimentsSettings", "wb") as f:
			pickle.dump(self.get_settings(), f)		
		 
		
	def get_settings(self):
		return {
				'name'				  : self.config.experiment.name,
				'operations_vector'	 : self.operations_vector,
				'jumpkinds_vector'	  : self.jumpkinds_vector,   
				'label_vector'		  : self.label_vector,	   
				'constants_vector'	  : self.constants_vector,
				'hashes_vector'		 : self.hashes_vector,
				'minhashes_vector'	 : self.minhashes_vector,
				'imported_data_refs_vector'	: self.imported_data_refs_vector,
				'name_vector'		   : self.name_vector,	
				'known_name_vector'	 : self.known_name_vector,	
				'token_vector'		  : self.token_vector,	
				'training_binary_ids'   : self.training_binary_ids,
				'validation_binary_ids' : self.validation_binary_ids,
				'testing_binary_ids'	: self.testing_binary_ids
		}
		

	def to_vec(self, name, arr):
		"""
			Convert an array of type {name} into its vector format
		"""
		if not isinstance(arr, collections.abc.Iterable):
			raise RuntimeError("arr should be a list of items to be in the vector")

		valid_names = ['jumpkinds_vector',
				'operations_vector', 'name_vector', 'label_vector', 'known_name_vector',
				'token_vector', 'constants_vector', 'hashes_vector', 'minhashes_vector']
		if name not in valid_names:
			raise RuntimeError("Error, name needs to be in {}. {} given.".format(valid_names, name))

		if name == 'minhashes_vector':
			arr = hashlib.md5(arr.view(np.uint8)).hexdigest()


		dim = getattr(self, name + '_dims')
		vec = np.zeros( (dim, ), dtype=np.int64 )

		cache = getattr(self, name + '_index_cache')
		for it in arr:
			if it in cache:
				ind = cache[it]
				vec[ind] += 1
			else:
				vector_desc = getattr(self, name)
				#check item exists
				if it not in vector_desc:
					#self.logger.debug(f"Missing {it} in {name}")
					continue

				ind = vector_desc.index( it )
				assert(ind >= 0)
				assert(ind < dim)
				vec[ind] += 1
				cache[it] = ind
				##write cache back
				setattr(self, name + '_index_cache', cache)

		return vec

	def to_sparse_vec(self, name, arr, sparse_type):
		"""
			Convert an array of type {name} into its vector format
		"""
		if not isinstance(arr, collections.abc.Iterable):
			raise RuntimeError("arr should be a list of items to be in the vector")

		valid_names = ['jumpkinds_vector', 'operations_vector', 'name_vector', 'label_vector', 'token_vector', 'known_name_vector', 'constants_vector', 'minhashes_vector', 'hashes_vector', 'imported_data_refs_vector']
		if name not in valid_names:
			raise RuntimeError("Error, name needs to be in {}. {} given.".format(valid_names, name))

		valid_sparse_types = ['csr', 'csc', 'dok', 'lil']
		if sparse_type not in valid_sparse_types:
			raise RuntimeError("Error, sparse_type needs to be in {}. {} given.".format(valid_sparse_types, sparse_type))


		dim = getattr(self, name + '_dims')

		if sparse_type == 'csr':
			vec = csr_matrix( (1, dim), dtype=np.int64 )
		elif sparse_type == 'csc':
			vec = csc_matrix( (1, dim), dtype=np.int64 )
		elif sparse_type == 'dok':
			vec = dok_matrix( (1, dim), dtype=np.int64 )
		elif sparse_type == 'lil':
			vec = lil_matrix( (1, dim), dtype=np.int64 )


		cache = getattr(self, name + '_index_cache')
		for it in arr:
			if it in cache:
				ind = cache[it]
				vec[0, ind] += 1
			else:
				vector_desc = getattr(self, name)
				##warn if item not n list
				try: 
					ind = vector_desc.index( it )
					assert(ind >= 0)
					assert(ind < dim)
					vec[0, ind] += 1
					cache[it] = ind
					##write cache back
					setattr(self, name + '_index_cache', cache)
				except Exception as e:
					self.logger.debug("Value {} not in {}!".format(it, name))
					self.logger.debug(e)
					continue

		return vec

	def to_sparse_lil_vec(self, name, arr):
		"""
			Convert an array of type {name} into its vector format
		"""
		return self.to_sparse_vec(name, arr, 'lil')

	def to_sparse_dok_vec(self, name, arr):
		"""
			Convert an array of type {name} into its vector format
		"""
		return self.to_sparse_vec(name, arr, 'dok')

	def to_sparse_csc_vec(self, name, arr):
		"""
			Convert an array of type {name} into its vector format
		"""
		return self.to_sparse_vec(name, arr, 'csc')

