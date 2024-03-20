
"""

Copyright 2017-2024 by James Patrick-Evans, Moritz Dannehl, Tristan Benoit, and Johannes Kinder.

This file is part of XFL.

XFL is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

XFL is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with XFL. If not, see <https://www.gnu.org/licenses/>. 

"""

import os, sys
import copy
import numpy as np
import functools
import tqdm
import shlex, shutil
import json
import collections
import pickle
import utils
import pandas as pd
import math
import scipy
import scipy.sparse
import itertools
import gc
from joblib import Parallel, delayed
from tempfile import mkdtemp
import subprocess
from sys import exit
from argparse import ArgumentParser
from functools import partial
from multiprocessing import Pool
import logging
from IPython.utils.capture import capture_output
import random

from config import Config
from evaluation import Evaluation
from experiment import Experiment
import NLP

class PfastreXML():

	@staticmethod
	def count_tokens(it_tok_it):
		config = Config()
		nlp	= NLP.NLP(config)

		canonical_set = []
		c = collections.Counter()
		for tok_it in it_tok_it:
			cs = nlp.canonical_set(tok_it)
			c.update(cs)
			canonical_set.append(cs)
		return canonical_set, c

	@staticmethod
	def name_vector(canonical_sets, L):
		config = Config()
		exp = Experiment(config)
		exp.token_vector = L
		exp.token_vector_dims = len(L)
		return list(map(lambda x, c=exp.to_vec: c('token_vector', x), canonical_sets))

	@staticmethod
	def train_pfastrexml(data_dir, trn_X_fname, trn_Y_fname, a=1.0, b=1.0, c=1.0, max_inst_in_leaves=10, l=100, g=30, T=64, trees=256, pfast_dir="/root/XML/Tree_Extreme_Classifiers/PfastreXML/"):
		"""
			Runs PfatsreXML training and test commands with the given hyperparameters
			Sample Usage :
				./PfastreXML_train [feature file name] [label file name] [inverse propensity file name] [model folder name] -S 0 -T 1 -s 0 -t 50 -b 1.0 -c 1.0 -m 10 -l 100
				-g 30 -a 0.8 -q 1

				-S PfastXML switch, setting this to 1 omits tail classifiers, thus leading to PfastXML algorithm. default=0
				-T Number of threads to use. default=1
				-s Starting tree index. default=0
				-t Number of trees to be grown. default=50
				-b Feature bias value, extre feature value to be appended. default=1.0
				-c SVM weight co-efficient. default=1.0
				-m Maximum allowed instances in a leaf node. Larger nodes are attempted to be split, and on failure converted to leaves. default=10
				-l Number of label-probability pairs to retain in a leaf. default=100
				-g gamma parameter appearing in tail label classifiers. default=30
				-a Trade-off parameter between PfastXML and tail label classifiers. default=0.8
				-q quiet option (0/1). default=0
				feature and label files are in sparse matrix format
		"""
		#print("Running new PfastreXML instance under data directory: ", data_dir)
		trn_cmd = pfast_dir + "/PfastreXML_train " + "{}/{} {}/{} {}/inv_prop.txt {}/xml_model ".format(data_dir, trn_X_fname, data_dir, trn_Y_fname, data_dir, data_dir)
		trn_cmd += "-q 0 -S 0 -T {} -t {} -a {} -b {} -c {} -m {} -g {} -l {}".format(T, trees, a, b, c, max_inst_in_leaves, g, l)
		model_dir = "{}/xml_model".format(data_dir)
		if os.path.exists(model_dir):
			##empty directory contents
			#print("Clearing previous model...")
			shutil.rmtree(model_dir)

		os.makedirs(model_dir, exist_ok=True)

		#print("Running: ", trn_cmd)
		res = subprocess.call(shlex.split(trn_cmd), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
		if res < 0:
			raise RuntimeError("Error calling PfastreXML subprocess during training")

	@staticmethod	
	def pred_pfastrexml(data_dir, tst_X_fname, pfast_dir="/root/XML/Tree_Extreme_Classifiers/PfastreXML/"):
		tst_cmd = pfast_dir + "/PfastreXML_predict {}/{} {}/xml_score.mat {}/xml_model".format(data_dir, tst_X_fname, data_dir, data_dir)
		#print("Running: ", tst_cmd)
		res = subprocess.call(shlex.split(tst_cmd), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
		if res < 0:
			raise RuntimeError("Error calling PfastreXML subprocess during prediction")

	def __init__(self, config, exp, evaluation=False):
		"""
			XML classifier
		"""
		utils._desyl_init_class_(self, config)
		self.nlp		= NLP.NLP(config)
		
		if evaluation==False:
			self.exp		= exp
			self.directory  = mkdtemp(prefix='desyl-pfastrexml-')
		
		self.calculable_knowns = set([ 'init', 'fini', 'csu_init', 'csu_fini', 'start' , 'libc_csu_init', 'libc_csu_fini', 'libc_start', 'deregister_tm_clones', 'register_tm_clones', 'rtld_init', 'main', 'do_global_dtors_aux', 'frame_dummy', 'frame_dummy_init_array_entry', 'do_global_dtors_aux_fini_array_entry', 'init_array_end', 'init_array_start', 'start_main', 'libc_start_main'])

	def __fini__(self):
		#don't clean results files on exit
		#self.directory.cleanup()
		pass

	def fromData(self, names, embeddings, realNames, canonNames, binariesPath, df, k, functionSplit=False):
		
		self.logger.info("Generating label space for top {} labels...".format(k))
		self.L	   = self.generate_label_space(names, k=k)
			
		self.logger.info("Parsing embeddings and labels...")
		self.generate_dataframe(names, embeddings, realNames, canonNames, binariesPath, df, functionSplit=functionSplit)

		self.exp.token_vector = self.L
		self.exp.token_vector_dims = len(self.L)

		self.logger.info("Calculating inverse propensities...")
		self.inv_propensities(A=0.5, B=0.425)
		self.logger.info("Saving to XML txt format...")
		self.saveXMLdata()

		#save pandas dataframes
		for k in tqdm.tqdm([ "{}_{}".format(b, e) for b in ('trn', 'val', 'tst') for e in ('X', 'Y') ] + [ "name_df" ], desc="Saving model data"):
			value = getattr(self, k)
			value.to_pickle("{}/{}.pickle".format(self.directory, k))

	def generate_dataframe(self, names, embeddings, realNames, canonNames, binariesPath, df, functionSplit=False):
		"""
			Generate a pandas dataframe given a list of
			function names and a list of their embeddings
		"""
		l_index = df.index

		self.name_df		 = pd.DataFrame(names, columns=['name'], index=l_index)
		self.name_df.to_pickle('{}/name_df'.format(self.directory))

		self.real_name_df   =  pd.DataFrame(realNames, columns=['realName'], index=l_index)
		self.canon_name_df   =  pd.DataFrame(canonNames, columns=['canonName'], index=l_index)		
		self.binary_path_df =  pd.DataFrame(binariesPath, columns=['binaryPath'], index=l_index)
		
		embeddings_df   = pd.DataFrame(embeddings, columns=['embedding'], index=l_index)
		
		# BUG: need to regenerate dataset if label size changes
		# label size needs to change otherwise propensities of labels differs
		while True:			
			chunks = utils.n_chunks(self.canonical_sets, 256)
			results = Parallel(n_jobs=self.config.analysis.THREAD_POOL_THREADS, verbose=1, backend="multiprocessing")(map(delayed(PfastreXML.name_vector), chunks, itertools.repeat(self.L)))
			labels = functools.reduce(lambda x, y: x + y, results, [])
			labels_mat = np.vstack(labels)

			self.Y = pd.DataFrame(data=labels_mat, index=l_index)
			self.X = embeddings_df

			if functionSplit == False:

				self.trn_X  = self.X[self.X.index.isin(df.loc[df['b_id'].isin(self.exp.training_binary_ids)].index)]
				self.val_X  = self.X[self.X.index.isin(df.loc[df['b_id'].isin(self.exp.validation_binary_ids)].index)]
				self.tst_X  = self.X[self.X.index.isin(df.loc[df['b_id'].isin(self.exp.testing_binary_ids)].index)]

				self.trn_Y  = self.Y[self.Y.index.isin(df.loc[df['b_id'].isin(self.exp.training_binary_ids)].index)]
				self.val_Y  = self.Y[self.Y.index.isin(df.loc[df['b_id'].isin(self.exp.validation_binary_ids)].index)]
				self.tst_Y  = self.Y[self.Y.index.isin(df.loc[df['b_id'].isin(self.exp.testing_binary_ids)].index)]

			else:

				self.trn_X  = self.X[self.X.index.isin(self.exp.training_function_ids)]
				self.val_X  = self.X[self.X.index.isin(self.exp.validation_function_ids)]
				self.tst_X  = self.X[self.X.index.isin(self.exp.testing_function_ids)]

				self.trn_Y  = self.Y[self.Y.index.isin(self.exp.training_function_ids)]
				self.val_Y  = self.Y[self.Y.index.isin(self.exp.validation_function_ids)]
				self.tst_Y  = self.Y[self.Y.index.isin(self.exp.testing_function_ids)]
	
			Ln  = len(self.L)
			# Apply dataset preconditioning/prefiltering
			self.trn_X, self.trn_Y, self.L = self.precondition_dataset(self.trn_X, self.trn_Y, self.L)
			self.logger.info("Number of labels after dataset preconditioning/prefiltering {}".format(Ln))
			if Ln == len(self.L):
				break


	def saveXMLdata(self):
		self.write_label_names()
		self.write_features()
		self.write_labels()
		self.write_inv_prop()

	def update_propensities(self, A, B):
		self.logger.info("Calculating inverse propensities... A={}, B={}".format(A, B))
		self.inv_propensities(A=A, B=B)
		self.logger.info("Saving to XML txt format...")
		self.write_inv_prop()

	def generate_label_space(self, names, k=512):
		"""
			Generate label space for list of input names.
		"""
		chunks = utils.n_chunks(names, k)

		c = collections.Counter()
		results = Parallel(n_jobs=self.config.analysis.THREAD_POOL_THREADS, verbose=1, backend="multiprocessing")(map(delayed(PfastreXML.count_tokens), chunks))
		self.canonical_sets = []
		for s_canonical_set, s_counter in results:
			c += s_counter
			self.canonical_sets += s_canonical_set

		c_tok_k, c_tok_v = zip(*c.most_common(k))
		res = list(c_tok_k)
		return res


	def inv_propensities(self, A=3.0, B=0.5):
		"""
			calculate inverse propensity scores
			 P(y_t = 1 | y^*_t = 1)

			 N	  :: The size of the dataset
			 N_t	:: The number of data points annotated with label l
			 A, B   :: Hyperparameters
		"""
		N, L = self.trn_Y.shape
		# L is dimensions of label space
		C = (np.log(N) - 1)*np.power((B + 1), A)
		
		#self.logger.info("Labels propensities for "+str(N)+" and "+str(L))
		self.inv_props = np.zeros((L, ), dtype=float)
		for t in range(L):
			N_t = self.trn_Y[t].sum()			
			exp_t = np.exp(-A * np.log(N_t + B))
			i_pt = 1.0 + (C * exp_t)
			self.inv_props[t] = i_pt
			#self.logger.info(str(t)+":"+str(N_t))
			#self.logger.info(str(t)+":"+str(i_pt))
	@staticmethod
	def write_XML_txt(V, fname, shape=None):
		"""
			Write Pandas DataFrame to an XML formatted data file
			shape: override shape of matrix
		"""
		with open(fname, 'w') as f:
			vshape = V.shape
			if shape:
				vshape = shape

			f.write("{} {}\n".format(*vshape))
			for index, row in tqdm.tqdm(V.iterrows(), desc='Saving {}'.format(fname), total=vshape[0]):
				rd  = row.to_numpy()
				##extract data, different formats/shapes
				if rd.shape == (1,):
					rd = rd[0].reshape(-1)

				nz = rd.nonzero()
				I = nz[0]
				first = True
				for i in I:
					if not first:
						f.write(" ")
					#print("Writing row")
					f.write("{}:{:.6f}".format(i, rd[i]))
					first = False
				f.write("\n")

	def read_XML_txt(self, fname):
		"""
			Read Pandas DataFrame from an XML formatted data file
		"""
		with open(fname, 'r') as f:
			first_line = next(f)
			size = first_line.split()
			rows, cols = int(size[0]), int(size[1])
			self.logger.debug("Reading XML matrix of size `({},{})`".format(rows, cols))

			m = np.zeros((rows, cols), dtype=float)

			for i, row in tqdm.tqdm(enumerate(f), desc='Loading {}'.format(fname), total=rows):
				elems = row.split()
				for elem in elems:
					ind, val = elem.split(':')
					m[i, int(ind)] = float(val)

		return m

	def write_labels(self, trn_fname='trn_Y.txt', tst_fname='tst_Y.txt', val_fname='val_Y.txt'):
		PfastreXML.write_XML_txt(self.trn_Y, self.directory+"/"+trn_fname)
		PfastreXML.write_XML_txt(self.tst_Y, self.directory+"/"+tst_fname)
		PfastreXML.write_XML_txt(self.val_Y, self.directory+"/"+val_fname)

	def write_features(self, trn_fname='trn_X.txt', tst_fname='tst_X.txt', val_fname='val_X.txt'):
		ind, row = next(self.X.iterrows())
		embed_len = row['embedding'].shape[-1]
		PfastreXML.write_XML_txt(self.trn_X, self.directory+"/"+trn_fname, shape=(len(self.trn_X), embed_len))
		PfastreXML.write_XML_txt(self.tst_X, self.directory+"/"+tst_fname, shape=(len(self.tst_X), embed_len))
		PfastreXML.write_XML_txt(self.val_X, self.directory+"/"+val_fname, shape=(len(self.val_X), embed_len))

	def write_inv_prop(self, fname='inv_prop.txt'):
		with open(self.directory +"/"+fname, 'w') as f:
			for p in self.inv_props:
				f.write("{:.4f}\n".format(p))

	def write_label_names(self, fname='labels.txt'):
		with open(self.directory+"/"+fname, 'w') as f:
			for i, l in enumerate(self.L):
				f.write("{}:{}\n".format(i, l))

	def rank_labels(self, score_m_fname='xml_score.mat'):
		self.logger.info("Ranking labels against TEST set")
		m = self.read_XML_txt(self.directory+"/"+score_m_fname)
		for i, row in enumerate(m):
			ranked = np.argsort(row)[::-1]
			top_5 = ranked[:5]
			#print(i, top_5)

			# tst_X or tst_Y can be used here, 
			# getting the index of the dataframe to lookup function name
			func_index = self.tst_X.index[i]
			func_name   = self.name_df['name'][func_index]

			true_labels_inds = self.tst_Y.iloc[i].to_numpy().nonzero()[0]
			true_labels = " ".join(set([self.L[i] for i in true_labels_inds]))

			predicted_labels = "_".join(set([self.L[i] for i in top_5]))

			#fmt_rank = "{: <18} => \033[3m{: <18}\033[23m :: ━━┓".format(func_name, true_labels, predicted_labels)
			#bar_bck = "━"*(len(fmt_rank) - 2 - 9)
			fmt_rank = "{: <18} => {: <18} :: ━━┓".format(func_name, true_labels, predicted_labels)
			bar_bck = "━"*(len(fmt_rank) - 2 )

			print(fmt_rank)
			print("┏{}┛".format(bar_bck))
			tups = list(map(lambda x: ['┣', self.L[x], row[x]], top_5))
			tups[-1][0] = '┗'
			for k in tups:
				#print("{}━━ \033[3m{: <10}\033[23m :: {}".format(k[0], k[1], k[2]))
				print("{}━━ {: <10} :: {}".format(k[0], k[1], k[2]))

	def predict_labels(self, score_m_fname='xml_score.mat', threshold=0.1):
		self.logger.info("Predicting labels against TEST set")
		m	   = self.read_XML_txt(self.directory+"/"+score_m_fname)
		ml_Y	= np.zeros(m.shape)
		for i, row in enumerate(m):
			above_thresh				= np.where(row > threshold)
			ranked					  = np.argsort(row)[::-1]
			ranked_ind_above_threshold  = ranked[:len(above_thresh[0])]

			for p in ranked_ind_above_threshold:
				ml_Y[i, p]  = 1

			predicted_labels = list(map(lambda x: self.L[x], ranked_ind_above_threshold))
			predicted_name	= '_'.join(predicted_labels)

			# tst_X or tst_Y can be used here, 
			# getting the index of the dataframe to lookup function name
			func_index 			= self.tst_X.index[i]
			func_name   		= self.name_df['name'][func_index]			
			func_real_name  	= self.real_name_df['realName'][func_index]
			func_canonl_name  	= self.canon_name_df['canonName'][func_index]
			
			binary_path = self.binary_path_df['binaryPath'][func_index]
			fmt = " {} {} {} {} => {}".format(binary_path, func_real_name, func_name, func_canonl_name, predicted_name)
			self.logger.info(fmt)
		return ml_Y

	def ml_scores(self, threshold=0.215, CALC_KNOWNS=False, REMOVE_CALC=True):
		eval = Evaluation()
		pred_Y  = self.predict_labels(threshold=threshold)
		true_Y  = self.tst_Y.values

		if CALC_KNOWNS:
			##assume we know calculable knowns
			for i, (ind,row) in enumerate(self.tst_Y.iterrows()):
				true_name   = self.name_df['name'][ind]
				if true_name in self.calculable_knowns:
					pred_Y[i, :] = true_Y[i, :]

		if REMOVE_CALC:
			delete_row_inds = []
			##delete calculable knowns
			for i, (ind,row) in enumerate(self.tst_Y.iterrows()):
				true_name   = self.name_df['name'][ind]
				if true_name in self.calculable_knowns:
					delete_row_inds.append(i)

			pred_Y  = np.delete(pred_Y, delete_row_inds, 0)
			true_Y  = np.delete(true_Y, delete_row_inds, 0)

		ml_p	= eval.ml_precision(true_Y, pred_Y)
		ml_r	= eval.ml_recall(true_Y, pred_Y)
		ml_f1   = eval.ml_f1(ml_p, ml_r)

		#print("Micro Avgs :: Precision:{}, Recall:{} F1:{}".format(ml_p, ml_r, ml_f1))

		mac_ml_p	= eval.ml_precision(true_Y, pred_Y, MODE='MACRO')
		mac_ml_r	= eval.ml_recall(true_Y, pred_Y, MODE='MACRO')
		mac_ml_f1   = eval.ml_f1(mac_ml_p, mac_ml_r)
		
		m_ml_p  = mac_ml_p[np.isfinite(mac_ml_p)]
		m_ml_r  = mac_ml_r[np.isfinite(mac_ml_r)]
		m_ml_f1  = mac_ml_f1[np.isfinite(mac_ml_f1)]

		macro_avg_ml_p  = np.mean(m_ml_p)
		macro_avg_ml_r  = np.mean(m_ml_r)
		macro_avg_ml_f1 = np.mean(m_ml_f1)


		experiment_results = {
			'micro_p'   : ml_p,
			'micro_r'   : ml_r,
			'micro_f1'  : ml_f1,
			'macro_p'   : macro_avg_ml_p,
			'macro_r'   : macro_avg_ml_r,
			'macro_f1'  : macro_avg_ml_f1,
			'L'		 : len(self.L)		  
		}
		return experiment_results



	@staticmethod
	def opt_predict_labels(m, evalua, tst_Y, threshold):
		#print("threshold", threshold)
		ml_Y	= np.zeros(m.shape)
		for i, row in enumerate(m):
			above_thresh				= np.where(row > threshold)
			ranked					  = np.argsort(row)[::-1]
			ranked_ind_above_threshold  = ranked[:len(above_thresh[0])]

			for p in ranked_ind_above_threshold:
				ml_Y[i, p]  = 1

		pred_Y  = ml_Y 
		true_Y  = tst_Y.values
		ml_p	= evalua.ml_precision(true_Y, pred_Y)
		ml_r	= evalua.ml_recall(true_Y, pred_Y)
		ml_f1   = evalua.ml_f1(ml_p, ml_r)
		
		#m_ml_f1  = ml_f1[np.isfinite(ml_f1)]
		#macro_avg_ml_f1 = np.mean(m_ml_f1)
		#print("F1:{}".format(ml_f1))
		return threshold, ml_f1

	def opt_f1(self, split="val", processes=20):
		self.logger.info("Ranking labels against "+split.upper()+" set")
		m = self.read_XML_txt(self.directory+"/xml_score.mat")
		evalua = Evaluation()
		
		sY = self.val_Y
		if split == "tst":
			sY = self.tst_Y
		elif split == "trn":
			sY = self.trn_Y

		with Pool(processes=processes) as p:
			results = p.map(partial(PfastreXML.opt_predict_labels, m, evalua, sY), np.linspace(0.001, 0.5, num=500))
	
		X, Y = zip(*results)
		Y = np.nan_to_num(Y)
		X, Y = list(X), list(Y)
		
		
		maxY = Y[np.argmax(Y)]
		optT = X[np.argmax(Y)]
			
		self.logger.info(str(X))
		self.logger.info(str(Y))		
		self.logger.info("Optimal threshold: "+str(optT)+" -> "+str(maxY))
		return optT, maxY

	
	def evaluate(self, score_m_fname='xml_score.mat', CALC_KNOWNS=False):
		m = self.read_XML_txt(self.directory+"/"+score_m_fname)
		xml_eval = Evaluation()
		cgs, dcgs, ndcgs = [], [], []
		
		np_tst_Y	= self.tst_Y.to_numpy()
		
		p	   = 5
		
		delete_row_inds = []
		for i, row in enumerate(m):
			true_labels = np_tst_Y[i,:]
			our_predict = row

			func_index = self.tst_X.index[i]
			func_name   = self.name_df['name'][func_index]

			if CALC_KNOWNS:
				if func_name in self.calculable_knowns:
					our_predict = true_labels
					np_tst_Y[i, :] = true_labels
					
			
			cg	  = xml_eval.cumulative_gain(true_labels, our_predict, p=p)
			dcg	 = xml_eval.discounted_cumulative_gain(true_labels, our_predict, p=p)
			ndcg	= xml_eval.normalised_discounted_cumulative_gain(true_labels, our_predict, p=p)

			pred_top_n = np.argsort(our_predict)[::-1][:p]			
			corr_top_n = np.argsort(true_labels)[::-1][:p]
			pred_labels = tuple(map(lambda x, L=self.L: L[x], pred_top_n))
			corr_labels = tuple(map(lambda x, L=self.L: L[x], corr_top_n))

			self.logger.info("{:<40} :: N={}, TL={}, PL={}, Cumulative Gain: {:>2}, Discounted Cumulative Gain: {:>7}, Normalised Discounted Cumulative Gain: {:>7}".format(
				func_name, p, corr_labels, pred_labels, cg, dcg, ndcg
			))
			self.logger.info("\t{:<40}->{:<40}".format(func_name, '_'.join(pred_labels)))

			cgs.append(cg)
			dcgs.append(dcg)
			ndcgs.append(ndcg)

		acg	 = np.mean(cgs)
		adcg	= np.mean(dcgs)
		andcg   = np.mean(ndcgs)


		### geometric mean
		T = "N={} :: Mean CG: {:>7}, Mean DCG: {:>7}, Mean NDCG: {:>7}".format(p, acg, adcg, andcg)
		pr	   = xml_eval.precision_at_ks(np_tst_Y, m)
		T+= " Precision @n: "+str(pr)
		self.logger.info(T)	

	def score_model(self, true_Y, score_m_fname='xml_score.mat', CALC_KNOWNS=False):
		"""
			Provide a numercial score for the model + predictions
			Currently averages the NDCG
		"""
		m		   = self.read_XML_txt(self.directory+"/"+score_m_fname)
		xml_eval	= Evaluation()
		ndcgs	   = []
		p		   = 5
		#np_tst_Y	= self.tst_Y.to_numpy()
		np_true_Y   = true_Y.to_numpy()

		for i, row in enumerate(m):
			true_labels = np_true_Y[i,:]
			our_predict = row

			func_index  = true_Y.index[i]
			func_name   = self.name_df['name'][func_index]

			if CALC_KNOWNS:
				if func_name in self.calculable_knowns:
					our_predict	 = true_labels

			ndcg	= xml_eval.normalised_discounted_cumulative_gain(true_labels, our_predict, p=p)
			ndcgs.append(ndcg)

		return np.mean(ndcgs)


	@staticmethod
	def opt_score_func(x, self, sg_y):
		A, B = x
		#self.logger.info(str(A)+"_"+str(B))
		self.inv_propensities(A=A, B=B)
		y   = np.array(sorted(list(map(lambda a, self=self: 1.0/a, self.inv_props))))


		##chose log sepearted points along sigmoid
		g = np.linspace(1, len(y), 26)
		yy = [ y[int(x)-1] for x in g ]

		#distance between list y and list sg_y
		r = np.linalg.norm(sg_y - yy)
		return r

	def optimize_hyperparameters(self):
		"""
			uses scipy.optimize.minimize to minimise the distance between propensities of a semi log plot to the 
			sigmoid on a semi-log plot
		"""
		y = self.inv_props
		sigmoid_f   = lambda x, exp=math.exp: 1.0 / ( 1.0 + exp(-x) )

		#x is fixed for all iterations
		x	   = self.trn_Y.sum(axis=0).tolist()
		sg_x	= np.linspace(-5, 5, 26)
		#sg_x	= np.linspace(-6, 6, len(x))
		sg_y	= np.array(list(map(lambda a, f=sigmoid_f: f(a), sg_x)))

		#lin_x	= np.geomspace(min(x), max(x), len(x))
		#my = list(map(lambda a: 1.0/a, y))

		##optimize distance between sg_y and my
		x0  = np.array([0.4, 0.5])
		#con = { 'type': 'ineq', 'fun': lambda x: x[0] > 0 and x[1] > 0 }
		bnds = ((0, 100), (0, 100))
		res = scipy.optimize.minimize(PfastreXML.opt_score_func, x0, args=(self, sg_y), bounds=bnds)
		self.logger.info(str(res))
		return res.x[0], res.x[1]
		


	def precondition_dataset(self, X:pd.DataFrame, Y:pd.DataFrame, L:list):
		"""
			Apply preconditions to dataset.

				i)  Remove labels with only a single data point (impossible to learn and test)
				ii) Remove data points with no labels

			WARNING: Will modify label set
		"""
		##only select colums where we have atleast min_samples samples
		min_samples = 3
		c1		  = Y.sum(axis=0) > min_samples
		c2		  = np.where(c1 == True)[0]
		Y	  = Y[c2]
		#print("Selected", len(c2), "labels")

		l   = np.array(L)
		L  = l[c2].tolist()

		"""
			Now trim rows to have at least 1 label
		"""
		#axis=1 is rows, only select rows where we have at least 1 label
		Y  = Y.loc[Y.sum(axis=1) > 0]
		#select rows in X that correspond to the new Y
		X  = X.loc[Y.index]
		self.logger.info("We now have "+str(len(X))+" rows of data")
		return X, Y, L


	def load_model(self, model_dir):
		"""
			load model stored in self.directory
		"""
		self.directory	= model_dir
		for k in tqdm.tqdm([ "{}_{}".format(b, e) for b in ('trn', 'val', 'tst') for e in ('X', 'Y') ] + [ "name_df" ], desc="Loading model data"):
			value = pd.read_pickle("{}/{}.pickle".format(self.directory, k))
			setattr(self, k, value)

		self.L = list(map(lambda x: x.split(':')[1], utils.read_file_lines("{}/labels.txt".format(self.directory))))
		self.inv_props = list(map(lambda x: float(x), utils.read_file_lines("{}/inv_prop.txt".format(self.directory))))

	def predict(self, embeddings):
		"""
			Predict labels from embeddings and loaded model
		"""
		tmp_fname = 'tmp-embeddings-file.txt'
		PfastreXML.write_XML_txt(self.embeddings, self.directory+tmp_fname)

		pfast_dir="{}/deps/PfastreXML".format(self.config.desyl)
		data_dir = self.directory

		tst_cmd = pfast_dir + "/PfastreXML_predict {}/{} {}/xml_score.mat {}/xml_model".format(data_dir, tmp_fname, data_dir, data_dir)
		res = subprocess.call(shlex.split(tst_cmd), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
		if res < 0:
			raise RuntimeError("Error calling PfastreXML subprocess during prediction")

def main(config, args):
	if args.verbose:
		config.logger.setLevel(logging.DEBUG)   
	
	config.logger.info("pfastreXML parameters:")
	config.logger.info(str(vars(args)))

	dexterDirectory     = config.res + "/" + args.directory	
	dexterParametersP   = dexterDirectory+"/argsD"	
	dexterNLPDataP      = dexterDirectory+"/nlpData"
	pfastreXMLP         = config.res

	exp = Experiment(config)
	exp.load_settings(dexterDirectory)

	if args.verbose:
		config.logger.setLevel(logging.DEBUG)   

	with open(dexterParametersP, "rb") as f:			
		argsD = pickle.load(f)	

	config.logger.info("DEXTER parameters:")
	config.logger.info(str(argsD))			

	config.logger.info("Loading embeddings")		
	with open(dexterDirectory+"/embeddings", "rb") as f:
		embeddingsDict  = pickle.load(f)

	files_OLD_E  = {"safe":"SAFE2_OLD_E", "asm2vec":"ASM2VEC_OLD_E", "palmtree_gemini":"PALMTREE_GEMINI_OLD_E"}
	otherEmbeddings = {}
	
	for otherMethod in files_OLD_E:
		pathE = dexterDirectory+"/"+files_OLD_E[otherMethod]
		if os.path.isfile(pathE):
			with open(pathE, "rb") as f:
				otherEmbeddings[otherMethod]  = pickle.load(f)

	config.logger.info("TRAIN: "+str(len(exp.training_binary_ids)))
	config.logger.info("VAL: "+str(len(exp.validation_binary_ids)))
	config.logger.info("TEST: "+str(len(exp.testing_binary_ids)))

	
	if args.regenerate:
		config.logger.info("Making new random binaries split")
		
		binaries = list(exp.training_binary_ids) + list(exp.validation_binary_ids) + list(exp.testing_binary_ids)	
		random.shuffle(binaries)
		exp.training_binary_ids = binaries[:round(len(binaries)*0.9)]
		exp.validation_binary_ids = binaries[round(len(binaries)*0.9):round(len(binaries)*0.95)]
		exp.testing_binary_ids =  binaries[round(len(binaries)*0.95):]

		config.logger.info("TRAIN: "+str(len(exp.training_binary_ids)))
		config.logger.info("VAL: "+str(len(exp.validation_binary_ids)))
		config.logger.info("TEST: "+str(len(exp.testing_binary_ids)))


	config.logger.info("Making dataframe")		

	with open(dexterNLPDataP, "rb") as f:
		nlpData = pickle.load(f)

	pdFrame	= []
	for dataSplit in nlpData:
		for function in dataSplit:
			pathB, bId, fId, name, real_name, canonSet, canonName = function

			s = str((pathB, real_name))
			
			if args.intersection:
				isInAll = True				
				for otherMethod in otherEmbeddings:
					if not(s in otherEmbeddings[otherMethod]):
						isInAll = False
						break
				if isInAll == False:
					continue

			if args.method == "dexter":
				eF = embeddingsDict[fId]			
			else:
				if not(s in otherEmbeddings[args.method]):
					continue
				eF = otherEmbeddings[args.method][s]
			pdFrame	+= [[fId, real_name, name, canonName, bId, pathB, eF]]

	if args.function_split:

		config.logger.info("Making new random functions split")
	
		allIds = [f[0] for f in pdFrame]
		random.shuffle(allIds)
		exp.training_function_ids = allIds[:round(len(allIds)*0.9)]
		exp.validation_function_ids = allIds[round(len(allIds)*0.9):round(len(allIds)*0.95)]
		exp.testing_function_ids =  allIds[round(len(allIds)*0.95):]

		config.logger.info("TRAIN FUNCTIONS: "+str(len(exp.training_function_ids)))
		config.logger.info("VAL FUNCTIONS: "+str(len(exp.validation_function_ids)))
		config.logger.info("TEST FUNCTIONS: "+str(len(exp.testing_function_ids)))
		
	config.logger.info("Making DataFrame")
	
	df = pd.DataFrame(pdFrame, columns=['id', 'realName', 'name', 'canonName', 'b_id', 'binaryPath', 'embedding']).set_index('id')
	names		    = df['name'].values
	embeddings      = df['embedding'].values
	realNames       = df['realName'].values
	canonNames		= df['canonName'].values
	binariesPath   = df['binaryPath'].values

	config.logger.info("FRAME: "+str(len(pdFrame)))

	xml = PfastreXML(config, exp)	
	xml.fromData(names, embeddings, realNames, canonNames, binariesPath,  df, args.labelspace_dims, args.function_split)
	
	config.logger.info("Optimizing A and B from PfastreXML")
	A, B =  xml.optimize_hyperparameters()
	xml.update_propensities(A, B)

	config.logger.info("Training PfastreXML")
	PfastreXML.train_pfastrexml(xml.directory, 'trn_X.txt', 'trn_Y.txt', trees=args.trees, T=config.analysis.THREAD_POOL_THREADS, a=args.a, g=args.g, pfast_dir=pfastreXMLP)

	config.logger.info("Optimizing ML threshold")
	PfastreXML.pred_pfastrexml(xml.directory, 'val_X.txt', pfast_dir=pfastreXMLP)
	threshold, optF1 =  xml.opt_f1(split="val", processes=config.analysis.THREAD_POOL_THREADS)
	if np.isnan(optF1):
		config.logger.info("No data on validation split for this embedding, using training split to select threshold")
		PfastreXML.pred_pfastrexml(xml.directory, 'trn_X.txt', pfast_dir=pfastreXMLP)
		threshold, _ =  xml.opt_f1(split="trn", processes=config.analysis.THREAD_POOL_THREADS)
	
	config.logger.info("Computing results")
	PfastreXML.pred_pfastrexml(xml.directory, 'tst_X.txt', pfast_dir=pfastreXMLP)
	xml.evaluate(CALC_KNOWNS=True)
	config.logger.info("F1 Tst: "+str(xml.ml_scores(threshold=threshold, CALC_KNOWNS=True, REMOVE_CALC=False)))

def evaluate(config, args):
	dexterDirectory     = config.res + "/" + args.directory	
	dexterNLPDataP      = dexterDirectory+"/nlpData"
	pfastreXMLP         = config.res
	pfastreDir          = dexterDirectory + "/" + args.pfastre_model

	config.logger.info("Loading embeddings")		
	with open(dexterDirectory+"/embeddings", "rb") as f:
		embeddingsDict  = pickle.load(f)

	config.logger.info("Recovering label space")
	L	   = []
	with open (pfastreDir + "/labels.txt", "r") as f:
		for l in f.readlines():
			L += [l.split(":")[1].strip()]		

	config.logger.info("Making dataframe")
	with open(dexterNLPDataP, "rb") as f:
		nlpData = pickle.load(f)
	
	canonical_sets = []
	pdFrame	= []
	for dataSplit in nlpData:
		for function in dataSplit:
			pathB, bId, fId, name, real_name, canonSet, canonName = function
			eF = embeddingsDict[fId]
			pdFrame	+= [[fId, name, real_name, canonName, bId, pathB, eF]]
			canonical_sets += [canonSet]

	df = pd.DataFrame(pdFrame, columns=['id', 'name', 'realName', 'canonName', 'b_id', 'binaryPath', 'embedding']).set_index('id')
	names			= df['name'].values
	embeddings		= df['embedding'].values
	realNames		= df['realName'].values
	canonNames		= df['canonName'].values
	binariesPath  	= df['binaryPath'].values

	config.logger.info("Parsing embeddings and labels...")		
	l_index = df.index
	embeddings_df   = pd.DataFrame(embeddings, columns=['embedding'], index=l_index)
	deduction_X = embeddings_df

	name_df		 	= pd.DataFrame(names, columns=['name'], index=l_index)		
	real_name_df 	= pd.DataFrame(realNames, columns=['realName'], index=l_index)		
	canon_name_df	= pd.DataFrame(canonNames, columns=['canonName'], index=l_index)		
	binary_path_df	= pd.DataFrame(binariesPath, columns=['binaryPath'], index=l_index)

	chunks = utils.n_chunks(canonical_sets, 256)
	results = Parallel(n_jobs=config.analysis.THREAD_POOL_THREADS, verbose=1, backend="multiprocessing")(map(delayed(PfastreXML.name_vector), chunks, itertools.repeat(L)))
	labels = functools.reduce(lambda x, y: x + y, results, [])
	labels_mat = np.vstack(labels)
	deduction_Y = pd.DataFrame(data=labels_mat, index=l_index)

	config.logger.info("Write XML data for pfastreXML")

	fileX = pfastreDir + "/deduction_X.txt"
	fileY = pfastreDir + "/deduction_Y.txt"
	
	ind, row = next(deduction_X.iterrows())
	embed_len = row['embedding'].shape[-1]
	PfastreXML.write_XML_txt(deduction_X, fileX, shape=(len(deduction_X), embed_len))
	PfastreXML.write_XML_txt(deduction_Y, fileY)
	
	config.logger.info("Predict labels")
	PfastreXML.pred_pfastrexml(pfastreDir, "deduction_X.txt", pfast_dir=pfastreXMLP)
	
	config.logger.info("Evaluate results")
	xml = PfastreXML(config, None, evaluation=True)
	xml.directory = pfastreDir
	xml.L = L
	xml.tst_X = deduction_X
	xml.tst_Y = deduction_Y
	xml.name_df = name_df
	xml.real_name_df = real_name_df
	xml.canon_name_df = canon_name_df
	xml.binary_path_df = binary_path_df

	xml.evaluate(CALC_KNOWNS=True)
	config.logger.info(str(xml.ml_scores(threshold=args.threshold, CALC_KNOWNS=True, REMOVE_CALC=False)))

if __name__ == '__main__':
	
	parser = ArgumentParser()
	parser.add_argument('-v', '--verbose', action='store_true', help='Enable DEBUG logging')
	parser.add_argument('-d', '--directory', required=True, help="DEXTER model directory")
	parser.add_argument('-method', '--method', default="dexter")
	parser.add_argument('-l', '--labelspace-dims', default=1024, type=int, help='Size of labelspace to use')
	parser.add_argument('-trees', '--trees', default=256, type=int, help='Number of trees of pfastreXML')	
	parser.add_argument('-a', '--a', default=1, type=float, help='Hyperparameter a of pfastreXML')
	parser.add_argument('-g', '--g', default=30, type=int, help='Hyperparameter g of pfastreXML')
	parser.add_argument('-r', '--regenerate', action='store_true', help='Renegerate train/val/test split')
	parser.add_argument('-f', '--function-split', action='store_true', help='Renegerate train/val/test split by functions')
	parser.add_argument('-i', '--intersection', action='store_true', help='Consider only functions accepted by all embeddings')
	parser.add_argument('-evaluate', '--evaluate', action='store_true', help='Evaluate a previously trained PfastreXML model')
	parser.add_argument('-pfastreModel', '--pfastre-model', help="Pfastre directory inside DEXTER model directory")
	parser.add_argument('-threshold', '--threshold', default=0.215, type=float, help='Labelling threshold for the evaluation of a trained model')
	
	args = parser.parse_args()
	
	if args.evaluate:
		with capture_output() as captured:
			config   = Config()
			logsPath  = f"{config.res}/{args.directory}/{args.pfastre_model}/deduction.log"
			evaluate(config, args)
			with open(logsPath, 'w') as f:
				f.write(captured.stdout)
				f.write(captured.stderr)
		exit()
	
	with capture_output() as captured:
		config   = Config()
		logsPath  = f"{config.res}/{args.directory}/{args.method}-{args.labelspace_dims}-R-{args.regenerate}-F-{args.function_split}-I-{args.intersection}.log"
		main(config, args)
		with open(logsPath, 'w') as f:
			f.write(captured.stdout)
			f.write(captured.stderr)
