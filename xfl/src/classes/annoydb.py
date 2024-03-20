
"""

Copyright 2017-2024 by James Patrick-Evans, Moritz Dannehl, and Johannes Kinder.

This file is part of XFL.

XFL is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

XFL is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with XFL. If not, see <https://www.gnu.org/licenses/>. 

"""

import context
import math
from classes.config import Config
from classes.database import RedisDB
from classes.experiment import Experiment
from classes.pmfs import PMF
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
import classes.utils
import IPython
import functools
import numpy as np
import pandas as pd
from annoy import AnnoyIndex
from tqdm import tqdm

class AnnoyDB():
    def __init__(self, config):
        classes.utils._desyl_init_class_(self, config)
        self.t      = None
        self.scaler = None
        self.f      = None
        self.metric = 'angular'
        self.rdb = RedisDB(config)

    def build_db(self, embeddings, names, n_trees=128, metric='angular'):
        assert(isinstance(names, list))
        print("Stacking embeddings")
        em = np.vstack(embeddings)
        print("Scaling data")
        self.scaler = StandardScaler()
        self.scaler.fit(em)

        new_em = self.scaler.transform(em)

        r, c = new_em.shape
        self.f = c
        self.metric = metric
        self.t = AnnoyIndex(c, metric)
        for i in tqdm(range(r), desc='Adding embeddings'):
            name = names[i]
            embedding = new_em[i, :]
            self.t.add_item(i, embedding)
            self.rdb.set_py_obj("{}:annoydb:keymap:{}".format(config.experiment.name, i), name)

        print("Building index...")
        #self.t.build(n_trees, n_jobs=32)
        self.t.build(n_trees)

    def save(self, fname='/tmp/db.ann'):
        self.t.save(fname)
        classes.utils.pickle_save_py_obj(self.config, self.f, 'f')
        classes.utils.pickle_save_py_obj(self.config, self.metric, 'metric')
        classes.utils.pickle_save_py_obj(self.config, self.scaler, 'scaler')

    def load(self, fname='/tmp/db.ann'):
        self.scaler = classes.utils.pickle_load_py_obj(self.config, 'scaler')
        self.f      = classes.utils.pickle_load_py_obj(self.config, 'f')
        self.metric = classes.utils.pickle_load_py_obj(self.config, 'metric')
        self.t = AnnoyIndex(self.f, self.metric)
        self.t.load(fname)

    def top_n_accuracy(self, exp, x, y, n=5):
        tp, tn, fp, fn = 0, 0, 0, 0
        rows, cols = x.shape
        for i in tqdm(range(rows)):
            pmf = self.query_vector(x[i,:], exp).todense()

            correct_ind = exp.to_index('name_vector', y[i])
            top_n = np.asarray(pmf).ravel().argsort()[-n:][::-1]
            #IPython.embed()
            assert(len(top_n) == n)
            if correct_ind in top_n:
                tp += 1
            else:
                fp += 1

        accuracy = 0.0
        if (tp+tn+fp+fn) > 0:
            accuracy = (tp+tn) / (tp+tn+fp+fn)

        return accuracy, tp, fp

    def query_vector(self, fingerprint, exp, n=8):
        scaled_fp = self.scaler.transform(fingerprint.reshape(1, self.f))
        nodes, distances = self.t.get_nns_by_vector(scaled_fp.ravel(), n, include_distances=True)
        names = list(map(lambda i, rdb=self.rdb: rdb.get_py_obj("{}:annoydb:keymap:{}".format(self.config.experiment.name, i)), nodes))
        pmfs = list(map(lambda x, names=names, exp=exp: exp.to_sparse_vec('name_vector', [x], 'lil'), names))
        ###sqrt(2) is the maximum (angular) distance, sqrt(2(1-cos(u,v)))
        inv_distance_weighted = list(map(lambda x: 1.0-(x/math.sqrt(2.0)), distances))
        weighted_pmfs = list(map(lambda x, y: x*y, inv_distance_weighted, pmfs))
        w = functools.reduce(lambda x, y: x+y, weighted_pmfs)
        return PMF.normalise_numpy_density(w)

def generate_dataset():
    ##desyl symbol embeddings need to be created by running 
    ## ./src/scripts/generate_symbol_embeddings.py
    df = pd.read_pickle("/tmp/symbol_embeddings_df")
    print("Loaded dataframe")

    binaries = df['binary'].unique()
    train_binaries, test_binaries = train_test_split(binaries, test_size=0.1)
    #train_binaries = list(filter(lambda x: '/og/' in x and '/gcc/' in x, binaries))
    #test_binaries = list(filter(lambda x: '/o2/' in x and '/gcc/' in x, binaries))

    print('filtered names...')
    train_df    = df[df['binary'].isin(train_binaries)]
    test_df     = df[df['binary'].isin(test_binaries)]

    print("Stacking vectors")
    ##regression vs classification
    #y_train = scipy.sparse.vstack(train_df['name'].apply(lambda x: E.to_sparse_lil_vec('name_vector', [x])).values)
    #y_test  = scipy.sparse.vstack(test_df['name'].apply(lambda x: E.to_sparse_lil_vec('name_vector', [x])).values)
    #y_train = np.vstack(train_df['name'].apply(lambda x: E.to_index('name_vector', x)).values)
    #y_test  = np.vstack(test_df['name'].apply(lambda x: E.to_index('name_vector', x)).values)
    y_train = np.vstack(train_df['name'])
    y_test  = np.vstack(test_df['name'])

    x_train = np.vstack(train_df['embedding'].values)
    x_test  = np.vstack(test_df['embedding'].values)

    for model in [ "x_train", "y_train", "x_test", "y_test", "train_df", "test_df", "train_binaries", "test_binaries" ]:
        print("Saving", model)
        classes.utils.pickle_save_py_obj(config, locals()[model], model)
    return x_train, y_train, x_test, y_test

def load_dataset():
    """
    for model in [ "x_train", "y_train", "x_test", "y_test" ]:
        print("Loading", model)
        locals()[model] = classes.utils.pickle_load_py_obj(config, model)
    """

    return classes.utils.pickle_load_py_obj(config, "x_train"), classes.utils.pickle_load_py_obj(config, "y_train"), classes.utils.pickle_load_py_obj(config, "x_test"), classes.utils.pickle_load_py_obj(config, "y_test")



if __name__ == '__main__':
    config = Config()
    exp = Experiment(config)
    exp.load_settings()
    #names, embeddings = classes.utils.pickle_load_py_obj(config, 'symbol.desyl.embeddings')
    #x_train, y_train, x_test, y_test = generate_dataset()
    x_train, y_train, x_test, y_test = load_dataset()

    y_train = y_train.ravel().tolist()
    y_test = y_test.ravel().tolist()

    adb = AnnoyDB(config)
    IPython.embed()
    #adb.build_db(names, embeddings)
    #print("AnnoyDB built!")

