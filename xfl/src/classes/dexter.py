
"""

Copyright 2017-2024 by James Patrick-Evans, Moritz Dannehl, and Johannes Kinder.

This file is part of XFL.

XFL is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

XFL is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with XFL. If not, see <https://www.gnu.org/licenses/>. 

"""

import context
import os
#disable GPU
os.environ["CUDA_VISIBLE_DEVICES"]="-1"
from classes.config import Config
from classes.NLP import NLP
from tqdm import tqdm
import classes.utils
import torch as th
import torch.nn as nn
import networkx as nx
import numpy as np
import scipy as sp
import gc
import pandas as pd
import copy
from collections import deque
from multiprocessing import Pool
from threading import Thread
from time import sleep
import tensorflow as tf
import tensorflow_addons as tfa
from sklearn import preprocessing
import sys
import IPython
from IPython import embed
from sys import exit
from math import ceil, inf
from random import sample, uniform
from functools import reduce
from multiprocessing import Queue, Process
import multiprocessing
from itertools import combinations, repeat
from classes.database import PostgresDB
from joblib import Parallel, delayed

_SPARSE_TENSORS_    = False

processes = []

def normalize_dataframe(df, column='embedding'):
    #normalize each column in the embedding
    #compute single matrix, then split back into rows
    batch_size  = 1024
    niters      = ceil(len(df) / batch_size)
    scaler      = preprocessing.StandardScaler()
    for ind in tqdm(range(niters), total=niters, desc='Calculating normalization'):
        embedding_mat   = np.vstack(df[column][ind*batch_size:(ind+1)*batch_size].values)
        scaler          = scaler.partial_fit(embedding_mat)

    print("Applying normalization transformation")
    df[column] = df[column].apply(lambda x, f=scaler: f.transform(x))
    return df, scaler

def load_dataset_generator(nlp, ratio=False, fname='/tmp/symbol_embeddings_df'):
    chunk = 0
    while True:
        df = pd.read_pickle(fname)

        ##average binary embeddings
        be_df = pd.DataFrame(columns=["binary", "embedding"])
        bins_df = df['binary'].unique()
        for b in tqdm(bins_df, desc='unique binaries'):
            bin_symbols     = df.loc[ df['binary'] == b ] 
            embeddings      = bin_symbols['embedding'].to_numpy()
            b_embedding     = np.average(embeddings)
            be_df = be_df.append({'binary': b, 'embedding': b_embedding}, ignore_index=True)

        symbols_df = df['name'].unique()
        symbols2labels = {}
        for name in tqdm(symbols_df, desc='symbols2labels'):
            labels = nlp.canonical_set(name)
            symbols2labels[name] = labels

        chunk += 1
        yield df, be_df, symbols2labels



def load_dataset(nlp, ratio=False, fname='/tmp/symbol_embeddings_df'):
    #nlp.logger.info("Reading Pandas DataFrame from CSV ({})".format(fname))
    #df  = pd.read_pickle(fname)
    nlp.logger.info("Building DataFrame from SQL")
    pdb = PostgresDB(nlp.config)
    pdb.connect()

    g = pdb.dexter_feature_vectors()
    #pandas dataframe indexed by function id in the database
    df = pd.DataFrame(g, columns=('id', 'name', 'real_name', 'callers', 'callees', 'binary', 'bin_name', 'cat_embedding', 'quant_embedding')).set_index('id')


    ##filter out calculatable knowns
    df  = df.loc[~df['name'].isin(classes.crf.CRF.calculable_knowns)]

    if ratio:
        ##subsampling dataset
        nlp.logger.critical("Subsampling dataset with ratio {}! This should be for DEBUG only".format(ratio))
        df = df.sample(frac=ratio)

    #df = normalize_dataframe(df)

    ##average binary embeddings
    be_df   = pd.DataFrame(columns=["binary", "cat_embedding", "quant_embedding"])

    bins_df = df['binary'].unique()
    for b in tqdm(bins_df, desc='Generating binary context feature vectors'):
        bin_symbols     = df.loc[ df['binary'] == b ] 
        c_embeddings    = bin_symbols['cat_embedding'].to_numpy()
        q_embeddings    = bin_symbols['quant_embedding'].to_numpy()

        ##if sparse matraces
        if classes.utils.is_scipy_sparse(c_embeddings[0]):
            #z = list(map(lambda x: np.asarray(x.todense()).ravel(), c_embeddings.tolist()))
            z = map(lambda x: x.todense(), c_embeddings.tolist())
            bc_embedding    = np.average(list(z), axis=0)
            #convert back to sparse matrix
            bc_embedding    = sp.sparse.coo_matrix(bc_embedding)
        else:
            bc_embedding     = np.average(c_embeddings)

        bq_embedding     = np.average(q_embeddings)

        be_df = be_df.append({'binary': b, 'cat_embedding': bc_embedding, 'quant_embedding': bq_embedding}, ignore_index=True)

    ##add caller callees context vectors
    #df['c_ctx_feat']    = None
    df['ctx_feat']    = None
    for ind, row in tqdm(df.iterrows(), desc='Generating symbol context feature vectors', total=len(df)):
        fn      = row['name']
        bn      = row['binary']
        tc      = sp.sparse.coo_matrix(row['cat_embedding'].shape)
        b_df    =  df[df['binary'] == row['binary']]

        """
        #tc_callee, tc_caller = tc*0, tc*0
        #tq_callee, tq_caller = tq*0, tq*0
        callers, callees    = pdb.function_callers_callees(bn, fn)
        ##callers and calless features should be stacked
        for c in callers + callees:
            #find row in df
            c_df = b_df[b_df['name'] == c]
            for c_ind, c_row in c_df.iterrows():
                tc_caller   += c_row['cat_embedding']
                tq_caller   += c_row['quant_embedding']

        for c in callees:
            #find row in df
            c_df = b_df[b_df['name'] == c]
            for c_ind, c_row in c_df.iterrows():
                tc_callee   += c_row['cat_embedding']
                tq_callee   += c_row['quant_embedding']
        
        c_ctx_feat  = tc_caller + tc_callee
        q_ctx_feat  = tq_caller + tq_callee
        if classes.utils.is_scipy_sparse(c_ctx_feat):
            c_ctx_feat  = c_ctx_feat.todense()

        df['ctx_feat'][ind]   = np.hstack([c_ctx_feat, q_ctx_feat]) 
        """

        callers, callees    = pdb.function_callers_callees(bn, fn)
        ##callers and calless features should be stacked
        for c in callers + callees:
            #find row in df
            c_df = b_df[b_df['name'] == c]
            for c_ind, c_row in c_df.iterrows():
                tc   += c_row['cat_embedding']

        df['ctx_feat'][ind] = tc

    nlp.logger.info("Running garbage collector")
    gc.collect()

    return df, be_df 


def cleanup(processes):
    for p in processes:
        p.kill()


def _mp_init_processes(Q:Queue, f, nprocs:int):
    """
        Support function for mp_buffer_generator
        Creating and starting a large number of processes
        takes a long time. Async the async.
        The generator object now returns instantly

        Q:multiprocessing.Queue queue
        nprocs: Number of processes to start
    """
    #processes = [Process(target=f, args=(Q,)) for _ in range(nprocs)]
    processes = [Thread(target=f, args=(Q,)) for _ in range(nprocs)]
    for p in processes:
        p.start()

    """
    #cleanup processes on exit
    import atexit
    atexit.register(cleanup, processes)

    print("checking for process exits")
    while True:
        for i, p in enumerate(list(processes)):
            ##check for finished processes 10 per second
            p.join(timeout=0.1)
            if p.exitcode == None:
                ##not terminated yet
                continue
            processes[i] = Process(target=f, args=(Q,))
            processes[i].start()
        gc.collect()
    """

def mp_buffer_generator(f, nprocs:int=multiprocessing.cpu_count(), maxbuf=1024):
    """
        Buffer a generator function uses multiprocesses.
        Default number of processes is machine CPU count
        f: function
        nprocs: number of processes to use
    """
    ##nelems size results buffer
    Q = Queue(maxsize=maxbuf)
    t = Thread(target=_mp_init_processes, args=(Q, f, nprocs))
    #t = Thread(target=f, args=(Q,))
    t.start()
    #_mp_init_processes(Q,f, nprocs)
    i = 0

    while True:
        try:
            a = Q.get(timeout=30)
            #print("Got item")
            yield a
            del a

            ##purge memory from unused items in generator
            i += 1
            if i > maxbuf:
                i = 0
                gc.collect()

        except Exception as e:
            print("Caught exception e in mp_buffer_generator.")
            raise e


def emit_symbol_pairs(df, binary_embeddings, size=48, queue=None):
    """
        optimized version
    """
    while True:
        #ss_df   = df.sample(n=size, random_state=int.from_bytes(os.urandom(4), sys.byteorder))
        ss_df   = df.sample(n=size) 
        #class balance whole function names
        #ss_df       = df.groupby("name").sample(random_state=1)
        for ind, row in ss_df.iterrows():
            ##symbol feature vector
            ac_em = row['cat_embedding']

            ##add callers and callee contexts
            c_ctx_vector = row['ctx_feat']

            bc_em   = binary_embeddings.loc[binary_embeddings['binary'] == row['binary'] ]['cat_embedding'].values[0]

            if not _SPARSE_TENSORS_:
                if classes.utils.is_scipy_sparse(ac_em):
                    ac_em   = np.array(ac_em.todense())
                if classes.utils.is_scipy_sparse(c_ctx_vector):
                    c_ctx_vector   = np.array(c_ctx_vector.todense())
                if classes.utils.is_scipy_sparse(bc_em):
                    bc_em   = np.array(bc_em.todense())

            aq_em = row['quant_embedding']
            q_ctx_vector = row['q_ctx_feat']

            ##binary feature vector
            bq_em   = binary_embeddings.loc[binary_embeddings['binary'] == row['binary'] ]['quant_embedding'].values[0]

                ## symbol feature vector, context feature vector, binary feature vector
            #a_em    = np.hstack([ac_em, aq_em, c_ctx_vector, q_ctx_vector, bc_em, bq_em])
                a_em    = np.hstack([ac_em, c_ctx_vector, bc_em ])
            else:
                a_em    = sp.sparse.hstack([ac_em, c_ctx_vector, bc_em ]) 


            at      = tf.convert_to_tensor(a_em, dtype=tf.float32)
            if not _SPARSE_TENSORS_:
                at      = tf.convert_to_tensor(a_em, dtype=tf.float32)
            else:
                at      = classes.utils.scipy_sparse_to_sparse_tensor_spec(a_em)


            ##WARING: a function with syntax yield anywhere wil be treated as a generator
            #if not queue:
            #    yield (a_em, a_em)
            #else:

            ##will block if queue is full

            queue.put( (at, at) )
            #if not _SPARSE_TENSORS_:
            #    queue.put( (at, at) )
            #else:
            #    queue.put(at)

            del a_em
            del at

        del ss_df
        gc.collect()


class Encoder(tf.keras.layers.Layer):
    """
            Start of tensorflow autoencoder implementation
    """
    def __init__(self, intermediate_dim, sub_intermediate_dim, training=True):
        super(Encoder, self).__init__()
        self.symb_hidden_layer = tf.keras.layers.Dense(
            units=sub_intermediate_dim,
            activation=tf.nn.leaky_relu,
            kernel_initializer='random_normal',
            kernel_regularizer=tf.keras.regularizers.l1_l2(l1=0.01, l2=0.01))

        self.context_hidden_layer = tf.keras.layers.Dense(
            units=sub_intermediate_dim,
            activation=tf.nn.leaky_relu,
            kernel_initializer='random_normal',
            kernel_regularizer=tf.keras.regularizers.l1_l2(l1=0.01, l2=0.01))

        self.binary_hidden_layer = tf.keras.layers.Dense(
            units=sub_intermediate_dim,
            activation=tf.nn.leaky_relu,
            kernel_initializer='random_normal',
            kernel_regularizer=tf.keras.regularizers.l1_l2(l1=0.01, l2=0.01))

        self.training=training

        self.symb_norm_layer    = tf.keras.layers.BatchNormalization()
        self.context_norm_layer = tf.keras.layers.BatchNormalization()
        self.binary_norm_layer  = tf.keras.layers.BatchNormalization()

        self.symb_embed_drop        = tf.keras.layers.Dropout(0.25)
        self.context_embed_drop     = tf.keras.layers.Dropout(0.25)
        self.binary_embed_drop      = tf.keras.layers.Dropout(0.25)

        self.output_layer = tf.keras.layers.Dense(
                units=intermediate_dim,
                activation=tf.nn.leaky_relu,
                kernel_initializer='random_normal',
                kernel_regularizer=tf.keras.regularizers.l1_l2(l1=0.01, l2=0.01))


    def call(self, input_features):
        ndivis          = 3
        n_features      = input_features.shape[2]
        if n_features % ndivis != 0:
            raise RuntimeError("Error, we are expecting n input features to be divisible by {}".format(ndivis))

        symb_feat_len = int(n_features / ndivis)

        #1n
        symb_input_features     = input_features[:,:,:symb_feat_len]
        #2-3n
        context_input_features  = input_features[:,:,symb_feat_len:2*symb_feat_len]
        #4n
        binary_input_features   = input_features[:,:,-symb_feat_len:]

        """
            INPUT -> DENSE SMALL -> BATCH NORM -> DROP -> DENSE OUT
        """


        #activation = self.symb_hidden_layer(input_features)
        #return self.output_layer(activation)
        ## input is sparse and wildly different, apply batch norm after activation
        s_activation    = self.symb_hidden_layer(symb_input_features)
        s_norm          = self.symb_norm_layer(s_activation, training=self.training)
        s_o             = self.symb_embed_drop(s_norm)

        c_activation    = self.context_hidden_layer(context_input_features)
        c_norm          = self.context_norm_layer(c_activation, training=self.training)
        c_o             = self.context_embed_drop(c_norm)

        b_activation    = self.binary_hidden_layer(binary_input_features)
        b_norm          = self.binary_norm_layer(b_activation, training=self.training)
        b_o             = self.binary_embed_drop(b_norm)

        return self.output_layer(tf.keras.layers.concatenate([s_o, c_o, b_o]))

class Decoder(tf.keras.layers.Layer):
    def __init__(self, intermediate_dim, sub_intermediate_dim, original_dim):
        super(Decoder, self).__init__()
        self.symb_hidden_layer = tf.keras.layers.Dense(
            units=sub_intermediate_dim,
            activation=tf.nn.leaky_relu,
            kernel_initializer='random_normal',
            kernel_regularizer=tf.keras.regularizers.l1_l2(l1=0.01, l2=0.01))

        self.context_hidden_layer = tf.keras.layers.Dense(
            units=sub_intermediate_dim,
            activation=tf.nn.leaky_relu,
            kernel_initializer='random_normal',
            kernel_regularizer=tf.keras.regularizers.l1_l2(l1=0.01, l2=0.01))

        self.binary_hidden_layer = tf.keras.layers.Dense(
            units=sub_intermediate_dim,
            activation=tf.nn.leaky_relu,
            kernel_initializer='random_normal',
            kernel_regularizer=tf.keras.regularizers.l1_l2(l1=0.01, l2=0.01))

        ##divisable by 4
        assert(original_dim % 3 == 0)
        self.s_output_layer = tf.keras.layers.Dense(
            units=original_dim/3,
            activation=tf.nn.leaky_relu)

        self.c_output_layer = tf.keras.layers.Dense(
            units=original_dim/3,
            activation=tf.nn.leaky_relu)

        self.b_output_layer = tf.keras.layers.Dense(
            units=original_dim/3,
            activation=tf.nn.leaky_relu)

        self.norm_layer        = tf.keras.layers.BatchNormalization()

        self.symb_embed_drop        = tf.keras.layers.Dropout(0.25)
        self.context_embed_drop     = tf.keras.layers.Dropout(0.25)
        self.binary_embed_drop      = tf.keras.layers.Dropout(0.25)

    def call(self, code):
        #print("Decoder::call: {}".format(code.shape))
        #activation = self.hidden_layer(code)
        #return self.output_layer(activation)

        c_norm  = self.norm_layer(code)
        
        s_h         = self.symb_hidden_layer(c_norm)
        s_d         = self.symb_embed_drop(s_h)
        s_o         = self.s_output_layer(s_d)


        c_h         = self.context_hidden_layer(c_norm)
        c_d         = self.context_embed_drop(c_h)
        c_o         = self.c_output_layer(c_d)

        b_h         = self.binary_hidden_layer(c_norm)
        b_d         = self.binary_embed_drop(b_h)
        b_o         = self.b_output_layer(b_d)

        return tf.keras.layers.concatenate([s_o, c_o, b_o])

class Autoencoder(tf.keras.Model):
    def __init__(self, intermediate_dim, sub_intermediate_dim, out_dim):
        #print("Autoencoder::init")
        super(Autoencoder, self).__init__()
        self.encoder = Encoder(intermediate_dim=intermediate_dim, sub_intermediate_dim=sub_intermediate_dim)
        self.decoder = Decoder(intermediate_dim=intermediate_dim, sub_intermediate_dim=sub_intermediate_dim, original_dim=out_dim)

    def call(self, input_features):
        #print("Autoencoder::call: {}".format(input_features.shape))
        assert(len(input_features.shape) == 3)
        code = self.encoder(input_features)
        reconstructed = self.decoder(code)
        return reconstructed

def loss(model, original):
    X, Y = original
    reconstruction_error = tf.reduce_mean(tf.square(tf.subtract(model(X), Y)))
    return reconstruction_error

def custom_loss(model, original, loss):
    X, Y = original
    return tf.reduce_mean(tf.square(loss(Y, model(X))))
    #return tf.reduce_mean(tf.square(tfa.losses.TripletHardLoss(Y, model(X))))
    #return tf.reduce_mean(tf.square(tfa.losses.contrastive_loss(Y, model(X))))
    #return tfa.losses.npairs_multilabel_loss(model(X), Y)

def kl_loss(model, original, loss_fnc=tf.keras.losses.KLDivergence()):
    X, Y = original
    pred_y = model(X)
    return loss_fnc(Y, pred_y).numpy()

def nce_loss(model, original):
    X, Y = original
    pred_y = model(X)
    #IPython.embed()
    return tf.nn.nce_loss(inputs=X, labels=Y, weights=pred_y, num_sampled=30).numpy()

def train(loss, model, opt, original):
    with tf.GradientTape() as tape:
        x, y = original
        gradients = tape.gradient(loss(y, model(x)), model.trainable_variables)
    gradient_variables = zip(gradients, model.trainable_variables)
    opt.apply_gradients(gradient_variables)

def extract_embeddings(df, be_df, model, ids):
    p = pd.DataFrame(columns=['dexter_embedding'])
    #for ind, row in tqdm(df.iterrows(), desc='Applying embeddings', total=len(df)):
    for ind in tqdm(ids):
        row = df.loc[ind]

        ##symbol feature vector
        aa_em = row['cat_embedding']
        aq_em = row['quant_embedding']
        if classes.utils.is_scipy_sparse(aa_em):
            aa_em   = np.array(aa_em.todense())

        ##binary feature vector
        ab_em   = be_df.loc[be_df['binary'] == row['binary'] ]['cat_embedding'].values[0]
        if classes.utils.is_scipy_sparse(ab_em):
            ab_em   = ab_em.todense()

        ##local context feature vector (attention)
        ctx_vectors = []
        for n in row['callers'] + row['callees']:
            #find entry for function name
            for e_ind, entry in df[(df['name'] == n) & (df['binary'] == row['binary'])].iterrows():
                ctx_vectors.append(entry['cat_embedding'])

        if len(ctx_vectors) == 0:
            ctx_vector = row['cat_embedding'] * 0
            if classes.utils.is_scipy_sparse(row['cat_embedding']):
                ctx_vector.eliminate_zeros()
                ctx_vector = np.array(ctx_vector.todense())
        else:
            ##if sparse matraces
            if classes.utils.is_scipy_sparse(row['cat_embedding']):
                z = map(lambda x: x.todense(), ctx_vectors)
                ctx_vector = np.average(list(z), axis=0)
            else:
                ctx_vector     = np.array(np.average(ctx_vectors))

        ## symbol feature vector, context feature vector, binary feature vector
        a_em    = np.hstack([aa_em, ctx_vector, ab_em])

        at      = tf.convert_to_tensor(a_em, dtype=tf.float32)
        shp     = list(at.shape)
        ##prepend as a single element batch
        shp.insert(0, 1)
        atb     = tf.reshape(at, shp)

        #fetch embedding
        embedding = model.encoder(atb)
        #embedding is a tf tensor of shape (1, 1, N)
        #N is the size of our embeddings
        intermediate_dim = max(embedding.shape)
        em_reshaped = tf.reshape(embedding, (intermediate_dim,)).numpy()

        """
            Build embedding and add quant vectors
        """
        ##local context feature vector (attention)
        ctx_vectors = []
        for n in row['callers'] + row['callees']:
            #find entry for function name
            for e_ind, entry in df[(df['name'] == n) & (df['binary'] == row['binary'])].iterrows():
                ctx_vectors.append(entry['quant_embedding'])

        if len(ctx_vectors) == 0:
            ctx_vector = (row['quant_embedding'] * 0).ravel()
        else:
            ##if sparse matraces
            ctx_vector     = np.average(ctx_vectors, axis=0).ravel()

        ##local context feature vector (attention)
        bin_vectors = []
        #find entry for function name
        for e_ind, entry in df[(df['binary'] == row['binary'])].iterrows():
            bin_vectors.append(entry['quant_embedding'])

        bin_vector     = np.average(bin_vectors, axis=0).ravel()
        dexter_embedding   = np.hstack([em_reshaped, aq_em.ravel(), ctx_vector, bin_vector])

        p.at[ind,'dexter_embedding'] = dexter_embedding

    df['dexter_embedding'] = p['dexter_embedding']
    # return only rows with embeddings
    return df.loc[ids]

def extract_embedding(df, be_df, model, ids):
    p = pd.DataFrame(columns=['dexter_embedding'])
    for ind in tqdm(ids):
        row = df.loc[ind]

        ##symbol feature vector
        ac_em = row['cat_embedding']
        aq_em = row['quant_embedding'].ravel()

        ##add callers and callee contexts
        c_ctx_vector = row['ctx_feat']

        bc_em   = be_df.loc[be_df['binary'] == row['binary'] ]['cat_embedding'].values[0]

        if classes.utils.is_scipy_sparse(ac_em):
            ac_em   = np.array(ac_em.todense())
        if classes.utils.is_scipy_sparse(c_ctx_vector):
            c_ctx_vector   = np.array(c_ctx_vector.todense())
        if classes.utils.is_scipy_sparse(bc_em):
            bc_em   = np.array(bc_em.todense())

        a_em    = np.hstack([ac_em, c_ctx_vector, bc_em ])


        at      = tf.convert_to_tensor(a_em, dtype=tf.float32)
        shp     = list(at.shape)
        ##prepend as a single element batch
        shp.insert(0, 1)
        atb     = tf.reshape(at, shp)

        #fetch embedding
        embedding = model.encoder(atb)
        #embedding is a tf tensor of shape (1, 1, N)
        #N is the size of our embeddings
        intermediate_dim = max(embedding.shape)
        em_reshaped = tf.reshape(embedding, (intermediate_dim,)).numpy()

        """
            Build embedding and add quant vectors
        """
        ##local context feature vector (attention)
        ctx_vectors = []
        for n in row['callers'] + row['callees']:
            #find entry for function name
            for e_ind, entry in df[(df['name'] == n) & (df['binary'] == row['binary'])].iterrows():
                ctx_vectors.append(entry['quant_embedding'])

        if len(ctx_vectors) == 0:
            ctx_vector = (row['quant_embedding'] * 0).ravel()
        else:
            ##if sparse matraces
            ctx_vector     = np.array(np.average(ctx_vectors, axis=0)).ravel()


        ##local context feature vector (attention)
        bin_vectors = []
        #find entry for function name
        for e_ind, entry in df[(df['binary'] == row['binary'])].iterrows():
            bin_vectors.append(entry['quant_embedding'])

        bin_vector     = np.array(np.average(bin_vectors, axis=0)).ravel()

        dexter_embedding   = np.hstack([em_reshaped, aq_em, ctx_vector, bin_vector])
        p.at[ind,'dexter_embedding']   = dexter_embedding

    return p

def save_embeddings_to_database(df, config):
    db = PostgresDB(config)
    db.connect()
    for ind, row in tqdm(df.iterrows()):
        embedding = row['dexter_embedding'].reshape(1, -1)
        db.add_function_embedding('dexter', {
            'function_id'   : ind,
            'embedding'     : classes.utils.py_obj_to_bytes_fast(embedding)
            })
    db.conn.commit()


def sparse_reshape(sparse):
    shape = sparse.dense_shape
    return tf.sparse.reshape(sparse, [shape[0], shape[2]])

def lr_scheduler(epoch, lr):
    """
        Adaptive adjustment of learning rate
    """
    return lr * tf.math.exp(-0.1 * epoch)

def main():
    ###
    EXTRACT_EMBED_MODE          = True
    EXTRACT_EMBED_CHECKPOINT    = 128
    LOAD_EMBED_CHECKPOINT       = 48
    ###

    #1.5x machine cores
    tf.config.threading.set_inter_op_parallelism_threads    = 120


    config = Config()
    nlp = NLP(config)
    #df, be_df = load_dataset(nlp)
    #classes.utils.pickle_save_py_obj(config, [df, be_df], 'dexter_data')
    df, be_df = classes.utils.pickle_load_py_obj(config, 'dexter_data')

    ##shape of a symbol embedding, input embedding in binary context vector + symbol feature vector
    #em_dim            = df[0:1]['cat_embedding'].values[0].shape[1] + df[0:1]['quant_embedding'].values[0].shape[1]
    em_dim              = df[0:1]['cat_embedding'].values[0].shape[1]
    in_dim              = (1, em_dim * 3)
    out_dim             = in_dim
    learning_rate       = 1e-4
    intermediate_dim    = 92
    sub_intermeditae_dim= 48
    batch_size          = 120*2
    prefetch_size       = batch_size
    #checkpoint_path     = "/tmp/checkpoint.{}.ckpt"
    checkpoint_path     = config.res + "/xml_model/checkpoint.{}.ckpt"
    save_freq           = 6
    early_stop_n_batch  = 6
    epoch_batches       = len(df) // batch_size
    num_epochs          = 6
    MAX_BATCHES         = epoch_batches * num_epochs
    MIN_EPOCHS          = 1
    min_batches         = epoch_batches * MIN_EPOCHS
    #lr_callback         = tf.keras.callbacks.LearningRateScheduler(lr_scheduler)
    print("Minimum batches for 1 epoch: {}".format(epoch_batches))

    autoencoder = Autoencoder(intermediate_dim=intermediate_dim, sub_intermediate_dim=sub_intermeditae_dim, out_dim=out_dim[1])
    #autoencoder.summary()
    #embed()
    if EXTRACT_EMBED_MODE:
        autoencoder.load_weights(checkpoint_path.format(EXTRACT_EMBED_CHECKPOINT))
        """
        edf = extract_embeddings(df, be_df, autoencoder)
        edf.to_pickle('/tmp/dexter_embeddings.pickle')
        save_embeddings_to_database(edf, config)
        embed()
        exit()
        """

        # scale quant columns
        df, scaler_quant = normalize_dataframe(df, 'quant_embedding')
        #be_df, be_scaler_quant = normalize_dataframe(be_df, 'quant_embedding')


        db = PostgresDB(config)
        db.connect()
        #dexter_df = pd.DataFrame(db.get_embeddings('dexter'), columns=['id', 'name', 'b_name', 'b_path', 'embedding']).set_index('id')

        #unprocessed_ids = list(set(df.index.values.tolist()) - set(dexter_df.index.values.tolist()))
        #del db
        #del dexter_df

        unprocessed_ids = db.get_non_null_embeddings('dexter', 'embedding')
        while len(unprocessed_ids) > 0:
            rnd_subset = sample(set(unprocessed_ids) & set(df.index), 64)
            if len(rnd_subset) == 0:
                break

            print("Using random subset of length:", len(rnd_subset))

            def update_funcs(df, be_df, autoencoder, chunk):
                p = extract_embeddings(df, be_df, autoencoder, chunk)
                save_embeddings_to_database(p, config)


            print("Processing", str(len(rnd_subset)), "ids")
            update_funcs(df, be_df, autoencoder, rnd_subset)
            #unprocessed_ids = list(set(unprocessed_ids) - set(rnd_subset))
            unprocessed_ids = db.get_non_null_embeddings('dexter', 'embedding')

        #chunks = classes.utils.n_chunks(unprocessed_ids, 1024)
        """
        for i, chunk in enumerate(chunks):
            print("On chunk", i)
            update_funcs(df, be_df, autoencoder, chunk)
        """

        #Parallel(n_jobs=120, verbose=1, backend="loky")(map(delayed(update_funcs), repeat(df), repeat(be_df), chunks))
        print("Finished extracting embeddings. Saved to database")
        #embed()
        exit()

    if LOAD_EMBED_CHECKPOINT > 0:
        print("Loading previous state - {}".format(LOAD_EMBED_CHECKPOINT))
        autoencoder.load_weights(checkpoint_path.format(LOAD_EMBED_CHECKPOINT))

    dg_f = lambda q, d=df, b=be_df: emit_symbol_pairs(d, b, queue=q)
    MT_dg_f = lambda: mp_buffer_generator(dg_f, nprocs=60, maxbuf=2*prefetch_size)

    ##single threaded emit random symbols IO
    #dg_q = lambda d=df, b=be_df: emit_symbol_pairs(d, b)

    output_signature=(
        tf.TensorSpec(shape=tf.TensorShape(in_dim), dtype=tf.float32, name='input'),
        tf.TensorSpec(shape=tf.TensorShape(out_dim), dtype=tf.float32, name='output')
    )

    #if _SPARSE_TENSORS_:
    #    output_signature=(tf.int64, tf.float32, tf.int64)

    dataset = tf.data.Dataset.from_generator(MT_dg_f, output_signature=output_signature)
    dataset = dataset.batch(batch_size=batch_size)
    dataset = dataset.cache().prefetch(int(prefetch_size))

    opt = tf.optimizers.Adam(learning_rate=learning_rate)

    writer      = tf.summary.create_file_writer('tmp')
    #checkpoint  = tf.keras.callbacks.ModelCheckpoint(filepath='/tmp/checkpoint', save_weights_only=True, verbose=1)

    min_loss = inf

    print("About to train autoencoder...")
    loss    = tfa.losses.ContrastiveLoss()

    g_it    = 0
    loss_it = 0
    with writer.as_default():
        with tf.summary.record_if(True):
            print("enumerating dataset...")
            for step, batch_features in enumerate(dataset):
                X, Y = batch_features
                print("[+] Computing batch", step)
                train(loss, autoencoder, opt, batch_features)
                loss_values = loss(Y, autoencoder(X))
                tf.summary.scalar('loss', loss_values, step=step)

                loss_value = loss_values.numpy()
                print("[+] Batch: {}, Loss: {}".format(g_it, loss_value))
                if loss_value < min_loss:
                    min_loss = loss_value
                    loss_it = 0
                else:
                    loss_it += 1

                if loss_it >= early_stop_n_batch and g_it > min_batches:
                    print("[!] Early stopping. Loss has not decreaed in {} batches".format(loss_it))
                    autoencoder.save_weights(checkpoint_path.format(g_it))
                    sys.exit()

                g_it += 1
                if g_it > MAX_BATCHES:
                    autoencoder.save_weights(checkpoint_path.format(g_it+1))
                    break

                if g_it % save_freq == 0:
                    print("[!] Saving model weights...")
                    # Save the weights using the `checkpoint_path` format
                    autoencoder.save_weights(checkpoint_path.format(g_it))

                del X
                del Y
                del batch_features
                del step
                del loss_value
                del loss_values
                print("[!] Running garbage collection...")
                gc.collect()
                print("[!] Finished clearing memory")

if __name__ == '__main__':
    main()
