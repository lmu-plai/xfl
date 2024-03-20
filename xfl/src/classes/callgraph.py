
"""

Copyright 2017-2024 by James Patrick-Evans, Moritz Dannehl, and Johannes Kinder.

This file is part of XFL.

XFL is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

XFL is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with XFL. If not, see <https://www.gnu.org/licenses/>. 

"""

import os, sys, re
import logging, tqdm
import networkx as nx
import numpy as np
import scipy
import scipy.sparse
from multiprocess import Pool
from multiprocess.pool import ThreadPool
import itertools
from networkx.drawing.nx_pydot import write_dot 
import random
import IPython
from IPython import embed
import tqdm
from joblib.parallel import cpu_count, Parallel, delayed


import context
from classes.config import Config
from classes.database import Database
from classes.symbol import Symbol
import classes.utils

class Callgraph:
    """
    """
    def __init__(self, config, pdb, path):
        classes.utils._desyl_init_class_(self, config)
        self.pdb        = pdb
        self.path       = path
        self.unknowns   = set([])
        self.knowns     = set([])
        self.functions  = set([])
        self.G          = nx.DiGraph()

        #self.G = self.build()

    @staticmethod
    def from_clf(config, exp, clf_pipe, pdb, path):
        cg = Callgraph(config, pdb, path)
        cg.build_with_clf(exp, clf_pipe)
        return cg

    def build(self):
        self.logger.info("Building Callgraph from DB for {}".format(self.path))
        res, known_functions = self.pdb.binary_symbols(self.path)
        self.knowns = set(known_functions)

        for s in tqdm.tqdm(res):
            self.unknowns.add(s.name)
            self.functions.add(s.name)
            self.G.add_node( s.name, text_func=True, func=True, vaddr=s.vaddr)

            for c in s.callees:
                #ignore recursive calls
                if c != s.name:
                    self.G.add_edge( s.name, c, call_ref=True, data_ref=False)

            for c in s.callers:
                #ignore recursive calls
                if c != s.name:
                    self.G.add_edge( c, s.name, call_ref=True, data_ref=False)

        self._add_node_attributes()
        self.logger.info("{} nodes in CG for binary '{}'".format( len(self.G.nodes), self.path))

        return self.G

    def random_walk_iter(self):
        for u, v in self.G.edges:
            for w, x in self.G.edges(v):
                yield [ u, v, x ]


    @staticmethod
    def clf_proba_inf(clf, exp, x):
        """
            Get probability of each class from clf
        """
        fp = np.zeros((exp.name_vector_dims,), dtype=np.float64)
        y = clf.predict_proba(x)

        for i, j in zip(*y.nonzero()):
            prob    = y[i, j]
            cl      = clf.classes_[j]
            fp[cl]  = prob

        return fp

    def build_with_clf(self, exp, clf_pipe):
        """
            clf_pipe is a lambda function that applies an ML Classifier pipeline on each symbol vector
            exp is an experiment instance
        """
        res, known_functions = self.pdb.binary_symbols(self.path)
        self.knowns = set(known_functions)

        functions, data_refs = set([]), set([])
        for s in tqdm.tqdm(res):
            self.unknowns.add(s.name)
            self.functions.add(s.name)
            symbol_vector   = s.to_vec(exp, KNOWN_FUNCS=known_functions)
            symbol_vector = symbol_vector[0]
            fp              = clf_pipe(symbol_vector)
            ##if assumed known, set fingerprint accordingly
            #if s.name in known_functions:
            #    fp = exp.to_vec('name_vector', [s.name])
            self.G.add_node( s.name, text_func=True, func=True, vaddr=s.vaddr, fingerprint=fp)
            if s.name not in functions:
                functions.add( s.name )

            for c in s.callees:
                #ignore recursive calls
                if c != s.name:
                    self.G.add_edge( s.name, c, call_ref=True, data_ref=False)

            for c in s.callers:
                #ignore recursive calls
                if c != s.name:
                    self.G.add_edge( c, s.name, call_ref=True, data_ref=False)

            for c in s.callees | s.callers:
                if c not in functions:
                    self.functions.add( c )

            if hasattr(s, 'dcallees') and hasattr(s, 'dcallers'):
                for c in s.dcallees:
                    self.G.add_edge( s.name, c, data_ref=True, call_ref=False )

                for c in s.dcallers:
                    self.G.add_edge( c, s.name, data_ref=True, call_ref=False )

                for c in s.dcallees + s.dcallers:
                    if c not in data_refs:
                        data_refs.add( c )

        self._add_node_attributes()

        self.logger.info("{} nodes in CG for binary '{}'".format( len(self.G.nodes), self.path))
        self.logger.info("{} functions and {} data xrefs'".format( len(self.functions) , len(data_refs) ))
        return self.G

    def _add_node_attributes(self):
        """
            Add attibutes to nodes to determine, func, data, known_func
        """
        for n in self.functions:
            if 'text_func' not in self.G.nodes[n]:
                ##it's a known
                attr = { n : { 'text_func' : False, 'func': True, 'data' : False } }
                nx.set_node_attributes(self.G, attr)
                self.knowns.add(n)

        for n in self.G.nodes:
            if 'func' not in self.G.nodes[n]:
                attr = { n : { 'text_func' : False, 'func': False, 'data' : True } }
                nx.set_node_attributes(self.G, attr)


def build_and_save_cg(bin_path):
    """
    Build the callgraph for a binary and save it under /res/cgs/
    :param bin_path: The file path of the binary to build a callgraph for
    :return: None
    :rtype: None
    """
    if not isinstance(bin_path, str):
        raise Exception("Error, binaries path is not a string")

    #check if cg already exists
    fname = bin_path.replace("/", "_")
    config = classes.config.Config(no_logging=True)

    if os.path.isfile( config.desyl + "/res/cgs/" + fname + ".dot" ):
        return

    db = classes.database.Database(config)
    name_to_index = classes.utils.load_py_obj(config, "name_to_index")
    G = build_crf_for_binary(db, bin_path, name_to_index)
    classes.utils.save_py_obj( config, G, "cgs/" + fname + ".cg")
    write_dot(G, config.desyl + "/res/cgs/" + fname + ".dot")
    db.close()

def build_crf_for_binary(db, E, clf, path, debug=False):
    dim = E.name_vector_dims
    logger = db.config.logger
    if debug:
        logger.info("Building Callgraph from DB for {}".format(path))
    res = db._raw_get_symbols_from_binary(path)

    G = nx.DiGraph()

    functions, data_refs = set([]), set([])
    for s in tqdm.tqdm(res):
        symb = Symbol.from_dict(db.config, s)
        G.add_node( s['name'], text_func=True, func=True, vaddr=s['vaddr'], vec=symb.to_vec(E), fingerprint=clf.predict(symb.to_vec(E)).reshape(1, -1) )
        if s['name'] not in functions:
            functions.add( s['name'] )

        for c in s['callees']:
            #ignore recursive calls
            if c != s['name']:
                G.add_edge( s['name'], c, call_ref=True, data_ref=False)

        for c in s['callers']:
            #ignore recursive calls
            if c != s['name']:
                G.add_edge( c, s['name'], call_ref=True, data_ref=False)

        for c in s['callees'] + s['callers']:
            if c not in functions:
                functions.add( c )

        if 'dcallees' in s and 'dcallers' in s:
            for c in s['dcallees']:
                G.add_edge( s['name'], c, data_ref=True, call_ref=False )

            for c in s['dcallers']:
                G.add_edge( c, s['name'], data_ref=True, call_ref=False )

            for c in s['dcallees'] + s['dcallers']:
                if c not in data_refs:
                    data_refs.add( c )

    all_symbol_names = set(E.name_vector)
    for n in functions:
        if n not in all_symbol_names:
            if 'text_func' not in G.nodes[n]:
                logger.warn("Known function {} not in function corpus, removing from CRF".format(n))
                G.remove_node(n)
                continue

            #pmf = scipy.sparse.dok_matrix( (dim, 1), dtype=np.float128)
            pmf = np.zeros( (dim, ), dtype=np.float64)
            print("Setting node potential for node {}".format(n))
            attr = { n : { 'node_potential' : pmf } }
            nx.set_node_attributes(G, attr)
            continue

        pmf = np.zeros( (dim, ), dtype=np.float64)
        #pmf = scipy.sparse.dok_matrix( (dim, ), dtype=np.float64)

        pmf[ E.to_index('name_vector', n) ] = 1.0
        attr = { n : { 'node_potential' : pmf } }
        nx.set_node_attributes(G, attr)

        if 'text_func' not in G.nodes[n]:
            attr = { n : { 'text_func' : False, 'func': True, 'data' : False } }
            nx.set_node_attributes(G, attr)

    ##no data refs and functions with the same name
    #assert(len(functions.intersection(data_refs)) == 0)
    if len(functions.intersection(data_refs)) != 0:
        logger.warn("DATA XREF and FUNCTION take the same name in callgraph {} - {}".format(path, functions.intersection(data_refs)))

    for n in data_refs - functions:
        attr = { n : { 'text_func' : False, 'func': False, 'data' : True } }
        nx.set_node_attributes(G, attr)

    if debug:
        logger.info("{} nodes in CG for binary '{}'".format( len(G.nodes), path))
        logger.info("{} functions and {} data xrefs'".format( len(functions) , len(data_refs) ))

    return G


def build_binary_cg_merge_vaddr(db, path):
    """
    Build a callgraph for a binary by loading relations from the database
    :param db: An instance of classes.database.Database
    :path path: Full path of the binary to build the callgraph for.
    :param collection: Collection name to use for looking up symbols in the database
    :return: The callgraph
    :rtype: networkx.DiGraph
    """
    db.logger.info("Fetching symbols in {}".format(path))
    symbols = db.get_symbols_from_binary(path)
    #db.logger.debug(symbols)

    db.logger.info("Buidling symbol hash maps for binary...")

    #build symbol name to vaddr hash map
    symb_to_vaddr = dict(map(lambda x: [x.name, x.vaddr], symbols))
    vaddr_to_symb = dict(map(lambda x: [x.vaddr, x.name], symbols))

    db.logger.info("{} symbols in binary '{}'".format( len(symbols), path))
    G = nx.DiGraph()
    for s in symbols:
        ## mod for using CFG from real binary!!
        #symb_name = __mod_name_to_stripped(symb_to_vaddr, s.name)
        symb_name = s.name

        for c in s.callees:
            G.add_edge( symb_name, c )

        for c in s.callers:
            #G.add_edge( __mod_name_to_stripped(symb_to_vaddr, c), symb_name )
            G.add_edge( c, symb_name )


        if len(s.callers + s.callees) == 0:
            G.add_node( symb_name )
            db.logger.debug("WARNING! Unconnected function: '{}'".format(s.name))

    for n in G.nodes:
        #imported symbol!!
        if n not in symb_to_vaddr:
            symb_to_vaddr[n] = 0
            attr = { n : { 'imported_function' : n } }
            nx.set_node_attributes(G, attr)

        #logger.debug("Labelling node {} with label vaddr={}".format(n, symb_to_vaddr[n]))
        G.nodes[n]['vaddr'] = symb_to_vaddr[n]

    db.logger.info("{} nodes (symbols) in CFG for binary '{}'".format( len(G.nodes), path))

    return G#, symbols


def load_cg_pattern(config, pattern):
    files = [f for f in os.listdir(config.desyl + '/res/cgs/') if re.search(pattern, f)]
    mf = list(map(lambda x: x.replace(".dill", ""), files))
    models = list(map(lambda x: 'cgs/' + os.path.basename(x) , mf))

    assert(len(models) == 1)
    #model_fname = 'cgs/' + os.path.basename(bin_path)
    model_fname = models[0]

    return classes.utils.load_py_obj(config, model_fname)

def load_cg(config, bin_path):
    model_fname = 'cgs/' + bin_path.replace("/", "_") + ".cg"
    return classes.utils.load_py_obj(config, model_fname)

def mp_load_cgs(config, bin_paths):
    p = ThreadPool(processes=64)
    #return p.starmap(load_cg, zip( itertools.repeat(config), bin_paths))
    
    return p.starmap(load_cg, zip( itertools.repeat(config), bin_paths))

def mp_load_all_cgs(config, pattern=r'.*', cg_dir='cgs'):
    """
    Load all callgraphs using multiprocessing.

    :return: list of networkx.DiGraph() for each cg
    :rtype: list [ (string:bin path, networx:CRF), ... ]
    """
    config.logger.info("Finding all CGs to load...")
    #files = list(glob.iglob(cfg.desyl + '/res/cfgs/' + pattern, recursive=False))
    files = [f for f in os.listdir(config.desyl + '/res/' + cg_dir + '/') if re.search(pattern, f)]
    #filter non dill files
    files = list(filter(lambda x: x[-5:] == ".dill", files))

    mf = list(map(lambda x: x.replace(".dill", ""), files))
    models = list(map(lambda x: cg_dir + '/' + os.path.basename(x) , mf))
    #randomize order so large cg files are not next to each other
    models = random.sample(models, len(models))

    chunk_size = 32
    config.logger.info("Splitting {} CGs into chunks of {}".format(len(models), chunk_size))
    chunks = classes.utils.chunks_of_size(models, chunk_size)

    config.logger.info("Loading {} callgraphs".format( len(models) ))
    p = Pool(processes=64)
    res = p.starmap(classes.utils.load_py_objs, zip( itertools.repeat(config), chunks))
    #res = p.starmap(classes.utils.load_py_objs, list(zip( itertools.repeat(config), chunks))[:10])
    #res = [ classes.utils.load_py_objs(config, next(chunks, 1)) ]
    #res = [ classes.utils.load_py_objs(config, list(chunks)[:10] ) ]
    config.logger.info("Loaded models. Flattening them...")
    GG = [G for GL in res for G in GL]
    bins = [b for bl in chunks for b in bl]
    p.close()
    return zip(bins, GG)

def load_all_cgs(config, pattern=r'.*'):
    """
    Load all callgraphs caches in /res/cfgs
    :return: list of networkx.DiGraph() for each cg
    :rtype: list
    """
    GG = []

    res = [f for f in os.listdir(config.desyl + '/res/cgs/') if re.search(pattern, f)]
    #for f in glob.iglob(cfg.desyl + '/res/cfgs/'+pattern, recursive=False):
    for f in res:
        if f[-5:] != ".dill":
            continue
        f = f.replace(".dill", "")
        model_name = 'cgs/' + os.path.basename(f)
        G = classes.utils.load_py_obj( config, model_name )
        GG.append(G)
    return GG

def build_all_cgs(db):
    """
    Build all callgraphs for each distinct binary in symbols collection of the database
    :param db: An instance of classes.database.Database
    :return: None
    :rtype: None
    """
    #bins = db.distinct_binaries()
    bins = set(db.distinct_binaries()) - db.get_known_symbol_binaries()
    bins = list(filter(lambda x: isinstance(x, str), bins))
    p = Pool(processes=32)
    p.map(build_and_save_cg, bins)
    p.close()

def build_cgs_from_paths(bins, CORPUS_NAME2INDEX=False):
    p = Pool(processes=64)
    #split into 1000
    chunked_bins = classes.utils.n_chunks(bins, 1000)
    f = __build_and_save_cg_chunks
    if CORPUS_NAME2INDEX:
        f = __build_and_save_corpus_cg_chunks
    for _ in tqdm.tqdm(p.map(f, chunked_bins)):
        pass
    p.close()

def __build_and_save_cg_chunks(bin_paths):
    """
    Build the callgraph for a binary and save it under /res/cgs/
    :param bin_path: The file path of the binary to build a callgraph for
    :return: None
    :rtype: None
    """
    config = classes.config.Config(no_logging=True)
    db = classes.database.Database(config)
    name_to_index = classes.utils.load_py_obj(config, "name_to_index")
    for bin_path in bin_paths:
        if not isinstance(bin_path, str):
            raise Exception("Error, binaries path is not a string")

        #check if cg already exists
        fname = bin_path.replace("/", "_")

        #if os.path.isfile( config.desyl + "/res/cgs/" + fname + ".dot" ):
        #    config.logger.info("Skipping {} - file already exists".format(bin_path))
        #    continue

        G = build_crf_for_binary(db, bin_path, name_to_index)
        classes.utils.save_py_obj( config, G, "cgs/" + fname + ".cg")
        write_dot(G, config.desyl + "/res/cgs/" + fname + ".dot")
    db.close()


def __build_and_save_corpus_cg_chunks(bin_paths):
    """
    Build the callgraph for a binary and save it under /res/cgs/
    :param bin_path: The file path of the binary to build a callgraph for
    :return: None
    :rtype: None
    """
    config = classes.config.Config(no_logging=True)
    db = classes.database.Database(config)
    name_to_index = classes.utils.load_py_obj(config, "corpus_name_to_index")
    for bin_path in bin_paths:
        if not isinstance(bin_path, str):
            raise Exception("Error, binaries path is not a string")

        #check if cg already exists
        fname = bin_path.replace("/", "_")

        if os.path.isfile( config.desyl + "/res/corpus_cgs/" + fname + ".dot" ):
            logger.info("Skipping", bin_path, "- file already exists")
            continue

        G = build_crf_for_binary(db, bin_path, name_to_index)
        classes.utils.save_py_obj( config, G, "corpus_cgs/" + fname + ".cg")
        write_dot(G, config.desyl + "/res/corpus_cgs/" + fname + ".dot")
    db.close()


def build_crf_for_binary_adb(pdb, E, adb, path, debug=False):
    dim = E.name_vector_dims
    logger = E.config.logger
    if debug:
        logger.info("Building Callgraph from DB for {}".format(path))
    res, known_functions = pdb.binary_symbols(path)

    G = nx.DiGraph()

    functions, data_refs = set([]), set([])
    for s in tqdm.tqdm(res):
        G.add_node( s.name, text_func=True, func=True, vaddr=s.vaddr, vec=s.to_vec(E, KNOWN_FUNCS=known_functions), fingerprint=adb.query_vector(s.to_vec(E, KNOWN_FUNCS=known_functions), E).reshape(1, -1) )
        if s.name not in functions:
            functions.add( s.name )

        for c in s.callees:
            #ignore recursive calls
            if c != s.name:
                G.add_edge( s.name, c, call_ref=True, data_ref=False)

        for c in s.callers:
            #ignore recursive calls
            if c != s.name:
                G.add_edge( c, s.name, call_ref=True, data_ref=False)

        for c in s.callees | s.callers:
            if c not in functions:
                functions.add( c )

        if hasattr(s, 'dcallees') and hasattr(s, 'dcallers'):
            for c in s.dcallees:
                G.add_edge( s.name, c, data_ref=True, call_ref=False )

            for c in s.dcallers:
                G.add_edge( c, s.name, data_ref=True, call_ref=False )

            for c in s.dcallees + s.dcallers:
                if c not in data_refs:
                    data_refs.add( c )

    all_symbol_names = set(E.name_vector) | set(E.known_name_vector)
    for n in functions:
        if n not in all_symbol_names:
            if 'text_func' not in G.nodes[n]:
                logger.warn("Known function {} not in function corpus, removing from CRF".format(n))
                G.remove_node(n)
                continue

        if 'text_func' not in G.nodes[n]:
            pmf = np.zeros( (E.known_name_vector_dims, ), dtype=np.float64)
            pmf[ E.to_index('known_name_vector', n) ] = 1.0

            #print("Setting node potential for KNOWN node {}".format(n))
            attr = { n : { 'text_func' : False, 'func': True, 'data' : False, 'node_potential': pmf } }
            nx.set_node_attributes(G, attr)
        else:
            ###unknown node
            pmf = np.zeros( (E.name_vector_dims, ), dtype=np.float64)
            pmf[ E.to_index('name_vector', n) ] = 1.0
            attr = { n : { 'node_potential' : pmf } }
            nx.set_node_attributes(G, attr)

    ##no data refs and functions with the same name
    #assert(len(functions.intersection(data_refs)) == 0)
    if len(functions.intersection(data_refs)) != 0:
        logger.warn("DATA XREF and FUNCTION take the same name in callgraph {} - {}".format(path, functions.intersection(data_refs)))

    for n in data_refs - functions:
        attr = { n : { 'text_func' : False, 'func': False, 'data' : True } }
        nx.set_node_attributes(G, attr)

    if debug:
        logger.info("{} nodes in CG for binary '{}'".format( len(G.nodes), path))
        logger.info("{} functions and {} data xrefs'".format( len(functions) , len(data_refs) ))

    return G


def build_crf_for_binary_clf(pdb, E, clf, path, debug=False):
    dim = E.name_vector_dims
    logger = E.config.logger
    if debug:
        logger.info("Building Callgraph from DB for {}".format(path))
    res, known_functions = pdb.binary_symbols(path)

    G = nx.DiGraph()

    functions, data_refs = set([]), set([])
    for s in tqdm.tqdm(res):
        G.add_node( s.name, text_func=True, func=True, vaddr=s.vaddr, vec=s.to_vec(E, KNOWN_FUNCS=known_functions), fingerprint=scipy.sparse.csr_matrix(clf.predict(s.to_vec(E, KNOWN_FUNCS=known_functions)).reshape(1, -1)) )
        if s.name not in functions:
            functions.add( s.name )

        for c in s.callees:
            #ignore recursive calls
            if c != s.name:
                G.add_edge( s.name, c, call_ref=True, data_ref=False)

        for c in s.callers:
            #ignore recursive calls
            if c != s.name:
                G.add_edge( c, s.name, call_ref=True, data_ref=False)

        for c in s.callees | s.callers:
            if c not in functions:
                functions.add( c )

        if hasattr(s, 'dcallees') and hasattr(s, 'dcallers'):
            for c in s.dcallees:
                G.add_edge( s.name, c, data_ref=True, call_ref=False )

            for c in s.dcallers:
                G.add_edge( c, s.name, data_ref=True, call_ref=False )

            for c in s.dcallees + s.dcallers:
                if c not in data_refs:
                    data_refs.add( c )

    all_symbol_names = set(E.name_vector)
    for n in functions:
        if n not in all_symbol_names:
            if 'text_func' not in G.nodes[n]:
                logger.warn("Known function {} not in function corpus, removing from CRF".format(n))
                G.remove_node(n)
                continue

            #pmf = scipy.sparse.dok_matrix( (dim, 1), dtype=np.float128)
            pmf = np.zeros( (dim, ), dtype=np.float64)
            print("Setting node potential for node {}".format(n))
            attr = { n : { 'node_potential' : pmf } }
            nx.set_node_attributes(G, attr)
            continue

        pmf = np.zeros( (dim, ), dtype=np.float64)
        #pmf = scipy.sparse.dok_matrix( (dim, ), dtype=np.float64)

        pmf[ E.to_index('name_vector', n) ] = 1.0
        attr = { n : { 'node_potential' : pmf } }
        nx.set_node_attributes(G, attr)

        if 'text_func' not in G.nodes[n]:
            attr = { n : { 'text_func' : False, 'func': True, 'data' : False } }
            nx.set_node_attributes(G, attr)

    ##no data refs and functions with the same name
    #assert(len(functions.intersection(data_refs)) == 0)
    if len(functions.intersection(data_refs)) != 0:
        logger.warn("DATA XREF and FUNCTION take the same name in callgraph {} - {}".format(path, functions.intersection(data_refs)))

    for n in data_refs - functions:
        attr = { n : { 'text_func' : False, 'func': False, 'data' : True } }
        nx.set_node_attributes(G, attr)

    if debug:
        logger.info("{} nodes in CG for binary '{}'".format( len(G.nodes), path))
        logger.info("{} functions and {} data xrefs'".format( len(functions) , len(data_refs) ))

    return G


