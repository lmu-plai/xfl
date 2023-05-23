import os, sys, logging
import copy
import numpy as np
from scipy.sparse import csr_matrix, lil_matrix, dok_matrix, csc_matrix
import context
import networkx as nx
import functools
from datetime import datetime
from joblib import Parallel, delayed
import tqdm
import hashlib
import collections
import binascii
import collections
import classes.utils
import classes.config
import classes.database
import classes.graph2vec
import classes.NLP
import IPython
import sklearn.cluster
from classes.config import Config
from classes.database import RedisDB

class Experiment():
    def __init__(self, config):
        """
            This class manages vectorisation and per experiment settings:
                - label -> symbol mappings
                - CFG vectorisation
                - Per experiment settings
        """
        classes.utils._desyl_init_class_(self, config)

        #self.db = classes.database.Database(config)
        self.pdb = classes.database.PostgresDB(config)
        self.rdb = classes.database.RedisDB(config)
        self.operations_vector  = []
        self.jumpkinds_vector   = []
        self.label_vector       = []
        self.func_arg_vector    = []
        self.name_vector        = []
        self.known_name_vector  = []
        self.ml_name_vector     = []
        self.constants_vector   = []
        self.hashes_vector      = []
        self.cfg_vector         = []

        self.operations_vector_dims = 0
        self.jumpkinds_vector_dims  = 0
        self.label_vector_dims      = 0
        self.func_arg_vector_dims   = 0
        self.name_vector_dims       = 0
        self.known_name_vector_dims = 0
        self.ml_name_vector_dims    = 0
        self.constants_vector_dims  = 0
        self.hashes_vector_dims     = 0
        self.symbol2vec_dims        = 0
        self.cfg_vector_dims        = 192

        ##frequent operations, build cache as dict
        ##caches are built lazily
        self.operations_vector_index_cache  = {}
        self.jumpkinds_vector_index_cache   = {}
        self.label_vector_index_cache       = {}
        self.func_arg_vector_index_cache    = {}
        self.name_vector_index_cache        = {}
        self.known_name_vector_index_cache  = {}
        self.ml_name_vector_index_cache     = {}
        self.constants_vector_index_cache   = {}
        self.hashes_vector_index_cache      = {}
        self.func_to_label_map              = {}

        self.symbol2vec         = {}
        #self.cfg_annoy_file     = ""

        self.assumed_known = set([
            'csu_fini', 'csu_init', 'register_tm_clones', 'deregister_tm_clones', 
            'start', 'fini', 'init', 'do_global_dtors_aux', 'frame_dummy'
        ])

        
    def load_settings(self):
        self.logger.debug("Loading experiment settings for current configuration")
        ##fixed experiments collection name
        #res = self.db.client['experiments'].find_one({ 'name' : self.config.experiment.name })
        res = self.rdb.get_py_obj('experiments:{}'.format(self.config.experiment.name))
        if not res:
            raise RuntimeError("Failed to get experiment configuration for experiment `{}`".format(self.config.experiment.name))

        for k in [ 'operations_vector', 'jumpkinds_vector', 'label_vector', 'func_arg_vector', 'name_vector', 'ml_name_vector', 'constants_vector', 'hashes_vector', 'cfg_vector', 'known_name_vector']:
            if k in res:
                setattr(self, k, res[k])
                setattr(self, k+'_dims', len(res[k]))
            else:
                self.logger.warning("Missing key in experiment settings: `{}`".format(k))

        self.constants = set(self.constants_vector)
        self.hashes = set(self.hashes_vector)


        self.func_to_label_map  = res['func_to_label_map']
        self.graph2vec_map      = set(self.cfg_vector)
        #self.cfg_annoy_file     = res['cfg_annoy_file']
        self.ll_relationships   = res['ll_relationships']
        self.ln_relationships   = res['ln_relationships']

        self.symbol2vec         = res['symbol2vec']
        self.symbol2vec_dims    = len(self.symbol2vec.keys())
    
    @staticmethod
    def _mp_symbols2_to_labels(chunk):
        """
            Process a chnk of names into labels
        """
        c = classes.config.Config()
        nlp = classes.NLP.NLP(c)
        return [nlp.canonical_set(i) for i in chunk]

    def gen_settings(self):
        ML_NAME_VEC_DIM = 8192 + 4096
        self.logger.debug("Generating experiment settings for current configuration! This may take some time.")
        self.pdb.connect()
        curr = self.pdb.cursor()
        for name, key, group in [
                ('cfg_vector', 'cfg', True),
                ('ml_name_vector', 'name', False),
                ('func_arg_vector', 'arguments', True),
                ('operations_vector', 'vex -> \'operations\'', True),
                ('jumpkinds_vector', 'vex -> \'jumpkinds\'', True)
                ]:
            self.logger.debug("Fetching all {}".format(key))
            query   = "SELECT {} AS field FROM public.binary_functions".format(key)
            if group:
                query   += " GROUP BY field"
            curr.execute(query)
            res = list(map(lambda x: x[0], curr.fetchall()))
            if not res:
                raise RuntimeError("Failed to generate distinct {} for experiment".format(name))

            if name in ['operations_vector', 'jumpkinds_vector']:
                res = list(functools.reduce(lambda x, y: x | set(y), res, set([])))

            if name == 'ml_name_vector':
                nlp     = classes.NLP.NLP(self.config)
                chunks  = classes.utils.n_chunks(res, 512)
                mod_res = Parallel(n_jobs=self.config.analysis.THREAD_POOL_THREADS)(delayed(Experiment._mp_symbols2_to_labels)(c) for c in chunks)
                c = collections.Counter()
                for r in mod_res:
                    for s in r:
                        c.update(s)
                
                c_tok_k, c_tok_v = zip(*c.most_common(ML_NAME_VEC_DIM))
                res = list(c_tok_k)

            ##include names from callers and callees
            #if name == 'name_vector':
                #generates label_vector
                ##cluster names into groups
                #self.cluster_words(res)


            if name == 'func_arg_vector':
                #remove arguments passed by memory
                #print(res)
                #IPython.embed()
                mod_res = list(filter(lambda x: not isinstance(x, type(None)) and 'mem_' not in x, res))
                res = list(functools.reduce(lambda x, y: x | set(y), mod_res, set([])))

            if name == 'cfg_vector':
                g2v = classes.graph2vec.Graph2Vec()
                #graph_hashes = list(map(lambda x: hashlib.sha256(x.encode('ascii')).digest(), res))
                #cfgs = list(tqdm.tqdm(map(lambda x, f=classes.utils.str_to_nx: f(x), res), desc="Converting CFGs to networkx.DiGraph", total=len(res))) 
                print("Converting graphs to networkx.DiGraph...")
                cfgs = Parallel(n_jobs=self.config.analysis.THREAD_POOL_THREADS)(delayed(classes.utils.str_to_nx)(r) for r in res)
                
                ###let tensroflow deal with duplicates, it's MUCH faster
                #g_map, g_unique = g2v.unique_graph_map( cfgs )
                #g2v.train( g_unique )
                unique_graphs = g2v.train( cfgs, model_dimensions=self.cfg_vector_dims)
                print("Continue when finished training")
                IPython.embed()

                embeddings = g2v.load_embeddings()
                ghashes = []
                for i, g in tqdm.tqdm(enumerate(unique_graphs), total=len(unique_graphs), desc='Saving embeddings'):
                    g_hash = classes.graph2vec.Graph2Vec.hash_graph(g)
                    ghashes.append(g_hash)
                    self.update_experiment_key("gHash2embedding:{}".format(str(g_hash)), embeddings[i])

                self.graph2vec_map  = set(ghashes)
                res = list(self.graph2vec_map)

            setattr(self, name, res)
            setattr(self, name + '_dims', len(res))

        self.known_name_vector      = list(self.pdb.all_known_functions())
        self.known_name_vector_dims = len(self.known_name_vector)

        self.unknown_name_vector      = list(self.pdb.all_unknown_functions())
        self.unknown_name_vector_dims = len(self.unknown_name_vector)

        self.name_vector      = list(set(self.known_name_vector) | set(self.unknown_name_vector))
        self.name_vector_dims = len(self.name_vector)

        ##generate default crf model parameters
        self.ll_relationships = {}
        self.ln_relationships = {}

        #self.cfg_annoy_file = ""

        tfidf_consts                = self.tfidf_constants(min_freq=2, max_freq=300)
        self.constants_vector       = list(tfidf_consts.keys())
        self.constants_vector_dims  = len(self.constants_vector)
        self.constants = set(self.constants_vector)

        ##build vector of most frequent opcode hashes
        freq_hashes                 = self.freq_opcode_hashes(freq=3)
        self.hashes_vector          = list(freq_hashes.keys())
        self.hashes_vector_dims     = len(self.hashes_vector)
        self.hashes                 = set(self.hashes_vector)

    def tfidf_constants(self, min_freq=3, max_freq=100):
        ###calculate term frequency inverse document frequency of constants
        self.logger.info("Fetching all symbol constants!")
        """
        consts = self.pdb.get_all_constants()
        consts_freq = collections.Counter(consts)

        idf = {}
        for key, value in tqdm.tqdm(consts_freq.items(), desc="Constants"):
            idf[key] = (1.0/value)

        ##filter maximum frequency
        f_idf_consts = dict(filter(lambda x: x[1] >= 1.0/m_freq, idf.items()))
        """
        f_idf_consts = self.pdb.constants_freq(max_freq=max_freq, min_freq=min_freq)

        return f_idf_consts

    def freq_opcode_hashes(self, freq=25):
        self.logger.info("Fetching all opcode hashes!")
        curr = self.pdb.cursor()
        curr.execute("SELECT opcode_hash FROM public.binary_functions;")
        opcode_hashes = list(map(lambda x: bytes(x[0]), curr.fetchall()))

        hash_freqs = collections.Counter(opcode_hashes)

        hashes = {}
        for key, value in tqdm.tqdm(hash_freqs.items(), desc="Opcode Hash Frequencies"):
            if value > freq:
                hashes[key] = value

        return hashes

    def freq_hashes(self, freq=25):
        self.logger.info("Fetching all hashes!")
        curr = self.pdb.cursor()
        curr.execute("SELECT asm_hash FROM public.binary_functions;")
        hashes = list(map(lambda x: bytes(x[0]), curr.fetchall()))

        hash_freqs = collections.Counter(hashes)

        hashes = {}
        for key, value in tqdm.tqdm(hash_freqs.items(), desc="Hash Frequencies"):
            if value > freq:
                hashes[key] = value

        return hashes



    def cluster_words(self, words):
        print("Clustering {} words! This may take a long time... O(n^2)".format(len(words)))
        words = np.asarray(words) #So that indexing with a list will work
        SW = classes.NLP.SmithWaterman()
        #similarity = -1*np.array([[distance.levenshtein(w1,w2) for w1 in words] for w2 in words])
        similarity = -1*np.array([[SW.distance(w1,w2) for w1 in words] for w2 in tqdm.tqdm(words, desc="computing word distances")])

        #affprop = sklearn.cluster.AffinityPropagation(affinity="precomputed", damping=0.5, preference=-0.31)
        affprop = sklearn.cluster.AffinityPropagation(affinity="precomputed")
        affprop.fit(similarity)

        """
        for cluster_id in np.unique(affprop.labels_):
            exemplar = words[affprop.cluster_centers_indices_[cluster_id]]
            cluster = np.unique(words[np.nonzero(affprop.labels_==cluster_id)])
            cluster_str = ", ".join(cluster)
            print(" - *%s:* %s" % (exemplar, cluster_str))
        """

        self.labels     = affprop.labels_
        center_indices  = affprop.cluster_centers_indices_
        
        """
        print("Clustered")
        print(self.labels)
        print(np.shape(self.labels))
        print(np.shape(center_indices))
        IPython.embed()
        """

        self.label_vector = list(map(lambda x, words=words: words[x], center_indices))
        self.label_vector_dims = len(self.label_vector)

        self.func_to_label_map = dict(map(lambda w, l, c=center_indices, words=copy.copy(words):
            (w, words[c[l]]), words, self.labels))

        print("Clustered into {} labels".format(self.label_vector_dims))

    def save_settings(self):
        #self.db.client['experiments'].delete_one({'name': self.config.experiment.name})
        self.rdb.set_py_obj('experiments:{}'.format(self.config.experiment.name), {
                'name'                  : self.config.experiment.name,
                'operations_vector'     : self.operations_vector,
                'jumpkinds_vector'      : self.jumpkinds_vector,   
                'label_vector'          : self.label_vector,       
                'constants_vector'      : self.constants_vector,
                'hashes_vector'         : self.hashes_vector,
                'func_to_label_map'     : self.func_to_label_map,
                'func_arg_vector'       : self.func_arg_vector,    
                'name_vector'           : self.name_vector,    
                'known_name_vector'     : self.known_name_vector,    
                'ml_name_vector'        : self.ml_name_vector,    
                'cfg_vector'            : self.cfg_vector,    
                'cfg_vector_dims'       : self.cfg_vector_dims,    
                #'cfg_annoy_file'        : self.cfg_annoy_file,     
                'll_relationships'      : self.ll_relationships,
                'ln_relationships'      : self.ln_relationships,
                'symbol2vec'            : self.symbol2vec,
        })

    def to_vec(self, name, arr):
        """
            Convert an array of type {name} into its vector format
        """
        if not isinstance(arr, collections.Iterable):
            raise RuntimeError("arr should be a list of items to be in the vector")

        valid_names = ['jumpkinds_vector', 'func_arg_vector',
                'operations_vector', 'name_vector', 'label_vector', 'known_name_vector',
                'symbol2vec', 'ml_name_vector', 'constants_vector',
                'hashes_vector', 'cfg_vector']
        if name not in valid_names:
            raise RuntimeError("Error, name needs to be in {}. {} given.".format(valid_names, name))

        if name == 'symbol2vec':
            vecs = map(lambda x: np.array(self.symbol2vec[x], dtype=np.float64), arr)
            return functools.reduce(lambda x, y: x + y, vecs)

        if name == 'cfg_vector':
            if isinstance(arr, str):
                arr = classes.utils.str_to_nx(arr)

            if not isinstance(arr, nx.DiGraph):
                raise RuntimeError("CFG arr needs to be a nx.DiGraph, not {}".format(type(arr)))

            g_hash = classes.graph2vec.Graph2Vec.hash_graph(arr)

            if g_hash not in self.graph2vec_map:
                self.logger.error("ERROR: CFG hash not found. Cannot generate embedding for unknown CFG. Returning 0 vector.")
                #return np.zeros((self.cfg_vector_dims, ), dtype=np.float64)
                raise RuntimeError("No cfg_vector mapping for {}:`{}`".format(g_hash,arr))
            return self.load_experiment_key("gHash2embedding:{}".format(str(g_hash)))

        ##convert function names to clustered centers
        #if name == 'label_vector':
        #    arr = list(map(lambda x: self.func_to_label_map[x], arr))

        dim = getattr(self, name + '_dims')
        vec = np.zeros( (dim, ), dtype=np.int64 )

        cache = getattr(self, name + '_index_cache')
        for it in arr:
            if it in cache:
                ind = cache[it]
                vec[ind] += 1
            else:
                vector_desc = getattr(self, name)
                if name == "ml_name_vector" or name == "label_vector":
                    if it not in vector_desc:
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
        if not isinstance(arr, collections.Iterable):
            raise RuntimeError("arr should be a list of items to be in the vector")

        valid_names = ['jumpkinds_vector', 'func_arg_vector', 'operations_vector', 'name_vector', 'label_vector', 'ml_name_vector', 'known_name_vector', 'constants_vector', 'hashes_vector']
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
                ind = vector_desc.index( it )
                assert(ind >= 0)
                assert(ind < dim)
                vec[0, ind] += 1
                cache[it] = ind
                ##write cache back
                setattr(self, name + '_index_cache', cache)

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





    def to_index(self, name, item):
        """
            Return the index in vectorspace of an item
        """
        valid_names = ['jumpkinds_vector', 'func_arg_vector', 'operations_vector', 'name_vector', 'label_vector', 'ml_name_vector', 'known_name_vector']
        if name not in valid_names:
            raise RuntimeError("Error, name needs to be in {}. {} given.".format(valid_names, name))

        dim = getattr(self, name + '_dims')
        cache = getattr(self, name + '_index_cache')
        if item in cache:
            ind = cache[item]
            return ind

        vector_desc = getattr(self, name)
        ind = vector_desc.index( item )
        assert(ind >= 0)
        assert(ind < dim)
        cache[item] = ind
        ##write cache back
        setattr(self, name + '_index_cache', cache)
        return ind

    def to_index_cache(self, name):
        ##fill cache
        for i in getattr(self, name):
            self.to_index(name, i)

        return copy.deepcopy( getattr(self, name + '_index_cache') )

    def update_experiment_key(self, key, value):
        """
            Save value to this experiment under key to the database
        """
        #res = self.db.client['experiments'].update_one({ 'name' : self.config.experiment.name }, { '$set' : { key : value } })
        res = self.rdb.set_py_obj('experiments:{}.{}'.format(self.config.experiment.name, key), value)

    def load_experiment_key(self, key):
        """
            Load key from this experiment database
        """
        #res = self.db.client['experiments'].find_one({ 'name' : self.config.experiment.name }, {key:1})
        res = self.rdb.get_py_obj('experiments:{}.{}'.format(self.config.experiment.name, key))
        if isinstance(res, type(None)):
            raise RuntimeError("Failed to get `{}` for experiment configuration `{}`".format(key, self.config.experiment.name))
        return res

    def parseFastTextvecFile(self, fname):
        self.symbol2vec = {}
        with open(fname, 'r') as f:
            lines = f.read().split('\n')
            entries, dims = list(map(lambda x: int(x), lines[0].split(' ')))
            self.symbol2vec_dims = dims
            self.logger.info("Parsing fastText vec model with {} entries each with {} dimensions".format(entries, dims))

            for line in tqdm.tqdm(lines[1:]):
                cols = line.split(' ')
                name = cols[0]
                ##null name
                if name == '</s>':
                    name = ''
                vector = list(map(lambda x: float(x), cols[1:-1]))

                self.symbol2vec[name] = np.array(vector)

    def load_labels(self, label_file):
        self.label_vector = list(map(lambda x: x.split(':')[1].strip(), classes.utils.read_file_lines(label_file)))
        self.label_vector_dims  = len(self.label_vector)
        self.label_vector_index_cache   = {}


class Result():
    """
        Class to process/store experiment results
        :param desc: description of experiment result
        :param store: diction to store values
    """

    def __init__(self, config:Config, desc:str, store:dict):
        classes.utils._desyl_init_class_(self, config)
        self.desc   = desc
        self.store  = store
        self.rdb    = RedisDB(config)

    @staticmethod
    def load(rdb:RedisDB, key:str):
        """
            Load key from this experiment database
        """
        #res = self.db.client['experiments'].find_one({ 'name' : self.config.experiment.name }, {key:1})
        res = rdb.get_py_obj('results:{}.{}'.format(rdb.config.experiment.name, key))
        if not res:
            raise RuntimeError("Failed to get `{}` for experiment configuration `{}`".format(key, rdb.config.experiment.name))
        return Result(rdb.config, key, res)

    def save(self):
        """
            Save value to this experiment under key to the database
        """
        return self.rdb.set_py_obj('results:{}.{}'.format(self.config.experiment.name, self.desc), self.store)

class CCSResult(Result):
    """
        Classification Experiment Result
    """
    def __init__(self, config:Config, store:dict, tool:str, pretrained:bool, label_size:int, train_set:str, test_set:str, date:datetime=datetime.now()):
        self.tstr   = date.isoformat(timespec='minutes') 
        self.desc    = "T={}:P={}:L={}:train_set={}:test_set={}:D={}".format(tool,
                str(pretrained), label_size, train_set, test_set, self.tstr)

        super(CCSResult, self).__init__(config, self.desc, store)

    def load(self, rdb):
        """
            Load a result store from the database
        """
        res         = Result.load(rdb, self.desc)
        self.store  = res.store


class Evaluation():
    """
        Class to calculate evaluation meterics for an experiment
    """

    def __init__(self, config):
        classes.utils._desyl_init_class_(self, config)
        pass

    @staticmethod
    def f1(tp, tn, fp, fn):
        return classes.utils.calculate_f1(fp, fn, fp, fn)

    def ml_precision(self, true_Y, pred_Y, MODE='MICRO') -> np.ndarray:
        """
            Calculate ML Precision from true label and predicted label matrix
        """
        assert(MODE in ('MICRO', 'MACRO'))
        tp  = self.ml_tp(true_Y, pred_Y, MODE)
        fp  = self.ml_fp(true_Y, pred_Y, MODE)
        return tp / (tp + fp)

    def ml_recall(self, true_Y, pred_Y, MODE='MICRO') -> np.ndarray:
        """
            Calculate ML Recall from ture label and predicted label matrix
        """
        assert(MODE in ('MICRO', 'MACRO'))
        tp  = self.ml_tp(true_Y, pred_Y, MODE)
        fn  = self.ml_fn(true_Y, pred_Y, MODE)
        return tp / (tp + fn)

    def ml_f1(self, p, r):
        """
            Calculate ML F1 from ML Precision and ML Recall
        """
        f1 = (2 * p * r) / ( p + r)
        return f1

    def ml_tp(self, true_Y, pred_Y, MODE:str) -> np.ndarray:
        """
            Expects 0's and 1's in both true and predicted label set
        """
        assert(true_Y.shape == pred_Y.shape)
        r, c    = true_Y.shape
        ##tp vector for each label
        tp      = np.zeros((c, ))
        #loop over all nonzero labels in true prediction
        rz, cz  = true_Y.nonzero()

        for i in tqdm.tqdm(range(len(rz)), 'Calculating ML TP'):
            ri  = rz[i]
            ci  = cz[i]
            if pred_Y[ri, ci] == true_Y[ri, ci]:
                tp[ci]  += 1

        #calculates tp for all classes, rather than vector of tp's
        if MODE=='MICRO':
            return np.sum(tp)
        return tp

    def ml_fn(self, true_Y, pred_Y, MODE:str) -> np.ndarray:
        """
            MultiLabel Flase Negative.
                Labels missed in prediction but exist in true set
        """
        assert(true_Y.shape == pred_Y.shape)
        r, c    = true_Y.shape
        ##tp vector for each label
        fn      = np.zeros((c, ))
        #loop over all nonzero labels in true prediction
        rz, cz  = true_Y.nonzero()

        for i in tqdm.tqdm(range(len(rz)), desc='Calculating ML FN'):
            ri  = rz[i]
            ci  = cz[i]
            assert(true_Y[ri, ci] == 1)
            if pred_Y[ri, ci] != true_Y[ri, ci]:
                fn[ci]  += 1

        ##calculates fn for all classes
        if MODE=='MICRO':
            return np.sum(fn)
        return fn

    def ml_fp(self, true_Y, pred_Y, MODE:str) -> np.ndarray:
        """
            MultiLabel Flase Positive.
                Labels predicted but don't exist in true set
        """
        assert(true_Y.shape == pred_Y.shape)
        r, c    = true_Y.shape
        ##tp vector for each label
        fp      = np.zeros((c, ))
        #loop over all nonzero labels in true prediction
        rz, cz  = pred_Y.nonzero()

        for i in tqdm.tqdm(range(len(rz)), desc='Calculating ML FP'):
            ri  = rz[i]
            ci  = cz[i]
            if pred_Y[ri, ci] != true_Y[ri, ci]:
                fp[ci]  += 1
        ##calculates fp for all classes
        if MODE=='MICRO':
            return np.sum(fp)
        return fp

    def cumulative_gain(self, y, ys, p=5):
        """
            Calculate cumulative gain given true gain labels y
            and predicted y* (ys) for top p predictions

            y and ys are a list of labels and their relevance (max 1.0 per elem)
            NB: y should be normalised (sum to 1)
        """
        #get top p  indexes
        ysp = np.argsort(ys)[::-1][:p]

        #get relevances
        rels    = [y[i] for i in ysp]
        return np.sum(rels)

    def discounted_cumulative_gain(self, y, ys, p=5):
        """
            Calculate discounted cumulative gain given true gain labels y
            and predicted y* (ys) for top p predictions

            y and ys are a list of labels and their relevance (max 1.0 per elem)
            NB: y should be normalised (sum to 1)
        """
        #get top p  indexes
        ysp = np.argsort(ys)[::-1][:p]

        #get relevances
        rels    = [y[i] for i in ysp]
        dcg     = 0.0
        for i, rel in enumerate(rels):
            dcg += (rel) / np.log2(i+1+1)

        return dcg
       

    def normalised_discounted_cumulative_gain(self, y, ys, p=5):
        """
            Calculate the normalised discounted cumulative gain given true gain labels y
            and predicted y* (ys) for top p predictions

            y and ys are a list of labels and their relevance (max 1.0 per elem)
            NB: y should be normalised (sum to 1)
        """

        dcg = self.discounted_cumulative_gain(y, ys, p)

        ideal_rank_top_p    = np.argsort(y)[::-1][:p]

        #get relevances
        ideal_rels    = [y[i] for i in ideal_rank_top_p]
        idcg     = 0.0
        for i, rel in enumerate(ideal_rels):
            idcg += (np.power(2, rel) - 1) / np.log2(i+1+1)

        if idcg == 0.0:
            self.logger.error("Error, IDCG is 0.0 -> function with no labels!")
            return 1.0

        ndcg = dcg / idcg
        return ndcg

    def precision_at_ks(self, true_Y, pred_Y, ks=[5]):
        """
            Return the Precision@K for k in ks, default: ks=[5]
            For P@5, P@10, P@3:
                set ks=[5, 10, 3]

            First argument is the correct set of labels, second is inferred labels
        """
        result = {}
        #true_labels = [set(true_Y[i, :].nonzero()[1]) for i in range(true_Y.shape[0])]
        true_labels = [set(true_Y[i, :].nonzero()[0]) for i in range(true_Y.shape[0])]

        #arg sort predicted labels and flip so largest is first
        label_ranks = np.fliplr(np.argsort(pred_Y, axis=1))
        for k in ks:
            pred_labels = label_ranks[:, :k]
            precs = [len(t.intersection(set(p))) / len(t) if len(t) > 0 else np.nan
                     for t, p in zip(true_labels, pred_labels)]
            result[k] = np.nanmean(precs)
        return result


           
if '__main__' == __name__:
    config = classes.config.Config()
    config.logger.setLevel(logging.INFO)
    exp = Experiment(config)
    print("Exiting after shell")
    IPython.embed()
    print("bye")
    sys.exit()
    exp.gen_settings()
    exp.save_settings()

