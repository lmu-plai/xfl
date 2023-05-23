import pickle
import dill
import json
import copy
import math
from io import BytesIO
import logging
import context
import classes.config
import progressbar
import numpy as np
import scipy as sp
import io

from random import uniform
from networkx.drawing import nx_agraph
import networkx as nx
import pygraphviz


def run_once(f):
        def wrapper(*args, **kwargs):
                if not wrapper.has_run:
                        wrapper.has_run = True
                        return f(*args, **kwargs)
        wrapper.has_run = False
        return wrapper


pbar_config = [' [ ',  progressbar.Counter(format='%(value)d / %(max_value)d'), ' ] ',  progressbar.Percentage(), ' [', progressbar.Timer(),
                           progressbar.Bar(), ' (', progressbar.ETA(), ')'
                           ]
###################################
#####Loading/Saving data###########
###################################

def py_obj_to_bytes(py_obj):
        """
                Save python object to bytes using DILL format
        """
        with BytesIO() as b:
                dill.dump(py_obj, b)
                return b.getvalue()

def py_obj_from_bytes(bin_data):
        """
                Load Python object from bytes using DILL format
        """
        with BytesIO(bin_data) as b:
                return dill.load(b)

def py_obj_to_bytes_fast(py_obj):
        """
                Save python object to bytes using DILL format
        """
        with BytesIO() as b:
                pickle.dump(py_obj, b)
                return b.getvalue()

def py_obj_from_bytes_fast(bin_data):
        """
                Load Python object from bytes using DILL format
        """
        with BytesIO(bin_data) as b:
                return pickle.load(b)



def pickle_save_py_obj(config, data, name):
        fname = config.res + "/" + name + ".pickle"
        ##if abs path given
        if name[0] == '/':
            fname = name + ".pickle"
        config.logger.debug("Saving {} to {}".format(name, fname))
        with open(fname, 'wb') as f:
                pickle.dump(data, f, protocol=pickle.HIGHEST_PROTOCOL)
                f.close()

def pickle_load_py_obj(config, name):
        fname = config.res + "/" + name + ".pickle"
        ##if abs path given
        if name[0] == '/':
            fname = name + ".pickle"
        config.logger.debug("Loading {} from {}".format(name, fname))
        with open(fname, 'rb') as f:
                a = pickle.load(f)
                f.close()
                return a



def save_py_obj(config, data, name):
        fname = config.res + "/" + name + ".dill"
        ##if abs path given
        if name[0] == '/':
            fname = name + ".dill"
        config.logger.debug("Saving {} to {}".format(name, fname))
        with open(fname, 'wb') as f:
                #pickle.dump(data, f, protocol=pickle.HIGHEST_PROTOCOL)
                dill.dump(data, f)
                f.close()

def load_py_obj(config, name):
        fname = config.res + "/" + name + ".dill"
        ##if abs path given
        if name[0] == '/':
            fname = name + ".dill"
        config.logger.debug("Loading {} from {}".format(name, fname))
        with open(fname, 'rb') as f:
                #a = pickle.load(f)
                a = dill.load(f)
                f.close()
                return a

def load_py_objs(config, names):
        """
        Load multiple objects and return in array
        """
        res = []
        for name in names:
                fname = config.res + "/" + name + ".dill"
                config.logger.debug("Loading {} from {}".format(name, fname))
                with open(fname, 'rb') as f:
                        #a = pickle.load(f)
                        a = dill.load(f)
                        f.close()
                        res.append(a)
        return res


###################################
######Splitting collections########
###################################


def chunks_of_size(l, n):
        """Yield successive n-sized chunks from l."""
        for i in range(0, len(l), n):
                yield l[i:i + n]


def n_chunks(l, n):
        """Break l into n parts"""
        N = math.ceil(len(l) / n)
        for i in range(0, len(l), N):
                yield l[i:i + N]


def chunks_of_func(l, f, t):
        """
        Split a list into chunks of total t calculated by function f on each elem in l
        """
        total = 0
        arr = []
        for i in l:
                c = f(i)
                if total + c > t and len(arr) > 0:
                        yield copy.deepcopy(arr)
                        arr.clear()
                        total = 0
                total += c
                arr.append(i)

        if len(arr) > 0:
                yield arr


def str_to_byte_ints(bin_str):
    """
        Convert a string of text with "0"s or "1"s into ints of each
        byte

        NB: call bytes(str_to_byte_ints) to get binary data
    """
    assert(len(bin_str) % 8 == 0)
    for b in chunks_of_size(bin_str, 8):
        yield int(b, 2)




def list_to_string(vec):
        name = ""
        for x in vec:
                name += str(x) + ","
        return name[:-1]


def _desyl_init_class_(self, config):
        assert(isinstance(config, classes.config.Config))
        #self.logger = logging.getLogger(config.logger)
        self.logger = config.logger
        self.config = config

def _desyl_deinit_class_(self):
        if hasattr(self, 'logger'):
                del self.logger
        if hasattr(self, 'config'):
                del self.config



def debug_np_obj(obj, txt=""):
        if len(txt):
                print(txt)
        print("Shape: {}".format(np.shape(obj)))
        print(obj)


def ordinal_follower(n):
        """
        Return the ordinal follower for numbered text
        """
        last_digit = str(n)[-1]
        if last_digit == "1":
                return "st"
        elif last_digit == "2":
                return "nd"
        elif last_digit == "3":
                return "rd"
        else:
                return "th"


def plural_follower(n):
        "Textual follow for plurals"
        if n == 1:
                return ""
        return "s"


def calculate_f1(tp, tn, fp, fn):
        precision = tp / float(tp + fp)
        recall = tp / float(tp + fn)
        f1 = 2.0 * (precision * recall)/(precision + recall)
        return f1, precision, recall

def is_scipy_sparse(np_obj):
    return sp.sparse.issparse(np_obj)


def denormalise_scipy_sparse(mat):
        """
                convert all values (0, 1] -> 1
        """
        #r, c = scipy.where(mat > 0.0)
        r, c = mat.nonzero()
        assert(len(r) == len(c))
        for i in tqdm.tqdm(range(len(r))):
                r_ind, c_ind = r[i], c[i]
                mat[r_ind, c_ind] = 1.0
        return mat


def read_file_lines(fname):
        # read file into array of lines
        res = []
        with open(fname, 'r') as f:
                for line in f:
                        t = line.strip()
                        if len(t) > 0:
                                res.append(t)
        return res


def nx_set_node_property(G, node_id, key, value):
        """
                Add property to a node in a graph
        """
        attr = {node_id: {key: value}}
        nx.set_node_attributes(G, attr)


def nx_set_edge_property(G, edge_tuple, key, value):
        """
                Add property to an edge between a tuple of nodes 
        """
        attr = {edge_tuple: {key: value}}
        nx.set_edge_attributes(G, attr)


def nx_to_str(G):
        with io.StringIO() as buf:
                nx.drawing.nx_pydot.write_dot(G, buf)
                return buf.getvalue()

def str_to_nx(buf):
    ####100 times faster using pygraphviz
    return nx_agraph.from_agraph(pygraphviz.AGraph(buf))
    #return nx.drawing.nx_pydot.read_dot(io.StringIO(buf))

def save_graph(G, filename):
    nx.drawing.nx_pydot.write_dot(G, filename)

def print_nonzero(np_obj):
        S = np.nonzero(np_obj)
        if len(S) == 2:
                r, c = np.nonzero(np_obj)
                out = np.zeros( (len(r), 1) )
                for i, (a, b) in enumerate(zip(r, c)):
                        out[i,0] = np_obj[a, b]
        elif len(S) == 1:
                r = np.nonzero(np_obj)
                out = np.zeros( (len(r), ) )
                for i, a in enumerate(r):
                        out[i] = np_obj[a]
        else:
                raise RuntimeError("Invalid numpy shape")
        return out


def _predict(estimator, X, method, start, stop):
        return getattr(estimator, method)(X[start:stop])

def parallel_predict(estimator, X, n_jobs=1, method='predict', batches_per_job=3):
        n_jobs = max(cpu_count() + 1 + n_jobs, 1)  # XXX: this should really be done by joblib
        n_batches = batches_per_job * n_jobs
        n_samples = len(X)
        batch_size = int(np.ceil(n_samples / n_batches))
        parallel = Parallel(n_jobs=n_jobs)
        results = parallel(delayed(_predict)(estimator, X, method, i, i + batch_size)
                                           for i in range(0, n_samples, batch_size))
        if sp.issparse(results[0]):
                return sp.sparse.vstack(results)
        return np.concatenate(results)


def with_proba(n:float):
    """
        return True with probability n
    """
    r = uniform(0.0, 1.0)
    return True if n > r else False


def scipy_sparse_to_sparse_tensor(X, dtype):
    coo = X.tocoo()
    indices = np.mat([coo.row, coo.col]).transpose()
    return tf.sparse.reorder(tf.SparseTensor(indices, coo.data, coo.shape, dtype=dtype))

def scipy_sparse_to_sparse_tensor_spec(X):
    coo = X.tocoo()
    indices = np.mat([coo.row, coo.col]).transpose()
    return (indices, coo.data, coo.shape)
