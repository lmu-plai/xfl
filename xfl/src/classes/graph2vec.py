import os
import IPython
import context
import classes.utils
from classes.config import Config
from scripts.gk_weisfeiler_lehman import GK_WL
from annoy import AnnoyIndex
import numpy as np
import networkx as nx
import tqdm
import json 

class Graph2Vec():
    """
        In LXD containers you may need to manually create a tmpfs at the following location:
            mount -t tmpfs -o size=1024G ramdisk /tmp/graph2vec/
    """

    def __init__(self):
        config = Config()
        classes.utils._desyl_init_class_(self, config)
        self.kernel = GK_WL()
        self.model  = None

    def save_graphs(self, graphs, directory):
        if not os.path.exists(directory):
            os.makedirs(directory)
        for i, g in tqdm.tqdm(enumerate(graphs), desc="Saving graphs to {}".format(directory), total=len(graphs)):
            #nx.write_edgelist(g, "{}/{}.json".format(directory, i), data=False)
            ##relabel nodes from strings to ints 0-N
            mapping = dict(zip(g.nodes(), range(len(g.nodes()))))
            g_mod = nx.relabel_nodes(g, mapping)

            #nx.write_edgelist(g_mod, "{}/{}.edgelist".format(directory, i), data=True)
            #nx.write_graphml(g, "{}/{}.graphml".format(directory, i))
            data = { "edges": list(g_mod.edges()) }
            with open('{}/{}.json'.format(directory, i), 'w') as outfile:
                json.dump(data, outfile)

    def unique_graph_map(self, graphs):
        """
            Given a list of graphs, compute a map from inde to unique graphs
            returns map, list of unique graphs
        """
        g_unique        = set()
        unique_indexes  = set()

        for i, g in tqdm.tqdm(enumerate(graphs), desc="Filtering unique graphs", total=len(graphs)):
            g_hash = Graph2Vec.hash_graph(g)
            if g_hash not in g_unique:
                g_unique.add(g_hash)
                unique_indexes.add(i)

        return unique_indexes, g_unique

    @staticmethod
    def hash_graph(g):
        #return nx.weisfeiler_lehman_graph_hash(g, node_attr=None, edge_attr='jumpkind')
        return nx.weisfeiler_lehman_graph_hash(g, node_attr=None, edge_attr=None)

    def train(self, graphs, model_path=None, model_dimensions=128):
        """
            Train a Graph2Vec model and return the unique-graphs
        """
        if not model_path:
            model_path = self.config.res + "/graph2vec.vec"

        g_indexes, g_unique_hashes = self.unique_graph_map(graphs)
        unique_graphs = [graphs[i] for i in g_indexes]

        self.logger.info("Saving edgelists to file")
        self.save_graphs(unique_graphs, "{}/graph2vec/".format(self.config.res))

        cmd="graph2vec# python3 src/graph2vec.py --input-path {}/graph2vec/ --output-path {} --workers {} --dimensions {} --epochs 50 --wl-iterations 3".format(self.config.res, model_path, self.config.analysis.THREAD_POOL_THREADS, model_dimensions)
        print("Please execute the following command:")
        print(cmd)
        print("WARNING! If you did not delete the graph2vec directory you need to do it and re-run this script!")
        return unique_graphs

    def load_embeddings(self, model_path=None):
        if not model_path:
            model_path = self.config.res + "/graph2vec.vec"
        ##parse csv file
        graph_vectors = []
        with open(model_path, 'r') as f:
            for i, line in tqdm.tqdm(enumerate(f), desc='Loading embeddings from file'):
                if i == 0:
                    continue
                values = line.split(',')
                entry, data = values[0], values[1:]
                g_vec = list(map(lambda x: float(x), data))
                np_arr = np.array(g_vec, dtype=np.float)
                graph_vectors.append(np_arr)

        return graph_vectors
