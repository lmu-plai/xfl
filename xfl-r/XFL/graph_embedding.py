
"""

Copyright 2017-2024 by James Patrick-Evans, Moritz Dannehl, Tristan Benoit, and Johannes Kinder.

This file is part of XFL.

XFL is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

XFL is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with XFL. If not, see <https://www.gnu.org/licenses/>. 

"""

from config import Config
from database import PostgresDB
from experiment import Experiment
from karateclub import FeatherGraph, NodeSketch, GraphWave, EgoNetSplitter, NNSED
import karateclub
import networkx as nx

"""
    Technical limitations

    ## Working Techniques

    LDP - works well, simple, deterministic?
    FeatherGraph - works, seems to be deterministic????

    ## Non-working techniques

    IGE - does not support direct graphs
    Feather
    GeoScattering - cannot handle fully connected graphs
    NetLSD - not implemnetd for directed graphs
    Wavelet Characteristic - Not implemented for directed graphs






    ### Structural node embeddings
        GraphWave for node embeddings, non-predicatble
        Role2Vec - seems great for single use, not predictabe! i.e. multiple models return different embeddings for the same node
        NodeSketch - deterministic, works!
        BoostNE - determinstic and works


    GLEE not implemneted for directed
    SocioDim not implemnetd

"""

def binary_node_embeddings(binary, callgraph: nx.Graph):
    """
        Get node embeddings for each function from the binary callgraph

        Returns numpy matrix with rows as node embeddings
        Also returns everse mapping to decode matrix. row i is symbol[i]
    """
    g = nx.convert_node_labels_to_integers(callgraph, first_label=0, ordering='default', label_attribute='old_label')
    keys    = list(g.nodes())
    vals    = list(map(lambda x, g=g: g.nodes[x]['old_label'], keys))
    mapping = dict(zip(keys, vals))
    clf = karateclub.BoostNE()
    clf.fit(g)
    return clf.get_embedding(), mapping, g

def build_graph_embeddings(symbols, nbins=48):
    """
        Pass in a list of symbols
        preserve mapping and handle removing zero sized graph

        embeeding i corresponds to symbol[ k_list[i] ]
        embedding i is embedding_mat[i, :]
    """
    ##reindexed graphs to ignore node values
    icfgs = list(map(lambda x: nx.convert_node_labels_to_integers( x.cfg ), symbols))
    mapping = dict(zip(range(len(symbols)), icfgs))
    null_vectors_list    = []

    ##remove empty graphs while preserving mapping
    for i in range(len(mapping)):
        if len(mapping[i].nodes()) == 0:
            null_vectors_list.append(i)
            del mapping[i]

    k_list, v_list  = [], []
    for k, v in mapping.items():
        k_list.append(k)
        v_list.append(v)

    ##compute whole graph embeddings
    ldp = karateclub.LDP(bins=nbins)
    ldp.fit(v_list)
    ##return embeddings with mapping in k_list
    return ldp.get_embedding(), k_list, null_vectors_list

def build_cg_with_vec(exp:Experiment, pdb:PostgresDB):
    clf_pipeline = lambda x: x

    for b in pdb.binaries():
        cg = Callgraph(config, pdb, b)
        di_g = cg.build_with_clf(exp, clf_pipeline)
        #yield di_g
        yield nx.Graph(di_g)

if __name__ == '__main__':
    config = Config()
    pdb = PostgresDB(config)
    exp = Experiment(config)
    #clf = FeatherGraph()
    #clf = NodeSketch()
    clf = GraphWave()
    #clf = EgoNetSplitter()
    #clf = NNSED()

    ##load settings from database
    ##connect to postgresdb
    pdb.connect()
    exp.load_settings()

    graph_gen = build_cg_with_vec(exp, pdb)

    g = next(graph_gen)
    ##remove disconnected components
    if not nx.is_connected(g):
        _g = nx.Graph()
        for sg in nx.connected_components(g):
            if len(sg) > len(_g.nodes()):
                _g = g.subgraph(sg)

    
    ##reindex graph
    ng = nx.convert_node_labels_to_integers(nx.Graph(_g))

    import utils
    utils.save_graph(g, '/tmp/g.dot')
    utils.save_graph(_g, '/tmp/csg.dot')

    clf.fit(ng)
    embeddings = clf.get_embedding()
    utils.pickle_save_py_obj(config, embeddings, 'feather.embeddings')
    IPython.embed()
