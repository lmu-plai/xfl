import context
from classes.config import Config
from classes.callgraph import Callgraph
from classes.database import PostgresDB
from classes.experiment import Experiment
from karateclub import FeatherGraph, NodeSketch, GraphWave, EgoNetSplitter, NNSED
import classes.utils
import networkx as nx
import IPython


"""
        Methods tried so far require a connected nx.Graph, fail on disconnect or DiGraph
"""

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

    import classes.utils
    classes.utils.save_graph(g, '/tmp/g.dot')
    classes.utils.save_graph(_g, '/tmp/csg.dot')

    clf.fit(ng)
    embeddings = clf.get_embedding()
    classes.utils.pickle_save_py_obj(config, embeddings, 'feather.embeddings')
    IPython.embed()
