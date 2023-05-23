import context
from classes.config import Config
import classes.utils
import dgl
import dgl.function as fn
import torch as th
import torch.nn as nn
import torch.nn.functional as F
from dgl import DGLGraph
from dgl.data import citation_graph as citegrh
from dgl.nn.pytorch import GraphConv
import networkx as nx
import time
import numpy as np
import IPython
import collections
import random
from sklearn.utils.class_weight import compute_class_weight
from dgl.nn.pytorch.glob import AvgPooling

gcn_msg = fn.copy_src(src='h', out='m')
gcn_reduce = fn.mean(msg='m', out='h')

class GCNLayer(nn.Module):
    def __init__(self, in_feats, out_feats):
        super(GCNLayer, self).__init__()
        self.linear = nn.Linear(in_feats, out_feats)

    def forward(self, g, feature):
        # Creating a local scope so that all the stored ndata and edata
        # (such as the `'h'` ndata below) are automatically popped out
        # when the scope exits.
        with g.local_scope():
            g.ndata['h'] = feature
            g.update_all(gcn_msg, gcn_reduce)
            h = g.ndata['h']
            return self.linear(h)


class Net(nn.Module):
    def __init__(self, n_features, n_classes, dropout=0.1):
        super(Net, self).__init__()
        self.layer1     = GCNLayer(n_features, 128)
        self.layerg     = GraphConv(128, 128, activation=F.leaky_relu)
        self.layer2     = GCNLayer(128, 64)
        self.pool       = AvgPooling()
        self.layerg2    = GraphConv(64, 64, activation=F.leaky_relu)
        self.layer3     = GCNLayer(64, n_classes)
        self.dropout    = nn.Dropout(p=dropout)
        self.hdropout    = nn.Dropout(p=0.25)

    def forward(self, g, features):
        x = F.leaky_relu(self.layer1(g, features))
        x = self.dropout(x)
        x = self.layerg(g, x)
        x = self.hdropout(x)
        x = self.layer2(g, x)
        x = self.dropout(x)
        x = self.pool(g, x)
        x = self.hdropout(x)
        x = self.layerg2(g, x)
        x = self.dropout(x)
        x = self.layer3(g, x)
        return x


def load_cora_data():
    data = citegrh.load_cora()
    features = th.FloatTensor(data.features)
    labels = th.LongTensor(data.labels)
    train_mask = th.BoolTensor(data.train_mask)
    test_mask = th.BoolTensor(data.test_mask)
    g = DGLGraph(data.graph)
    return g, features, labels, train_mask, test_mask

def load_desyl_data():
    config      = Config()
    dgl_g       = classes.utils.pickle_load_py_obj(config, 'dgl_g.32')
    features    = th.FloatTensor(dgl_g.ndata['feat'])
    labels      = th.LongTensor(dgl_g.ndata['label'])

    n_rows      = int(max(labels.shape))
    tt_split    = 0.6
    t_rows      = int(n_rows * tt_split)
    ts_rows     = n_rows - t_rows
    #train_mask  = th.cat ( (th.ones( (t_rows,), dtype=th.bool) , th.zeros( (ts_rows,), dtype=th.bool )  ))
    #test_mask   = th.cat ( (th.zeros( (t_rows,), dtype=th.bool) , th.ones( (ts_rows,), dtype=th.bool )  ))


    total   = set(range(n_rows))
    train   = random.sample(range(n_rows), t_rows)
    test    = total - set(train)

    train_mask  = set_to_mask(train, n_rows)
    test_mask   = set_to_mask(test, n_rows)

    #g           = DGLGraph(dgl_g.graph)
    g           = dgl_g
    return g, features, labels, train_mask, test_mask

def set_to_mask(s:set, t:int):
    a   = th.zeros((t,), dtype=th.bool)
    for i in s:
        a[i] = True
    return a


def evaluate(model, g, features, labels, mask):
    model.eval()
    with th.no_grad():
        logits = model(g, features)
        logits = logits[mask]
        labels = labels[mask]
        _, indices = th.max(logits, dim=1)
        correct = th.sum(indices == labels)
        return correct.item() * 1.0 / len(labels)

def class_weightings(labels):
    c           = collections.Counter(labels.tolist())
    ##maximum weighting is 1.0. 1/items may produce very small weightings
    n_classes   = len(c)
    w           = th.zeros((n_classes,), dtype=th.float)
    for i in range(n_classes):
        w[i] = 1.0 / c[i]

    ##rescale to sum to 1.0
    s   = th.sum(w)
    return w / s 

def main():
    #g, features, labels, train_mask, test_mask = load_cora_data()
    g, features, labels, train_mask, test_mask = load_desyl_data()

    #cw  = class_weightings(labels)
    cw  = th.FloatTensor( compute_class_weight('balanced', np.unique(labels.numpy()), labels.numpy()) )
    n_items, n_features = features.shape
    n_classes           = len(np.unique(labels.numpy()))

    net = Net(n_features, n_classes)
    print(net)
    optimizer = th.optim.Adam(net.parameters(), lr=5e-6)
    print("[+] About to train")
    IPython.embed()
    dur = []
    for epoch in range(50):
        if epoch >= 3:
            t0 = time.time()

        net.train()
        logits  = net(g, features)
        logp    = F.log_softmax(logits, 1)
        loss    = F.nll_loss(logp[train_mask], labels[train_mask], weight=cw, reduction='sum')
        #loss    = F.nll_loss(logp[train_mask], labels[train_mask])

        optimizer.zero_grad()
        loss.backward()
        optimizer.step()

        if epoch >= 3:
            dur.append(time.time() - t0)

        acc         = evaluate(net, g, features, labels, test_mask)
        train_acc    = evaluate(net, g, features, labels, train_mask)
        print("Epoch {:05d} | Loss {:.4f} | Train Acc {:.4f} | Test Acc {:.4f} | Time(s) {:.4f}".format(
            epoch, loss.item(), train_acc, acc, np.mean(dur)))

    print("Finished training")
    IPython.embed()

if __name__ == '__main__':
    main()
