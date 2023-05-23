import os, sys
import copy
import numpy as np
import binascii
import context
import functools
import tqdm
import shlex, shutil
import json
import collections
import classes.utils
import classes.config
import classes.experiment
from classes.experiment import CCSResult
import classes.NLP
from classes.database import PostgresDB
from IPython import embed
import pandas as pd
import math
from sklearn.model_selection import train_test_split
import scipy
import scipy.sparse
import itertools
import gc
from joblib import Parallel, delayed
from tempfile import mkdtemp 
import subprocess
from sys import exit

def plot_freq_distribution(xml, names):
    ##script generates the necessary python objets for use in src/visualizations/dataset-analysis.py
    c = collections.Counter(names)
    names, func_counts = zip(*c.most_common())

    label_counts = xml.Y.sum(axis=0).values
    return func_counts, label_counts

class PfastreXML():

    @staticmethod
    def count_tokens(it_tok_it):
        config = classes.config.Config()
        nlp    = classes.NLP.NLP(config)
        #symbol2labels = classes.utils.pickle_load_py_obj(config, '

        canonical_set = []
        c = collections.Counter()
        for tok_it in it_tok_it:
            cs = nlp.canonical_set(tok_it)
            c.update(cs)
            canonical_set.append(cs)
        return canonical_set, c

    @staticmethod
    def name_vector(canonical_sets, L):
        config = classes.config.Config()
        exp = classes.experiment.Experiment(config)
        exp.ml_name_vector = L
        exp.ml_name_vector_dims = len(L)
        return list(map(lambda x, c=exp.to_vec: c('ml_name_vector', x), canonical_sets))

    @staticmethod
    def train_test_pfastrexml(data_dir, trn_X_fname, trn_Y_fname, tst_X_fname, a=1.0, b=1.0, c=1.0, max_inst_in_leaves=10, l=100, g=30, T=64, trees=256, pfast_dir="/root/XML/Tree_Extreme_Classifiers/PfastreXML/"):
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
        print("Running new PfastreXML instance under data directory: ", data_dir)
        trn_cmd = pfast_dir + "/PfastreXML_train " + "{}/{} {}/{} {}/inv_prop.txt {}/xml_model ".format(data_dir, trn_X_fname, data_dir, trn_Y_fname, data_dir, data_dir)
        trn_cmd += "-q 0 -S 0 -T {} -t {} -a {} -b {} -c {} -m {} -g {} -l {}".format(T, trees, a, b, c, max_inst_in_leaves, g, l)
        model_dir = "{}/xml_model".format(data_dir)
        if os.path.exists(model_dir):
            ##empty directory contents
            print("Clearing previous model...")
            shutil.rmtree(model_dir)

        os.makedirs(model_dir, exist_ok=True)

        print("Running: ", trn_cmd)
        res = subprocess.call(shlex.split(trn_cmd), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if res < 0:
            raise RuntimeError("Error calling PfastreXML subprocess during training")

        tst_cmd = pfast_dir + "/PfastreXML_predict {}/{} {}/xml_score.mat {}/xml_model".format(data_dir, tst_X_fname, data_dir, data_dir)
        print("Running: ", tst_cmd)
        res = subprocess.call(shlex.split(tst_cmd), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if res < 0:
            raise RuntimeError("Error calling PfastreXML subprocess during prediction")

    def __init__(self, config, embeddings='dexter'):
        """
            XML classifier
        """
        classes.utils._desyl_init_class_(self, config)
        self.exp        = classes.experiment.Experiment(config)
        self.nlp        = classes.NLP.NLP(config)
        self.directory  = mkdtemp(prefix='desyl-pfastrexml-')
        self.embeddings = embeddings
        # write config to folder
        with open(self.directory + '/embedding_mode', 'w') as f:
            f.write(f"{self.embeddings}\n")

    def __fini__(self):
        #don't clean results files on exit
        #self.directory.cleanup()
        pass

    def fromData(self, names, embeddings, k=512, df=None):
        self.logger.info("Generating label space for top {} labels...".format(k))
        self.L       = self.generate_label_space(names, k=k)
        #self.logger.info("Loading label space for top {} labels...".format(k))
        #self.L                = self.exp.load_experiment_key(f'M={self.embeddings}:L={k}')


        self.logger.info("Parsing embeddings and labels...")
        self.generate_dataframe(names, embeddings, df=df)

        #copy over to experiment settings
        self.exp.ml_name_vector = self.L
        self.exp.ml_name_vector_dims = len(self.L)

        self.logger.info("Saving label space to database for current config")
        self.exp.update_experiment_key('M={}:L={}'.format(EMBED_MODE, k), self.L)

        self.logger.info("Calculating inverse propensities...")
        self.inv_propensities(A=0.5, B=0.4)
        self.logger.info("Saving to XML txt format...")
        self.saveXMLdata()


        #save pandas dataframes
        for k in tqdm.tqdm([ "{}_{}".format(b, e) for b in ('trn', 'val', 'tst') for e in ('X', 'Y') ] + [ "name_df" ], desc="Saving model data"):
            value = getattr(self, k)
            value.to_pickle("{}/{}.pickle".format(self.directory, k))

    def generate_dataframe_from_list(self, names, embeddings):
        """
            Generate a pandas dataframe given a list of
            function names and a list of their embeddings
        """
        assert(isinstance(names, list))
        assert(isinstance(embeddings, list))
        assert(len(names) == len(embeddings))
        assert(len(names) > 0)
        assert(isinstance(names[0], str))
        assert(isinstance(embeddings[0], list))
        L = len(embeddings[0])
        assert all(len(x) == L for x in embeddings)

        gc.collect()


        #data = { 'name': names, 'embeddings': embeddings }
        self.df = pd.DataFrame(data=zip(names, embeddings), columns=['name', 'embedding'])
        self.df.to_csv('{}/df.csv'.format(self.directory))
        print('written df.csv')
        ##expand embedding from list to column
        entries = list(map(lambda x, y: [x] + y, names, embeddings))
        self.edf = pd.DataFrame(entries)
        self.edf.rename(columns={0:'name'}, inplace=True)
        self.edf.to_csv('{}/edf.csv'.format(self.directory))

        labels = list(map(lambda x, c=self.nlp.canonical_set, v=self.exp.to_vec: v('ml_name_vector', c(x)), names))

        self.X = pd.DataFrame(data=embeddings)
        self.Y = pd.DataFrame(data=labels)

        ##train test split
        #self.trn_X, self.tst_X = train_test_split(self.X)
        #self.trn_Y, self.tst_Y = train_test_split(self.Y)

        #self.trn_X, self.tst_X, self.trn_Y, self.tst_Y = train_test_split(self.X, self.Y)
        test_only_names = set(classes.utils.read_file_lines('/root/desyl/res/unique-test-names.txt'))
        print("Split dataset to train and test names")
        embed()
        exit()



    def generate_dataframe(self, names, embeddings, df=None):
        """
            Generate a pandas dataframe given a list of
            function names and a list of their embeddings
        """
        l_index = None
        if not isinstance(df, type(None)):
            l_index = df.index

        self.name_df         = pd.DataFrame(names, columns=['name'], index=l_index)
        self.name_df.to_pickle('{}/name_df'.format(self.directory))

        if classes.utils.is_scipy_sparse(embeddings):
            embeddings = embeddings.todense()

        embeddings_df   = pd.DataFrame(embeddings, columns=['embedding'], index=l_index)

        #BUG: need to regenerate dataset if label size changes
        #label size needs to change otherwise propensities of labels differs
        while True:
            print("Regenerating dataset")
            #labels = list(map(lambda x, c=self.nlp.canonical_set, v=self.exp.to_vec: v('ml_name_vector', c(x)), names))
            chunks = classes.utils.n_chunks(self.canonical_sets, 256)
            results = Parallel(n_jobs=126, verbose=1, backend="multiprocessing")(map(delayed(PfastreXML.name_vector), chunks, itertools.repeat(self.L)))
            labels = functools.reduce(lambda x, y: x + y, results, [])
            labels_mat = np.vstack(labels)

            self.Y = pd.DataFrame(data=labels_mat, index=l_index)
            self.X = embeddings_df

            ##split into known parts if we have df
            if not isinstance(df, type(None)):
                print("Generating dataset from predetermined experiment split (expriment II)")
                dd           = classes.utils.load_py_obj(config, 'IEEESP_experiment_binaries_split')
                #nd           = classes.utils.load_py_obj(config, 'nero_dataset')

                #ndd          = classes.utils.load_py_obj(config, 'non_debian_dataset')
                #ondd          = classes.utils.load_py_obj(config, 'optimised_non_debian_dataset')
                #dndd          = classes.utils.load_py_obj(config, 'debian_non_debian_dataset')
                #nero_test_bins  = set(map(lambda x: x.split('__')[-1], nd['test']))

                training    = dd['train']
                validation  = dd['val']
                testing     = dd['test']

                ##below is incorrect
                self.trn_X  = self.X[self.X.index.isin(df.loc[df['b_path'].isin(training)].index)]
                self.val_X  = self.X[self.X.index.isin(df.loc[df['b_path'].isin(validation)].index)]
                self.tst_X  = self.X[self.X.index.isin(df.loc[df['b_path'].isin(testing)].index)]

                self.trn_Y  = self.Y[self.Y.index.isin(df.loc[df['b_path'].isin(training)].index)]
                self.val_Y  = self.Y[self.Y.index.isin(df.loc[df['b_path'].isin(validation)].index)]
                self.tst_Y  = self.Y[self.Y.index.isin(df.loc[df['b_path'].isin(testing)].index)]
            else:
                #90:5:5 train:validation:test
                print("Generating dataset from random split")
                self.trn_X, test_x, self.trn_Y, test_y          = train_test_split(self.X, self.Y, train_size=0.9 )
                self.val_X, self.tst_X, self.val_Y, self.tst_Y  = train_test_split(test_x, test_y, train_size=0.5 )


            ##filter dataset and remove calculatable knowns
            print("Filtering out calculatable knowns and common functions")
            if not isinstance(df, type(None)):
                self.trn_X  = self.trn_X[~self.trn_X.index.isin(df.loc[df['name'].isin(classes.crf.CRF.calculable_knowns)].index)]
                self.val_X  = self.val_X[~self.val_X.index.isin(df.loc[df['name'].isin(classes.crf.CRF.calculable_knowns)].index)]
                self.tst_X  = self.tst_X[~self.tst_X.index.isin(df.loc[df['name'].isin(classes.crf.CRF.calculable_knowns)].index)]
                self.trn_Y  = self.trn_Y[~self.trn_Y.index.isin(df.loc[df['name'].isin(classes.crf.CRF.calculable_knowns)].index)]
                self.val_Y  = self.val_Y[~self.val_Y.index.isin(df.loc[df['name'].isin(classes.crf.CRF.calculable_knowns)].index)]
                self.tst_Y  = self.tst_Y[~self.tst_Y.index.isin(df.loc[df['name'].isin(classes.crf.CRF.calculable_knowns)].index)]

            else:
                self.trn_X  = self.trn_X[~self.trn_X.index.isin(self.trn_X.loc[self.name_df['name'].isin(classes.crf.CRF.calculable_knowns)].index)]
                self.trn_Y  = self.trn_Y[~self.trn_Y.index.isin(self.trn_Y.loc[self.name_df['name'].isin(classes.crf.CRF.calculable_knowns)].index)]
                self.val_X  = self.val_X[~self.val_X.index.isin(self.val_X.loc[self.name_df['name'].isin(classes.crf.CRF.calculable_knowns)].index)]
                self.val_Y  = self.val_Y[~self.val_Y.index.isin(self.val_Y.loc[self.name_df['name'].isin(classes.crf.CRF.calculable_knowns)].index)]
                self.tst_X  = self.tst_X[~self.tst_X.index.isin(self.tst_X.loc[self.name_df['name'].isin(classes.crf.CRF.calculable_knowns)].index)]
                self.tst_Y  = self.tst_Y[~self.tst_Y.index.isin(self.tst_Y.loc[self.name_df['name'].isin(classes.crf.CRF.calculable_knowns)].index)]

    
            Ln  = len(self.L)
            #apply dataset preconditioning/prefiltering
            self.trn_X, self.trn_Y, self.L = xml.precondition_dataset(self.trn_X, self.trn_Y, self.L)

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
        #print("Generating canonical sets")
        #mod_res = list(map(lambda x, nlp=self.nlp: nlp.canonical_set(x), names))
        chunks = classes.utils.n_chunks(names, k)

        #print("Counting labels")
        c = collections.Counter()
        results = Parallel(n_jobs=64, verbose=1, backend="multiprocessing")(map(delayed(PfastreXML.count_tokens), chunks))
        self.canonical_sets = []
        for s_canonical_set, s_counter in results:
            c += s_counter
            self.canonical_sets += s_canonical_set

        #for r in tqdm.tqdm(mod_res, desc='Counting tokens'):
        #    c.update(r)
        
        c_tok_k, c_tok_v = zip(*c.most_common(k))
        res = list(c_tok_k)
        return res

    def inv_propensities(self, A=3.0, B=0.5):
        """
            calculate inverse propensity scores
             P(y_t = 1 | y^*_t = 1)

             N      :: The size of the dataset
             N_t    :: The number of data points annotated with label l
             A, B   :: Hyperparameters
        """
        N, L = self.trn_Y.shape
        # L is dimensions of label space
        C = (np.log(N) - 1)*np.power((B + 1), A)

        self.inv_props = np.zeros((L, ), dtype=float)
        for t in tqdm.tqdm(range(L), desc="Calculating inverse propensities"):
            N_t = self.trn_Y[t].sum()
            exp_t = np.exp(-A * np.log(N_t + B))
            i_pt = 1.0 + (C * exp_t)
            self.inv_props[t] = i_pt

    def write_XML_txt(self, V, fname, shape=None):
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
        self.write_XML_txt(self.trn_Y, self.directory+"/"+trn_fname)
        self.write_XML_txt(self.tst_Y, self.directory+"/"+tst_fname)
        self.write_XML_txt(self.val_Y, self.directory+"/"+val_fname)

    def write_features(self, trn_fname='trn_X.txt', tst_fname='tst_X.txt', val_fname='val_X.txt'):
        ind, row = next(self.X.iterrows())
        embed_len = row['embedding'].shape[0]
        self.write_XML_txt(self.trn_X, self.directory+"/"+trn_fname, shape=(len(self.trn_X), embed_len))
        self.write_XML_txt(self.tst_X, self.directory+"/"+tst_fname, shape=(len(self.tst_X), embed_len))
        self.write_XML_txt(self.val_X, self.directory+"/"+val_fname, shape=(len(self.val_X), embed_len))

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
        m       = self.read_XML_txt(self.directory+"/"+score_m_fname)
        ml_Y    = np.zeros(m.shape)
        for i, row in enumerate(m):
            above_thresh                = np.where(row > threshold)
            ranked                      = np.argsort(row)[::-1]
            ranked_ind_above_threshold  = ranked[:len(above_thresh[0])]

            for p in ranked_ind_above_threshold:
                ml_Y[i, p]  = 1

            predicted_labels = list(map(lambda x: self.L[x], ranked_ind_above_threshold))
            predicted_name    = '_'.join(predicted_labels)

            # tst_X or tst_Y can be used here, 
            # getting the index of the dataframe to lookup function name
            func_index = self.tst_X.index[i]
            func_name   = self.name_df['name'][func_index]

            fmt = "{: <18} => {: <18}".format(func_name, predicted_name)
            print(fmt)

        return ml_Y

    def ml_scores(self, threshold=0.215, CALC_KNOWNS=False, REMOVE_CALC=True):
        eval = classes.experiment.Evaluation(self.config)
        pred_Y  = self.predict_labels(threshold=threshold)
        true_Y  = self.tst_Y.values

        if CALC_KNOWNS:
            ##assume we know calculable knowns
            for i, (ind,row) in enumerate(self.tst_Y.iterrows()):
                true_name   = self.name_df['name'][ind]
                if true_name in classes.crf.CRF.calculable_knowns:
                    pred_Y[i, :] = true_Y[i, :]

        if REMOVE_CALC:
            delete_row_inds = []
            ##assume we know calculable knowns
            for i, (ind,row) in enumerate(self.tst_Y.iterrows()):
                true_name   = self.name_df['name'][ind]
                if true_name in classes.crf.CRF.calculable_knowns:
                    delete_row_inds.append(i)

            pred_Y  = np.delete(pred_Y, delete_row_inds, 0)
            true_Y  = np.delete(true_Y, delete_row_inds, 0)

        ml_p    = eval.ml_precision(true_Y, pred_Y)
        ml_r    = eval.ml_recall(true_Y, pred_Y)
        ml_f1   = eval.ml_f1(ml_p, ml_r)

        print("Micro Avgs :: Precision:{}, Recall:{} F1:{}".format(ml_p, ml_r, ml_f1))

        mac_ml_p    = eval.ml_precision(true_Y, pred_Y, MODE='MACRO')
        mac_ml_r    = eval.ml_recall(true_Y, pred_Y, MODE='MACRO')
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
            'macro_f1'  : macro_avg_ml_f1
        }
        res = CCSResult(config, experiment_results, self.embeddings, False, len(self.L), 'train', 'test')
        res.save()
        return ml_f1



    @staticmethod
    def opt_predict_labels(threshold, m, eval, tst_Y):
        print("threshold", threshold)
        ml_Y    = np.zeros(m.shape)
        for i, row in enumerate(m):
            above_thresh                = np.where(row > threshold)
            ranked                      = np.argsort(row)[::-1]
            ranked_ind_above_threshold  = ranked[:len(above_thresh[0])]

            for p in ranked_ind_above_threshold:
                ml_Y[i, p]  = 1

        pred_Y  = ml_Y 
        true_Y  = tst_Y.values
        ml_p    = eval.ml_precision(true_Y, pred_Y)
        ml_r    = eval.ml_recall(true_Y, pred_Y)
        ml_f1   = eval.ml_f1(ml_p, ml_r)
        
        #m_ml_f1  = ml_f1[np.isfinite(ml_f1)]
        #macro_avg_ml_f1 = np.mean(m_ml_f1)
        print("F1:{}".format(ml_f1))
        return -ml_f1

    def opt_f1(self):
        self.logger.info("Ranking labels against TEST set")
        m = self.read_XML_txt(self.directory+"/xml_score.mat")
        eval = classes.experiment.Evaluation(self.config)
        x0 = np.array([0.3])
        res = scipy.optimize.minimize(PfastreXML.opt_predict_labels, x0, args=(m, eval, self.tst_Y))
        print(res)
        embed()

    def evaluate(self, score_m_fname='xml_score.mat', CALC_KNOWNS=True):
        m = self.read_XML_txt(self.directory+"/"+score_m_fname)
        xml_eval = classes.experiment.Evaluation(self.config)
        cgs, dcgs, ndcgs = [], [], []

        np_tst_Y    = self.tst_Y.to_numpy()
        delete_row_inds = []
        for i, row in enumerate(m):
            true_labels = np_tst_Y[i,:]
            our_predict = row

            func_index = self.tst_X.index[i]
            func_name   = self.name_df['name'][func_index]

            if CALC_KNOWNS:
                if func_name in classes.crf.CRF.calculable_knowns:
                    our_predict = true_labels
                    np_tst_Y[i, :] = true_labels

            p       = 5
            cg      = xml_eval.cumulative_gain(true_labels, our_predict, p=p)
            dcg     = xml_eval.discounted_cumulative_gain(true_labels, our_predict, p=p)
            ndcg    = xml_eval.normalised_discounted_cumulative_gain(true_labels, our_predict, p=p)

            pred_top_n = np.argsort(our_predict)[::-1][:p]
            corr_top_n = np.argsort(true_labels)[::-1][:p]
            pred_labels = tuple(map(lambda x, L=self.L: L[x], pred_top_n))
            corr_labels = tuple(map(lambda x, L=self.L: L[x], corr_top_n))

            print("{:<40} :: N={}, TL={}, PL={}, Cumulative Gain: {:>2}, Discounted Cumulative Gain: {:>7}, Normalised Discounted Cumulative Gain: {:>7}".format(
                func_name, p, corr_labels, pred_labels, cg, dcg, ndcg
            ))
            print("\t{:<40}->{:<40}".format(func_name, '_'.join(pred_labels)))
            cgs.append(cg)
            dcgs.append(dcg)
            ndcgs.append(ndcg)

        acg     = np.mean(cgs)
        adcg    = np.mean(dcgs)
        andcg   = np.mean(ndcgs)


        ### geometric mean
        print("N={} :: Mean CG: {:>7}, Mean DCG: {:>7}, Mean NDCG: {:>7}".format(p, acg, adcg, andcg))
        pr       = xml_eval.precision_at_ks(np_tst_Y, m)
        print("Precesion @n:")
        print(pr)

        print("Saving exeriment result to database")
        experiment_results = {
            'precison@' : pr,
            'N'         : p,
            'cg'        : acg,
            'dcg'       : adcg,
            'ndcg'      : andcg
        }
        res = CCSResult(config, experiment_results, self.embeddings, False, len(self.L), 'train', 'test')
        res.save()
 

    def score_model(self, true_Y, score_m_fname='xml_score.mat', CALC_KNOWNS=True):
        """
            Provide a numercial score for the model + predictions
            Currently averages the NDCG
        """
        m           = self.read_XML_txt(self.directory+"/"+score_m_fname)
        xml_eval    = classes.experiment.Evaluation(self.config)
        ndcgs       = []
        p           = 5
        #np_tst_Y    = self.tst_Y.to_numpy()
        np_true_Y   = true_Y.to_numpy()

        for i, row in enumerate(m):
            true_labels = np_true_Y[i,:]
            our_predict = row

            func_index  = true_Y.index[i]
            func_name   = self.name_df['name'][func_index]

            if CALC_KNOWNS:
                if func_name in classes.crf.CRF.calculable_knowns:
                    our_predict     = true_labels

            ndcg    = xml_eval.normalised_discounted_cumulative_gain(true_labels, our_predict, p=p)
            ndcgs.append(ndcg)

        return np.mean(ndcgs)


    @staticmethod
    def opt_score_func(x, self, sg_y):
        A, B = x
        print(A, B)
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
        x       = self.trn_Y.sum(axis=0).tolist()
        sg_x    = np.linspace(-5, 5, 26)
        #sg_x    = np.linspace(-6, 6, len(x))
        sg_y    = np.array(list(map(lambda a, f=sigmoid_f: f(a), sg_x)))

        #lin_x    = np.geomspace(min(x), max(x), len(x))
        #my = list(map(lambda a: 1.0/a, y))

        ##optimize distance between sg_y and my
        x0  = np.array([[0.4, 0.5]])
        #con = { 'type': 'ineq', 'fun': lambda x: x[0] > 0 and x[1] > 0 }
        bnds = ((0, 100), (0, 100))
        res = scipy.optimize.minimize(PfastreXML.opt_score_func, x0, args=(self, sg_y), bounds=bnds)
        print(res)
        embed()
        


    def precondition_dataset(self, X:pd.DataFrame, Y:pd.DataFrame, L:list):
        """
            Apply preconditions to dataset.

                i)  Remove labels with only a single data point (impossible to learn and test)
                ii) Remove data points with no labels

            WARNING: Will modify label set
        """
        ##only select colums where we have atleast min_samples samples
        min_samples = 3
        c1          = Y.sum(axis=0) > min_samples
        c2          = np.where(c1 == True)[0]
        Y      = Y[c2]
        print("Selected", len(c2), "labels")

        l   = np.array(L)
        L  = l[c2].tolist()

        """
            Now trim rows to have at least 1 label
        """
        #axis=1 is rows, only select rows where we have at least 1 label
        Y  = Y.loc[Y.sum(axis=1) > 0]
        #select rows in X that correspond to the new Y
        X  = X.loc[Y.index]
        print("We now have", len(X), "rows of data")

        return X, Y, L

    def load_model(self, model_dir):
        """
            load model stored in self.directory
        """
        self.directory    = model_dir
        for k in tqdm.tqdm([ "{}_{}".format(b, e) for b in ('trn', 'val', 'tst') for e in ('X', 'Y') ] + [ "name_df" ], desc="Loading model data"):
            value = pd.read_pickle("{}/{}.pickle".format(self.directory, k))
            setattr(self, k, value)

        self.L = list(map(lambda x: x.split(':')[1], classes.utils.read_file_lines("{}/labels.txt".format(self.directory))))
        self.inv_props = list(map(lambda x: float(x), classes.utils.read_file_lines("{}/inv_prop.txt".format(self.directory))))

    def predict(self, embeddings):
        """
            Predict labels from embeddings and loaded model
        """
        tmp_fname = 'tmp-embeddings-file.txt'
        self.write_XML_txt(self.embeddings, self.directory+tmp_fname)

        pfast_dir="/root/XML/Tree_Extreme_Classifiers/PfastreXML/"
        data_dir = self.directory

        tst_cmd = pfast_dir + "/PfastreXML_predict {}/{} {}/xml_score.mat {}/xml_model".format(data_dir, tmp_fname, data_dir, data_dir)
        print("Running: ", tst_cmd)
        res = subprocess.call(shlex.split(tst_cmd), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if res < 0:
            raise RuntimeError("Error calling PfastreXML subprocess during prediction")

        print("Done")


def usage():
    print("""
    Usage: ./src/classes/pfastrexml.py {{L}} {{embedding}}

        {{L}} Label space size
        {{embedding}} Embeddings to use
    """)
    exit()


if __name__ == '__main__':
    """
    Example inputs:

        names       = ['memset', 'memcpy', 'malloc', 'realloc', 'calloc']
        embeddings  = [[0, 1, 2, 3], [1, 2, 3, 4],
                    [3, 4, 3, 3],
                    [3, 4, 3, 4],
                    [3, 4, 2, 3],
                ]
    """
    ###
    MODE_EVAL_MODEL     = False
    MODEL_DIR           = '/tmp/desyl-pfastrexml-9u4mfsu6'
    EXTERNAL_EMBEDDINGS = False
    #EMBED_MODE          = 'xfl'
    #EMBED_MODE          = 'palmtree_gemini'
    #EMBED_MODE          = 'palmtree_gemini_128'
    #EMBED_MODE          = 'safe'
    #EMBED_MODE          = 'safe2'
    #EMBED_MODE          = 'asm2vec'
    #EMBED_MODE          = 'dexter'
    #EMBED_MODE          = 'palmtree_avg'
    ###

    if len(sys.argv) < 3:
        usage()

    EMBED_MODE = sys.argv[2]

    config  = classes.config.Config()
    xml = PfastreXML(config, embeddings=EMBED_MODE)
    db  = PostgresDB(config)
    config.logger.info("Connecting to database...")
    db.connect()
    config.logger.info("Connected to database!")

    if MODE_EVAL_MODEL:
        print("Loading model data from", MODEL_DIR)
        xml.load_model(MODEL_DIR)
        #xml.evaluate()
        #r = xml.ml_scores()
        #print(r)
        embed()
        #xml.rank_labels()
        exit()


    if EXTERNAL_EMBEDDINGS:
        #data = classes.utils.load_py_obj(config, "function_names_embeds_dataset_I_30092020")
        data = classes.utils.read_file_lines("/root/dexter_2022.csv")
        names, embeddings, binaries = [], [], []
        for line in tqdm.tqdm(data, desc="Reading text file"):
            try:
                #l_meta, l_data = line.split(";")
                #binary, function = l_meta.split("::")
                name, q_vector, q_embedding, c_embedding = line.split('\t')
                names.append(name)

                #py_embedding = classes.utils.py_obj_from_bytes_fast(binascii.unhexlify(embedding[3:]))
                q_vector = classes.utils.py_obj_from_bytes_fast(binascii.unhexlify(q_vector[3:]))
                q_embedding = classes.utils.py_obj_from_bytes_fast(binascii.unhexlify(q_embedding[3:]))
                c_embedding = classes.utils.py_obj_from_bytes_fast(binascii.unhexlify(c_embedding[3:]))
                embeddings.append(np.hstack([q_vector, c_embedding]).reshape(-1))

            except: 
                pass


            #arr = np.array(json.loads(l_data))
            #names.append(xml.nlp.strip_library_decorations(function))
            #embeddings.append(arr)
            #binaries.append(binary)
        #_names, _embeddings = zip(*data)
        #names       = list(map(lambda x: x.split('::')[1], _names))
        #embeddings  = list(map(lambda x: x.tolist(), _embeddings))
        #embeddings = np.asarray(embeddings).reshape(-1)

        z = np.empty(len(embeddings), dtype=object)
        z[:] = embeddings[:]
        embeddings = z

    else:
        config.logger.info("Fetching embeddings...")
        df = pd.DataFrame(db.get_embeddings(EMBED_MODE), columns=['id', 'name', 'b_name', 'b_path', 'embedding']).set_index('id')
        #ensure embedding is an array, not matrix
        df['embedding'] = df['embedding'].apply(lambda x: x.reshape(-1))

        #ratio = 1.0
        #config.logger.warning("Subsampling to {:.2f}% of the full dataset!".format(float(ratio*100)))
        #df = df.sample(frac=ratio)

        names       = df['name'].values
        embeddings  = df['embedding'].values
        """
            NB: scipy.sparse.vstack != np.vstack, if stacking sparse matracies, need to use scipy.sparse.vstack
        """

    config.logger.info("Using {} embeddings!".format(EMBED_MODE))
    L   = int(sys.argv[1])
    config.logger.info("Using top {} labels!".format(L))
    #embed()
    #exit()

    xml.fromData(names, embeddings, k=L, df=df)
    #xml.fromData(names, embeddings, k=L)
    PfastreXML.train_test_pfastrexml(xml.directory, 'trn_X.txt', 'trn_Y.txt', 'tst_X.txt', trees=256, T=120, a=1.0, g=30)
    xml.evaluate()
    r = xml.ml_scores()
    print("Result:", r)
    embed()
    exit()

    #xml.update_propensities(2.25, 0.3)
    embed()
    exit()

    """
    #xml.fromData(names, embeddings, k=L, df=df)
    xml.fromData(names, embeddings, k=L)
    print("Tuning PfastreXML Hyperparameters")
    n_search = 8
    ab, bb = -1, -1
    res = np.zeros((n_search, n_search), dtype=float)
    for ai, a in enumerate(np.linspace(0.75, 1.1, num=n_search)):
        for bi, b in enumerate(np.linspace(25, 35, num=n_search)):
            gc.collect()
            #print("Training with a={}, b={}".format(a, b))
            #xml.update_propensities(a, b)
            PfastreXML.train_test_pfastrexml(xml.directory, 'trn_X.txt', 'trn_Y.txt', 'val_X.txt', trees=128, T=128, a=a, g=b)
            r = xml.score_model(xml.val_Y)
            print("Model result:", r)
            if r > np.max(res):
                print("Updating new maxima!")
                ab = a
                bb = b
            res[ai, bi] = r

    #save grid search results
    classes.utils.save_py_obj(config, res, 'res.gridsearch')

    print("Finished gridsearch of inverse propensities")
    embed()
    """
