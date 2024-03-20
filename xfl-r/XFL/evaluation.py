
"""

Copyright 2017-2024 by James Patrick-Evans, Moritz Dannehl, Tristan Benoit, and Johannes Kinder.

This file is part of XFL.

XFL is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

XFL is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with XFL. If not, see <https://www.gnu.org/licenses/>. 

"""

import utils
import numpy as np
import tqdm

class Evaluation():
    """
        Class to calculate evaluation meterics for an experiment
    """

    @staticmethod
    def f1(tp, tn, fp, fn):
        return utils.calculate_f1(tp, tn, fp, fn)

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

        for i in range(len(rz)):
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

        for i in range(len(rz)):
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

        for i in range(len(rz)):
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
            #self.logger.error("Error, IDCG is 0.0 -> function with no labels!")
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
