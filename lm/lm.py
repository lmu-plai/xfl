# Copyright 2022-2023 Johannes Kinder <johannes.kinder@unibw.de>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
# documentation files (the "Software"), to deal in the Software without restriction, including without limitation the
# rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all copies or substantial portions of
# the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
# THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
# TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

from collections import Counter
from collections import deque
from sklearn.model_selection import train_test_split
from statistics import mean
import time
import sys
import kenlm  # pip install https://github.com/kpu/kenlm/archive/master.zip
import subprocess
import argparse
import re

args = None
model = None


def score(s, **kwargs):
    return model.score(" ".join(s), kwargs)


def greedy_walk(words):
    labels_to_sort = set(words)
    cur = list()
    while len(labels_to_sort) > 0:
        s = max(labels_to_sort, key=lambda x: score(cur + [x], eos=False))
        cur.append(s)
        labels_to_sort.remove(s)
    return cur


def most_likely_permutation(words):
    current_optimum = greedy_walk(words)
    lower_bound = score(current_optimum)
    # print("Heuristic seed:", current_optimum, lower_bound)
    queue = deque()
    queue += ([[x] for x in words])
    steps = 0
    while len(queue) > 0 and steps < args.max_steps:
        steps += 1
        node = queue.pop()
        # print("Processing ", node)
        if len(node) == len(words):
            candidate_score = score(node)
            # print("Evaluating candidate", node, "=", candidate_score)
            if candidate_score > lower_bound:
                # print("New optimum!")
                current_optimum = node
                lower_bound = candidate_score
        else:
            remaining_words = set(words).difference(set(node))
            for child in remaining_words:
                child_score = score(node + [child], eos=False)
                if child_score > lower_bound:
                    # print("Adding ", node + [child], child_score)
                    queue.append(node + [child])
                # else:
                #     print("Discarding branch", node + [child])

    # print("Steps", steps)
    return current_optimum


def load_data(file_name):
    label_split = list()
    label_space = Counter()
    with open(file_name, 'r') as file:
        for line in file:
            line = line.strip()
            try:
                line_number, f_name, label_string = line.split('\t')
            except ValueError:
                continue
            labels = label_string.split('_')
            labels = list(filter(None, labels))
            label_split.append(labels)
            label_space.update(labels)

    print(f'Total number of labels: {len(label_space)}')
    # print('Top labels:', "\n".join([x[0] + ',' + str(x[1]) for x in label_space.most_common(5000)]))
    return label_split


def train_model(training_set):
    print(f"Training LM({args.order}) on {len(training_set)} function names")
    subprocess.run([f'{args.kenlm}/lmplz', '-o', f'{args.order}', '--arpa', args.model],
                   input="\n".join([" ".join(name) for name in training_set]),
                   encoding='ascii')


def main():
    print("Function name language model for sorting tokens, v1.0.")
    print("Copyright 2022-23 Johannes Kinder <johannes.kinder@unibw.de>")

    global args
    global model

    # Argument processing
    def add_arguments(parsers, *p_args, **kwargs):
        for p in parsers:
            p.add_argument(*p_args, **kwargs)

    parser = argparse.ArgumentParser(description='Train and evaluate a language model for function names.',
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    subparsers = parser.add_subparsers(dest='mode', help='choose a mode of operation', required=True)
    parser_train = subparsers.add_parser('train', help='train a language model',
                                         formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser_eval = subparsers.add_parser('eval', help='train and evaluate the language model',
                                        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser_predict = subparsers.add_parser('predict', help='predict function names from token sets on stdin',
                                           formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    add_arguments([parser_eval, parser_train, parser_predict],
                  "--model", help="file to store the model in", metavar="FILE", default="data/function_names.arpa")
    add_arguments([parser_train, parser_eval], "--kenlm",
                  help="path to KenLM binaries (see https://github.com/kpu/kenlm)",
                  metavar="FILE", default='kenlm/build/bin')
    add_arguments([parser_train, parser_eval], "--order", help="order of the language model",
                  choices=[1, 2, 3], default=3, type=int)
    parser_eval.add_argument("--runs", dest="runs_for_mean", help="number of runs to average model evaluation over",
                             default=1, type=int)
    parser_eval.add_argument("--split", dest="train_test", help="training to testing set ratio", default=0.9, type=float)
    add_arguments([parser_eval, parser_predict], "--steps", dest="max_steps",
                  help="maximum number of branch & bound steps", default=1000000, type=int)
    add_arguments([parser_train, parser_eval], "--dataset", help="dataset file", metavar="FILE",
                  default='data/labels.txt')
    args = parser.parse_args()

    # Argument processing ends

    start_time = time.time()

    # Predict individual function names from stored model
    if args.mode == 'predict':
        model = kenlm.LanguageModel(args.model)
        print("Finished loading, waiting on input from stdin. Use spaces or _ to separate tokens. End with Ctrl-D.")
        for function_name in sys.stdin:
            result = most_likely_permutation(re.split(r'\s|_', function_name.rstrip()))
            print(f"{function_name} => {'_'.join(result)} ({score(result)})")
    else:
        print(f"Loading data from {args.dataset}")
        label_list = load_data(args.dataset)

        # Train a new model
        if args.mode == 'train':
            print("Training new model from full dataset")
            train_model(label_list)
        # Evaluate model over multiple train / test splits
        elif args.mode == 'eval':
            print(f"Evaluating model performance over {args.runs_for_mean} train/test splits with ratio {args.train_test}")
            accuracies = list()
            for i in range(0, args.runs_for_mean):
                training_set, testing_set = train_test_split(label_list, train_size=args.train_test, shuffle=True)
                train_model(training_set)
                model = kenlm.LanguageModel(args.model)

                print(f"Evaluating on {len(testing_set)} function names")
                correct = count = 0
                for labels in testing_set:
                    unique_labels = set(labels)
                    result = most_likely_permutation(unique_labels)
                    if labels == result:
                        correct += 1
                    count += 1
                    if count % 1000 == 0:
                        print(f"n = {count:5}, acc = {correct / count:.3}")

                print(f"--- {time.time() - start_time:.2f} seconds elapsed ---")
                print(f"LM({args.order}) got {correct} out of {count} correct, "
                      f"accuracy = {correct / count:.3}, max steps = {args.max_steps}")
                accuracies.append(correct / count)

            print(f"Mean accuracy over {args.runs_for_mean} runs is {mean(accuracies):.4}")

    print(f"--- {time.time() - start_time:.2f} seconds elapsed ---")
    print("Done.")


if __name__ == "__main__":
    main()
