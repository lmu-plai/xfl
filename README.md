# XFL: Naming Functions in Binaries with Extreme Multi-label Learning

This repository will contain the code accompanying the paper [_XFL: Naming Functions in Binaries with Extreme Multi-label Learning_](https://arxiv.org/abs/2107.13404) by James Patrick-Evans, Moritz Dannehl and Johannes Kinder, which will be presented at the [IEEE Symposium on Security & Privacy 2023](https://sp2023.ieee-security.org/index.html). 

## Overview

The repository currently contains the following components:

* `lm/` Language model for generation function names from lists of predicted tokens
* `xfl/` Partial source code and full experiment data used in our paper

To generate embeddings from symbols in binaries as a service, please use the [reait](https://github.com/RevEngAI/reait) tool.


## Citation
Please cite the paper as
```
@inproceedings{oakland23-xfl,
  author      = {James Patrick-Evans and Moritz Dannehl and Johannes Kinder},
  title       = {{XFL}: Naming Functions in Binaries with Extreme Multi-label Learning},
  booktitle   = {Proc. IEEE Symp. Security and Privacy (S\&P)},
  pages       = {1677-1692},
  publisher   = {IEEE},
  year        = {2023},
  doi         = {10.1109/SP46215.2023.00096},
}
```
