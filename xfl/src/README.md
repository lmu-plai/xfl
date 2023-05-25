To split symbol names into labels, use `symbolnlp.py`, e.g.,


```
from symbolnlp import SymbolNLP

nlp = SymbolNLP()

nlp.canonical_set('init_networkfile') # { 'init', 'network', 'file' }
nlp.wordnet_similarity('freed_network', 'free_networking')
nlp.canonical_name('initnetworktruebase')  # 'init_network_true_base'
nlp.check_word_similarity('init_network', 'initialised_networked') # True
```
