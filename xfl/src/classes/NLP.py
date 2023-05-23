import os, sys
# external regex library, supports overlapping
import regex as re
import enchant, functools, itertools
import nltk, math, copy
from nltk.corpus import wordnet as wn
from threading import Lock
from intervaltree import Interval, IntervalTree
import numpy as np
import itertools
from functools import reduce
from IPython import embed

import context
import classes.utils
import classes.config

class NLP:

    def __init__(self, config):
        classes.utils._desyl_init_class_(self, config)
        self.enchant_lock = Lock()

        self.us_D = enchant.Dict("en_US")
        self.gb_D = enchant.Dict("en_GB")

        #regexes
        self.underprefix    = re.compile(r'^_+')
        self.undersuffix    = re.compile(r'_+$')
        self.bitssuffix     = re.compile(r'(32|64)$')
        self.bitsprefix     = re.compile(r'^(32|64)')

        self.r2_prefix      = re.compile(r'^sym\.')
        self.r2_dyn_prefix  = re.compile(r'^sym\.imp\.')

        self.ida_dyn_prefix = re.compile(r'^__imp_')

        self.isra           = re.compile(r'\.isra(\.\d*)*')
        self.part           = re.compile(r'\.part(\.\d*)*')
        self.constprop      = re.compile(r'\.constprop(\.\d*)*')
        self.constp         = re.compile(r'\.constp(\.\d*)*')

        self.libc           = re.compile(r'libc\d*')
        self.sse2           = re.compile(r'_sse\d*')
        self.ssse3          = re.compile(r'_ssse\d*')
        self.avx            = re.compile(r'avx\d*')
        self.cold           = re.compile(r'\.cold$')

        self.unaligned      = re.compile(r'unaligned')
        #self.internal = re.compile(r'internal')
        self.erms           = re.compile(r'erms')
        self.__ID__         = re.compile(r'_+[A-Z]{1,2}_+')

        self.dot_prefix     = re.compile(r'^\.+')
        self.dot_suffix     = re.compile(r'\.+$')
        self.num_suffix     = re.compile(r'_+\d+$')
        self.num_prefix     = re.compile(r'^\d+_+')
        self.dot_num_suffix = re.compile(r'\.+\d+$')
        self.num_only_prefix = re.compile(r'^\d+')
        self.num_only_suffix = re.compile(r'\d+$')

        self.repeated_nonalpha = re.compile(r'([^a-zA-Z0-9\d])\1+')

        self.ida_import     = re.compile(r'__imp_')
        self.data_lib       = re.compile(r'@@.*')

        self.abbreviations = {
            'mem' : 'memory',
            'char' : 'character',
            'arg' : 'argument',
            'cmp' : 'compare',
            'cpy' : 'copy',
            'str' : 'string',
            'mov' : 'move',
            'val' : 'value',
            'cbc' : 'cipher_block_chaining',
            'aes' : 'advanced_encryption_standard',
            'des' : 'data_encryption_standard',
            'smtp': 'simple_mail_transfer_protocol',
            'pop' : 'post_office_protocol',
            'tls' : 'transfer_layer_security',
            'ssl' : 'secure_socket_layer',
            'ctx' : 'context',
            'dbus': 'data_bus',
            'ins' : 'insert',
            'req'   : 'request',
            'init' : 'initialise',
            'deinit': 'remove_initialise',
            'fini' : 'finalise',
            'dev':  'device',
            'va' : 'various_arguments',
            'msg' : 'message',
            'ts' : 'timestamp',
            'int' : 'integer',
            'buf' : 'buffer',
            'buff' : 'buffer',
            'hid'   : 'human_input_device',
            'sep' : 'separate',
            'gcc' : 'compiler',
            'pkcs'  : 'public_key_cryptography_standards',
            'fork'  : 'fork',
            'clang' : 'compiler',
            'db' : 'database',
            'cb' : 'callback',
            'hw' : 'hardware',
            'mutex' : 'mutex',
            'tex'   : 'type_setting',
            'profil' : 'profile',
            'con' : 'connection',
            'conn' : 'connection',
            'ent'   : 'entry',
            'crc'   : 'cyclic_redundancy_check',
            'mnt'   : 'mount',
            'sig' : 'signal',
            'jmp' : 'jump',
            'proc' : 'process',
            'eval' : 'evaluate',
            'gen': 'generate',
            'abrt' : 'abort',
            'alloc' : 'memory_allocate',
            'realloc' : 'memory_reallocate',
            'malloc' : 'memory_allocate',
            #'re' : 'redo',
            'sys' : 'system',
            'io' : 'input_output',
            'dup' : 'duplicate',
            'fcn' : 'function',
            'fn' : 'function',
            'func': 'function',
            'struct' : 'structure',
            'cpus' : 'central_processing_units',
            'vcpu' : 'virtual_central_processing_unit',
            'vcpus' : 'virtual_central_processing_units',
            'nan' : 'not_a_number',
            'opt' : 'option',
            'aux' : 'auxiliary',
            'mul' : 'multiply',
            'div' : 'divide',
            'sub' : 'subtract',
            'add' : 'addition',
            'exp' : 'exponential',
            'loc' : 'location',
            'pid' : 'process_identifier',
            'gid' : 'group_identifier',
            'uid' : 'user_identifier',
            'egid' : 'effective_group_identifier',
            'euid' : 'effective_user_identifier',
            'sgid' : 'set_group_identifier',
            'suid' : 'set_user_identifier',
            'alt'   : 'alternative',
            'iter' : 'iterate',
            'err' : 'error',
            'stp' : 'string_pointer',
            'charset'   : 'character_set',
            'locale'    : 'locale',
            'pnp'   : 'plug_and_play',
            'pgp'   : 'pretty_good_privacy',
            'len' : 'length',
            'pad' : 'padding',
            'delim' : 'delimiter',
            'sched' : 'schedule',
            'info' : 'information',
            'std' : 'standard',
            'ip' : 'internet_protocol',
            'reg' : 'register',
            'stat' : 'status',
            'dir' : 'directory',
            'mmap' : 'memory_map',
            'punct' : 'punctuation',
            'res' : 'resource',
            'eq' : 'equal',
            'conv' : 'convert',
            'async' : 'asynchronous',
            'sync' : 'synchronous',
            'fd' : 'file_descriptor',
            'alnum' : 'alpha_numeric',
            'num'   : 'number',
            'int'   : 'integer',
            'str'   : 'string',
            'lib'   : 'library',
            'arr'   : 'array',
            'lifo'  : 'last_in_first_out',
            'fifo'  : 'first_in_first_out',
            'ent'   : 'entry',
            'avg' : 'average',
            'cwd' : 'current_working_directory',
            'pwd' : 'print_working_directory',
            'lib' : 'library',
            'conf' : 'configuration',
            'config'    : 'config',
            'os' : 'operating_system',
            'chr' : 'character',
            'src' : 'source',
            'dst' : 'destination',
            'usb'   : 'universal_serial_bus',
            'qemu'  : 'emulator',
            'gpt'   : 'gnu_partition_table',
            'gnu'   : 'gnu',
            'gui'   : 'graphical_user_interface',
            'seq'   : 'sequence',
            'gtk'   : 'gimp_toolkit',
            'reiser'    : 'reiser',
            'qt'    : 'qt',
            'xfce'  : 'xfce',
            'kde'   : 'kubuntu_desktop_environment',
            'vfs'   : 'virtual_file_system', 
            'cfg'   : 'config',
            'cli'   : 'command_line_interface',
            'rgb'   : 'rgb',
            'mb'    : 'multi_byte',
            'rgba'  : 'rgba', 
            'mk'    : 'make',
            'del'   : 'delete',
            'rm'    : 'remove',
            'json'  : 'javascript_object_notation',
            'udp'   : 'user_datagram_protocol',
            'tcp'   : 'transmission_control_protocol',
            'dest'  : 'destination',
            'tow'   : 'to_wide',
            'lxc'   : 'linux_containers',
            'i2c'   : 'inter_integrated_circuit',
            'dl' : 'dynamically_linked',
            'dll' : 'dynamically_linked_library',
            'so'    : 'shared_object',
            'ec'    : 'elliptic_cruve',
            'tty' : 'terminal',
            'pts' : 'pseudo_terminal',
            'spi'   : 'serial_peripheral_interface',
            'cspn' : 'character_span',
            'dents' : 'directory_entries',
            'tz' : 'time_zone',
            'wc' : 'wide_character',
            'mesg'  : 'message',
            'ev'    : 'event',
            'cb'    : 'callback',
            'opt'   : 'option',
            'ioctl' : 'input_output_control',
            'x11'   : 'x11',
            'ftp'   : 'file_transfer_protocol',
            'cfg'   : 'config',
            'mbox'  : 'mail_box',
            'pop'  : 'post_office_protocol',
            'pop3'  : 'post_office_protocol',
            'smtp'  : 'simple_mail_transfer_protocol',
            'imap'  : 'internet_message_access_protocol',

            'toa' : 'to_ascii',
            'pos' : 'position',
            'chk' : 'check',
            'expr' : 'expression',
            'ind' : 'index',
            'errno' : 'error',
            'assert' : 'assertion',
            'addr' : 'address',
            'int' : 'integer',
            'ux' : 'user_interface',
            'p2p': 'peer_to_peer',
            'lex'   : 'lexical',
            'txt'   : 'text',
            'sig'   : 'signal',
            'asn'   : 'autonomous_system',
            'oid'   : 'object_identifier',
            'sys'   : 'system',
            'chan'  : 'channel',
            'seq'   : 'sequence',
            'pdf'   : 'portable_document_format',
            'xml'   : 'extensible_markup_language',
            'json'  : 'javascript_object_notation',
            'js'    : 'javascript',
            'javascript': 'javascript',
            'cdn'   : 'content_delivery_network',
            'yaml'  : 'human_readable_markup_language',
            'calc'  : 'calculate',
            'uart'  : 'universal_asynchronous_receiver_transmitter',
            'async' : 'asynchronous',
            'mgr'   : 'manager',
            'hz'    : 'hertz',
            'html'  : 'hypertext_markup_language',
            'iso'   : 'international_standards_organisation',
            'ctrl'  : 'controller',
            'bt'    : 'bluetooth',
            'ext'   : 'extend',
            'md5'   : 'md5',
            'sha'   : 'sha',
            'cpu'   : 'central_processing_unit',
            'gpu'   : 'graphics_processing_unit',
            'num'   : 'number',
            'arp'   : 'address_resolution_protocol',
            'aux'   : 'auxiliary',
            'gdb'   : 'gnu_debugger',
            'gcc'   : 'gnu_c_compler',
            'resv'  : 'receive',
            'gen'   : 'generate',
            'ieee'  : 'ieee',
            'int'   : 'integer',
            'dec'   : 'decimal',
            'noa'   : 'no_access',
            'rc'    : 'run_commands',
            'attr'  : 'attribute',
            'x'     : 'x11',
            'dh'    : 'diffie_hellman',
            'ecdh'  : 'elliptic_curve_diffie_helman',
            'xz'    : 'zip',
            'rsa'   : 'rivest_shamir_adleman',
            'ctl'   : 'control',
            'sql'   : 'structured_query_langauge',
            'srv'   : 'server',
            'var'   : 'variable',
            'mem'   : 'memory',
            'reg'   : 'register',
            'rcpt'  : 'recipient',
            'rpc'   : 'remote_procedure_call',
            'sim'   : 'simulate',
            'proc'  : 'process',
            'vga'   : 'video_graphics_array',
            'util'  : 'utility',
            'crt'   : 'c_runtime',
            'virt'  : 'virtual',
            'caml'  : 'ocaml',
            'dbg'   : 'debug',
            #missing definitions
            'hook' : 'hook',
            'to' : 'to',
            'i18n' : 'i18n',
            'posix' : 'posix',
            'amd' : 'computer_architecture',
            'intel' : 'computer_architecture',
            'unmap' : 'unmap',
            'free' : 'free',
            'is' : 'is',
            'at' : 'at',
            'align' : 'align',
            'open' : 'open',
            'utf-8' : 'utf-8',
            'utf-16' : 'utf-16',
            'ascii' : 'ascii',
            'acpi'  : 'acpi'
        }


    def expand_abbreviations(self, abbr):
        if abbr in self.abbreviations:
            return self.abbreviations[abbr]
        return abbr

    def _score_abbrs(self, name, abbrs):
        """
            Score a permutation of abbrs in a string
        """
        t = IntervalTree()
        score = 0
        used = set([])

        for abbr in abbrs:
            start = name.index(abbr)
            end = start + len(abbr)
            if t.overlaps(start, end):
                continue
            t.addi(start, end, len(abbr))
            score += (len(abbr) ** 2) / 2
            used.add(abbr)

        return score, used

    def subtract_words_sequence(self, name, abbrs):
        """
            Return a set of words that are split by known abbreviations
            e.g. awdddwordkjh, [ word ] -> [awddd, word, kjh]
        """
        assert(isinstance(abbrs, list))
        words = []
        splits = set([name])
        acc = 0
        for word in abbrs:
            #print(word)
            #print(splits)
            #print(words)
            new_splits = set([])
            for split in splits:
                try:
                    s = split.index(word)
                    words.append(split[s:s+len(word)])
                    if s > 0:
                        new_splits.add(split[:s])
                    if s + len(word) < len(split):
                        new_splits.add(split[s+len(word):])

                    #found, continue
                    splits = copy.deepcopy(new_splits)
                    break

                except ValueError:
                    new_splits.add(split)
                    continue

        return words + list(splits)

    def score_intervals(self, tree:IntervalTree):
        """
            Scores intervals such that:
                i) A range that uses more total characters is greater than less characters
                ii) Longer individual intervals score higher that subintervals of the same characters
                iii) An overlap in characters is invalid
        """
        #overlap check
        for k, v in tree.boundary_table.items():
            int_set = tree.at(k)
            ##if we have an overlap
            if len(int_set) > 1:
                return -1, -1

        ##total characters used
        c_used  = 0
        score   = 0
        for i in tree.all_intervals:

            c_used  += i.length()
            score   += math.pow(i.length(), 2)

        return c_used, score

    def nonoverlapping_substrings(self, s:str, substrs:list):
        """
            Check if all substrings fit into string s without overlapping
        """
        tree = IntervalTree()
        for ss in substrs:
            it = 0
            """
                substring could be contained in multiple positions
                ##getgetgc => get getgc
            """
            ##add all instances of substring
            while it < len(s):
                ss_ind = s.find(ss, it)
                if ss_ind == -1:
                    break
                tree.addi(ss_ind, ss_ind + len(ss), ss)
                it = ss_ind + 1

        hc, hs = 0, 0
        ht = IntervalTree()
        nsubstrs = len(substrs)
        for i in range(nsubstrs):
            for comb in itertools.combinations(tree.all_intervals, i+1):
                t       = IntervalTree(comb)
                c, sc   = self.score_intervals(t)

                if c >= hc:
                    if sc > hs:
                        ht = copy.deepcopy(t)
                        hc = c
                        hs = sc

        ###get all subtokens from intervals
        tokens = set([])
        cut_ind = 0
        for k, v in ht.boundary_table.items():
            if cut_ind < k:
                ss  = s[cut_ind:k]
                tokens.add(ss)

            iset   = ht.at(k)
            if not iset:
                #end of found tokens, add until end
                if cut_ind < len(s):
                    ss  = s[cut_ind:]
                    tokens.add(ss)

                break

            i   = iset.pop()
            tokens.add(i.data)
            cut_ind = k + i.length()

        return tokens


    def _combinations_with_condition(self, l, cond_value, base=[]):
        #recursively generate all combinations that meet conditions
        assert(isinstance(l, list))
        max_dimensions = len(l)

        for i in range(len(base), max_dimensions):
            if l[i] in base:
                continue
            new_comb = base + [ l[i] ]
            ##check is all abbreviations fit in string with no overlap
            size = functools.reduce(lambda x, y: x + len(y), new_comb, 0)
            if size <= cond_value:
                yield new_comb
            else:
                break

            yield from self._combinations_with_condition(l, cond_value, base=copy.deepcopy(new_comb))

    def best_cut_of_the_rod(self, name, abbrs):
        """
            return the best subset that maximizes the know characters in name
        """
        #perms = itertools.permutations(abbrs)
        #perms = itertools.combinations(abbrs)
        combs = self._combinations_with_condition(list(abbrs), len(name))
        bscore = -1
        bset = set([])
        for comb in combs:
            score, subabbrs = self._score_abbrs(name, comb)
            if score > bscore:
                bscore = score
                bset = subabbrs
                #max score
                if score == (len(name) ** 2) / 2:
                    return bset
        return bset


    def quick_subabbreviations(self, alpha_chars):
        """
            convert strcmp -> [string, compare]
            getlanguagespecificdata -> [get, language, specific, data]
        """

        MIN_WORD_LEN = 4
        MIN_ABBR_LEN = 3
        words = []

        if self.us_D.check(alpha_chars) or self.gb_D.check(alpha_chars):
            return [ alpha_chars ]

        for word in nltk.corpus.words.words():
            if len(word) >= MIN_WORD_LEN and word in alpha_chars:
                words.append(word)

        ##find abbreviations in words
        for abbr, full_abbr in self.abbreviations.items():
            if len(abbr) >= MIN_ABBR_LEN and abbr in alpha_chars:
                words.append(abbr)

        for word in nltk.corpus.stopwords.words('english'):
            if len(word) >= MIN_ABBR_LEN and word in alpha_chars:
                words.append(word)

        ##perform a sequential pass and check for words in dictionary
        MAX_WORD_LEN = 11
        for i in range(len(alpha_chars) - MIN_WORD_LEN):
            for j in range(MIN_WORD_LEN, MAX_WORD_LEN):
                subword = alpha_chars[i:i+j+1]
                if self.us_D.check(subword) or self.gb_D.check(subword):
                    words.append(subword)

        return set(words)


    def find_subabbreviations(self, alpha_chars):
        """
            convert strcmp -> [string, compare]
            getlanguagespecificdata -> [get, language, specific, data]
        """

        me = set([])

        if alpha_chars in self.abbreviations:
            me.add(alpha_chars)

        if len(alpha_chars) < min( self.config.analysis.nlp.MIN_MAX_ABBR_LEN, self.config.analysis.nlp.MIN_MAX_WORD_LEN):
            return me

        if len(alpha_chars) >= self.config.analysis.nlp.MIN_MAX_WORD_LEN:
            self.enchant_lock.acquire()
            if self.us_D.check(alpha_chars) or self.gb_D.check(alpha_chars):
                me.add(alpha_chars)
            self.enchant_lock.release()

        valid_substr_prefix = self.find_subabbreviations(alpha_chars[:-1])
        valid_substr_suffix = self.find_subabbreviations(alpha_chars[1:])

        ### find longest subabbreviations that do not overlap
        #sub_abbrs = valid_substr_suffix.union( valid_substr_prefix )

        return valid_substr_suffix.union( valid_substr_prefix ).union( me )

    def find_maximal_length_word(self, alpha_chars):
        if len(alpha_chars) < self.config.analysis.nlp.MIN_MAX_WORD_LEN:
            return ""

        self.enchant_lock.acquire()
        if self.us_D.check(alpha_chars) or self.gb_D.check(alpha_chars):
            self.enchant_lock.release()
            return alpha_chars
        self.enchant_lock.release()


        valid_substr_prefix = self.find_maximal_length_word(alpha_chars[:-1])
        valid_substr_suffix = self.find_maximal_length_word(alpha_chars[1:])

        if len(valid_substr_prefix) >= len(valid_substr_suffix):
            return valid_substr_prefix

        return valid_substr_suffix

    def strip_ida_decorations(self, name):
        rules = [ self.ida_import ]
        for rule in rules:
            name = re.sub(rule, "", name)
        return name


    def strip_r2_decorations(self, name):
        """
            Return real name of symbol from r2
        """
        syntax_replace = [
            self.r2_dyn_prefix,
            self.r2_prefix
        ]

        for sf in syntax_replace:
            name = re.sub(sf, "", name)

        return name

    def strip_ida_data_refs(self, name):
        rules = [ self.data_lib ]
        for rule in rules:
            name = re.sub(rule, "", name)
        return name

    def filter_ida_junk(self, iterable):
        return filter(lambda x: not x.startswith("sub_"), iterable)

    def filter_null(self, iterable):
        return filter(lambda x: not x == '', iterable)

    def strip_library_decorations(self, name):
        """
            Compare names of symbols against known prefixed and suffixes
            strcpy -> __strcpy
            open -> open64
        """
        content_replace = [
            self.__ID__, self.ssse3, self.sse2,  self.avx, self.cold, self.libc, self.unaligned, self.erms,
            self.constprop, self.constp, self.isra, self.part
        ]

        syntax_replace = [
                self.r2_dyn_prefix, self.r2_prefix, self.ida_dyn_prefix,
            self.dot_num_suffix, self.num_suffix, self.num_prefix,
            #self.bitssuffix, self.bitsprefix, 
            self.dot_prefix, self.dot_suffix,
            self.underprefix, self.undersuffix,
            self.num_only_prefix #, self.num_only_suffix
        ]

        for cf in content_replace:
            name = re.sub(cf, "", name)
            for sf in syntax_replace:
                name = re.sub(sf, "", name)

            name = re.sub(self.repeated_nonalpha, '\g<1>', name)
        return name

    @staticmethod
    def split_camel_case(string:str):
        """
            Split a string into labels based on camel case
            rtype:set
            return: set of substrings
        """
        words = set([])
        while True:
            m = re.search(r'[a-z]{1}[A-Z]{1}', string)
            if not m:
                break
            substr = string[0:m.start()+1]
            words.add(substr)
            string = string[len(substr):]

        #add end of string
        words.add(string)
        return words

    def canonical_name(self, name):
        #return '_'.join( self.canonical_set(name) )
        return '_'.join(NLP.find_label_order(name, self.canonical_set(name)))

    @staticmethod
    def find_label_order(name: str, labels: set):
        """
            Finds the order the {labels} appear in {name}
            Returns list of labels

            assumption: labels do not overlap
            how to deal with repeated labels

            algorithm:
                sort labels by size (longest first)
                find first character index of labels
                return labels as list

        """
        llabels = sorted(list(labels), key=lambda x: -len(x))
        # cannot deal with sublabels inside other labels e.g. 'key' in 'subkey'
        #indexes = list(map(lambda x, v=name.lower(): v.find(x), llabels))
        tree    = IntervalTree()
        bname   = name.lower()
        indexes = {}
        for l in llabels:
            #ind = bname.find(l, start)
            inds = list(re.finditer(l, bname, overlapped=True))
            if len(inds) > 1:
                #merge conflict
                continue

            #if not int_ind := tree.overlaps(ind, ind+ len(l)):
            if len(inds) == 1:
                start   = inds[0].start()
                end     = inds[0].end()
                int_ind = tree.overlaps(start, end)
                if not int_ind:
                    tree.addi(start, end, l)
                    indexes[start] = l
                    continue
            else: 
                raise RuntimeError(f"label not found in function name, {name}, {l}")


        # resolve merge conflicts
        #largest first
        for l in sorted(set(llabels) - set(list(map(lambda x: x.data, tree.items()))), key=lambda x: -len(x)):
            #print(f"merge conflict for {l}")
            inds = re.finditer(l, bname, overlapped=True)
            for interval in inds: 
                int_s, int_e = interval.span()
                #if not int_ind := tree.overlaps(ind, ind+ len(l)):
                int_ind = tree.overlaps(int_s, int_e)
                if not int_ind:
                    tree.addi(int_s, int_e, l)
                    indexes[int_s] = l
                    #print(f"Found label in name {name}, {l}, {int_s}, {int_e}")
                    #break

            if l not in indexes.values():
                #error conflict
                #raise RuntimeError(f"Error finding label order: {name}, {l}, {indexes}")
                print(f"Error finding label order: {name}, {l}, {indexes}")

        #kv = dict(zip(indexes, llabels))
        return list(indexes[k] for k in sorted(indexes))

    def canonical_set(self, name):
        base_name = self.strip_library_decorations(name)

        #remove punctuation
        words_in_name = re.findall(r'[a-zA-Z]+', base_name)
        numbers_in_name = re.findall(r'[0-9]+', base_name)

        ##implement camel case splits
        ccsplit_subsets = list(map(lambda x: NLP.split_camel_case(x), words_in_name)) 
        words_in_name   = reduce(lambda x, y: x | y, ccsplit_subsets, set([]))
        words_in_name   = list(map(lambda x: x.lower(), words_in_name))

        labels = set([])
        for number in numbers_in_name:
            labels.add(number)

        for word in words_in_name:
            pass
        while words_in_name:
            word = words_in_name.pop()
            #print(word)
            ##divide and concour, only return longest abbreviation 
            if len(word) >= self.config.analysis.nlp.MAX_STR_LEN_BEFORE_SEQ_SPLIT:
                #find large words to split the name first
                #print("Finding quick subabbrs in {}".format(word))
                sub_abbrs       = self.quick_subabbreviations(word)
                ##use teh buggest to spit
                if len(sub_abbrs) > 8:
                    sub_abbrs = sorted(list(sub_abbrs), key=lambda x: len(x))[-8:]

                #print("Found sub abbreviations: {}".format(sub_abbrs))
                ##get best set but don't include non abbreviations
                best_sub_abbrs  = set(filter(lambda x, sa=sub_abbrs, self=self: x in sa, self.nonoverlapping_substrings(word, sub_abbrs)))
                if not best_sub_abbrs:
                    ##oops, what can we do here?
                    words = [ word ]
                else:
                    ##split this word based on the largest found subword
                    mx  = reduce(lambda x, y: x if len(x) > len(y) else y, best_sub_abbrs, '')
                    #print("longest subabbr found was {}".format(mx))
                    words = set(self.subtract_words_sequence(word, [mx]))
                    words.remove(mx)
                    words_in_name += words
                    #words = [ mx ]
                    labels.add(mx)
                    continue
            else:
                #print("Not splitting {} for fast abbreviations".format(word))
                words = [ word ]

            for subword in words:
                #print("subword in words: {}".format(subword))
                if len(subword) > self.config.analysis.nlp.MAX_WORD_LEN:
                    labels.add(subword)
                    continue

                abbrs = self.find_subabbreviations(subword)
                #abbrs = self.quick_subabbreviations(subword)

                #print("computing best cut of rod with {} and {}".format(word, abbrs))
                #abbr = self.best_cut_of_the_rod(subword, abbrs)
                abbr = self.nonoverlapping_substrings(subword, abbrs)
                #print(abbr)

                #replace words with abbreviatiosn if they are abbreviations
                #expanded_words = set(map(lambda x: self.abbreviations[x] if x in self.abbreviations else x, abbr))
                #list_of_lists = list(map(lambda x: re.findall(r'[a-zA-Z]+', x), expanded_words))
                list_of_lists = list(map(lambda x: re.findall(r'[a-zA-Z]+', x), abbr))

                #add original if no abbreveation or word found
                if len(list_of_lists) == 0:
                    list_of_lists = [ [ subword ] ] 

                new_words = [x for y in list_of_lists for x in y ]
                filt_new_words = set(filter(lambda x: len(x) >= 2, new_words))
                labels |= filt_new_words

        ##minimum token size of 2 characters
        return set(filter(lambda x: len(x) >= 2, labels))

    def wordnet_similarity(self, a:str, b:str):
        word_sims = set()
        ac  = self.canonical_set(a)
        bc  = self.canoncial_set(b)
        for aw, bw in itertools.product(ac, bc):
            synset_aw   = wn.synsets(aw)
            synset_bw   = wn.synsets(bw)
            for a_ss, b_ss in itertools.product(synset_aw, synset_bw):
                d = wn.wup_similarity(a_ss, b_ss)
                word_sims.add(d)
        return max(word_sims)




    def alpha_numeric_set(self, name):
        """
            Return set of labels by splitting on all non-alphanumeric letters

        """
        base_name = self.strip_library_decorations(name).lower()

        #remove punctuation
        words_in_name = re.findall(r'[a-zA-Z0-9]+', base_name)
        #numbers_in_name = re.findall(r'[0-9]+', base_name)

        labels = set([])
        #for label in numbers_in_name + words_in_name:
        for label in words_in_name:
            labels.add(label)

        return labels

    #need to get at least 1/e % of names correct for similarity match
    def check_word_similarity(self, correct_name, inferred_name):
        """
            Check similarity between 2 function names.
            correct name goes first
            :param correct_name: The functions actual name
            :param inferred_name: The name we think it is
            :rtype: Bool
            :return: If similar or not
        """

        if len(correct_name) == 0 and len(inferred_name) == 0:
            return True
        if len(correct_name) == 0 or len(inferred_name) == 0:
            return False

        #correct name is a prefix or suffix of inferref name and vica versa
        if correct_name in inferred_name or inferred_name in correct_name:
            self.logger.debug("Matched on substring! {} -> {}".format(inferred_name, correct_name))
            return True

        #check edit distance as a function of max length
        levehstien_distance = nltk.edit_distance( correct_name, inferred_name )

        #edit distance as a function of length
        m = float( max( len(correct_name),  len(inferred_name) ) )
        #m = float( len(correct_name) + len(inferred_name) )
        #d = float(  abs( len(correct_name) - len(inferred_name) ) )

        #EDIT_DISTANCE_THRESHOLD = 1.0 / 2.0 


        ### higher is better
        edit_sim =  1.0 - ( float(levehstien_distance) / m )
        if edit_sim >= self.config.analysis.nlp.EDIT_DISTANCE_THRESHOLD:
            self.logger.debug("Matched on edit distance! {} -> {} : {}".format(inferred_name, correct_name, edit_sim))
            return True

        canonical_inferred = self.canonical_name(inferred_name)
        canonical_correct = self.canonical_name(correct_name)

        words_in_inferred_name = re.findall(r'[a-zA-Z]+', canonical_inferred)
        words_in_correct_name = re.findall(r'[a-zA-Z]+', canonical_correct)

        #THRESHOLD = 1.0 / math.e #0.36 -> 1/2, 2/3, 2/4, 2/5, 3/6, ...

        #self.logger.debug("Canonical name: {} => {}".format(inferred_name, words_in_inferred_name))
        #self.logger.debug("Canonical name: {} => {}".format(correct_name, words_in_correct_name))


        ##########################################
        self.enchant_lock.acquire()
        ##########################################
        try:
            #TODO: filter to uniue and WHOLE words! in a dictionary
            words_in_inferred_name = set( words_in_inferred_name )
            words_in_correct_name = set( words_in_correct_name )

            #filter for english words
            words_in_inferred_name = set( filter( lambda w: len(w) > 2 and (self.us_D.check(w) or self.gb_D.check(w)), words_in_inferred_name) )
            words_in_correct_name = set( filter( lambda w: len(w) > 2 and (self.us_D.check(w) or self.gb_D.check(w)), words_in_correct_name) )

        except Exception as e:
            self.logger.warn("[!] Could not compute check_similarity_of_symbol_name( {} , {} )".format(correct_name, inferred_name))
            self.logger.warn(e)

        finally:
            self.enchant_lock.release()


        #remove boring stop words
        unique_words_inferred = words_in_inferred_name - set(nltk.corpus.stopwords.words('english'))
        unique_words_correct = words_in_correct_name - set(nltk.corpus.stopwords.words('english'))


        #self.logger.debug("Name description: {} => {}".format(inferred_name, unique_words_inferred))
        #self.logger.debug("Name description: {} => {}".format(correct_name, unique_words_correct))

        stemmer = nltk.stem.PorterStemmer()
        lemmatiser = nltk.stem.wordnet.WordNetLemmatizer()

        stemmed_inferred = set( map( lambda x: stemmer.stem(x), unique_words_inferred) )
        stemmed_correct = set( map( lambda x: stemmer.stem(x), unique_words_correct) )

        lemmatised_inferred = set( map( lambda x: lemmatiser.lemmatize(x), unique_words_inferred) )
        lemmatised_correct = set( map( lambda x: lemmatiser.lemmatize(x), unique_words_correct) )

        if len(lemmatised_correct) > 0 and len(lemmatised_inferred) > 0:
            jaccard_distance = nltk.jaccard_distance( lemmatised_correct, lemmatised_inferred )
            if jaccard_distance < self.config.analysis.nlp.WORD_MATCH_THRESHOLD:
                self.logger.debug("\tJaccard Distance Lemmatised {} : {} -> {}".format(jaccard_distance, inferred_name, correct_name))
                return True

        if len(stemmed_correct) > 0 and len(stemmed_inferred) > 0:
            jaccard_distance = nltk.jaccard_distance( stemmed_correct, stemmed_inferred )
            if jaccard_distance < 1.0 - self.config.analysis.nlp.WORD_MATCH_THRESHOLD:
                self.logger.debug("\tJaccard Distance Stemmed {} : {} -> {}".format(jaccard_distance, inferred_name, correct_name))
                return True

        if len(unique_words_correct) > 0 and len(unique_words_inferred) > 0:
            if self.compare_synsets(unique_words_correct, unique_words_inferred) >= 0.385:
                self.logger.debug("\tMatched on wordnet synsets: {} -> {}".format(inferred_name, correct_name))
                return True

        return False

    def compare_synsets(self, A, B):
        """
            Compare two sets of words based on synsets from wordnet
        """
        _A = list(A)
        _B = list(B)

        mc = 0.0
        ##score is a function of teh maximum length, if length of 2 words sets is 10, 2 and all 2 are in 10 -> wrong name
        max_m = float( max(len(_A), len(_B)) )
        if max_m == 0.0:
            raise Exception("Error, empty word set passed ({},{})".format(A, B))

        a_synsets = list(map(lambda x: wn.synsets(x), _A))
        b_synsets = list(map(lambda x: wn.synsets(x), _B))

        for i, a_ss in enumerate(a_synsets):
            WORD_MATCH = False
            a_words_list = list(map(lambda x: x.lemma_names(), a_ss))
            a_words = [word for word_list in a_words_list for word in word_list]
            a_synonyms = set(a_words)
            for j, b_ss in enumerate(b_synsets):
                b_words_list = list(map(lambda x: x.lemma_names(), b_ss))
                b_words = [word for word_list in b_words_list for word in word_list]
                b_synonyms = set(b_words)
                if len(a_synonyms.intersection(b_synonyms)) > 0:
                    self.logger.debug("Matched ({},{}) on {}".format(_A[i], _B[j], a_synonyms.intersection(b_synonyms)))
                    WORD_MATCH = True
                    break

            if WORD_MATCH:
                mc += 1.0

        return mc / max_m


class SmithWaterman:
    """
        Implements Smith-Waterman distance
    """
    def __init__(self, gap_cost=2, match_score=3):
        self.match_score    = match_score
        self.gap_cost       = gap_cost

    def matrix(self, a, b):
        """
            Calculates similarity matrix for 2 sequences 
        """
        H = np.zeros((len(a)+1, len(b)+1), np.int)

        for i, j in itertools.product(range(1, H.shape[0]), range(1, H.shape[1])):
            match   = H[i-1, j-1] + self.match_score if a[i-1] == b[j-1] else - self.match_score
            delete  = H[i-1, j] - self.gap_cost
            insert  = H[i, j-1] - self.gap_cost

            H[i, j] = max(match, delete, insert, 0)

        return H

    def traceback(self, H, b, b_='', old_i=0):
        """
            Recursivly find best alignment
        """
        H_flip = np.flip(np.flip(H, 0), 1)
        i_, j_ = np.unravel_index(H_flip.argmax(), H_flip.shape)
        i, j = np.subtract(H.shape, (i_ + 1, j_ + 1))  # (i, j) are **last** indexes of H.max()

        if H[i, j] == 0:
            return b_, j

        b_ = b[j - 1] + '-' + b_ if old_i - i > 1 else b[j - 1] + b_
        return self.traceback(H[0:i, 0:j], b, b_, i)

    def max_alignment(self, a, b):
        """
            Returns the string indicies for the highest scoring alignment
            :return: start_ind, end_ind
            :rtype: tuple of 2 ints
        """
        a, b    = a.lower(), b.lower()
        H       = self.matrix(a, b)
        b_, pos = self.traceback(H, b)
        return pos, pos + len(b_)

    def score(self, a, b):
        """return a similarity score between 2 sequences"""
        start, end = self.max_alignment(a, b)
        assert(end >= start)
        return end-start

    def distance(self, a, b):
        """
            Get the distance between a and b, smaller is closer distance
        """
        d = self.score(a, b)
        return 1.0 / (1.0 + np.log(1+d))


if __name__ == '__main__':
    config = classes.config.Config()
    nlp = NLP(config)
    import IPython
    IPython.embed()
