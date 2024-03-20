
"""

Copyright 2017-2024 by James Patrick-Evans, Moritz Dannehl, and Johannes Kinder.

This file is part of XFL.

XFL is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

XFL is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with XFL. If not, see <https://www.gnu.org/licenses/>. 

"""

#!/usr/bin/python3
import json
import pymongo, re, functools, itertools
import timeout_decorator
import IPython
import random, subprocess, os
import logging
import redis
import psycopg2
import psycopg2.extras
#from multiprocessing import Pool
import multiprocess
from multiprocess.pool import ThreadPool
from itertools import islice
from tqdm import tqdm
from collections import namedtuple

import context
import classes.utils
import classes.symbol
import classes.crf

class Database:

    #use Database.client as MongoDB reference
    def __init__(self, config, collection_name=''):
        """
            Create a new database object to handle operations with MongoDB
            Each database instance only handles talking to a single collection!
            To handle using a differnet collection, open a new database object with a new collection_name

            :param: config
            :param: collection_name: string name for collection to operate on
        """
        classes.utils._desyl_init_class_(self, config)

        self._db_name   = self.config.database.mongodb.name
        self._ip        = self.config.database.mongodb.address
        self._port      = self.config.database.mongodb.port
        self._username  = self.config.database.mongodb.username
        self._password  = self.config.database.mongodb.password

        self.redis = self.config.database.redis


        if len(collection_name) == 0:
            collection_name = self.config.database.mongodb.collection_name

        self.collection_name = collection_name
        self._db_config_str = self._gen_config()
        #print(self._db_config_str)
        self.conn = self.connect()

        if not self.conn:
            raise Exception("Error, could not connect to MongoDB")

        self.client = self.conn[self._db_name]
        self.logger.debug("Created a database instance with collection_name : {}".format(self.collection_name))

    def _gen_config(self):
        if len(self._username) > 0 and len(self._password) > 0:
            return "mongodb://{}:{}@{}:{}/{}".format(self._username, self._password, self._ip, self._port, self._db_name)
        elif len(self._username) > 0:
            return "mongodb://{}@{}:{}/{}".format(self._username, self._ip, self._port, self._db_name)
        else:
            return "mongodb://{}:{}/{}".format(self._ip, self._port, self._db_name)

    def connect(self):
        return pymongo.MongoClient(self._db_config_str)

    def close(self):
        self.conn.close()

    def drop_collection(self):
        self.client[self.collection_name].drop()

    def _rnd_distinct_field(self, field, pre_query=[], post_query=[], coll_name=''):
        vals = self._distinct_field(field, pre_query=pre_query, post_query=post_query, coll_name=coll_name)
        return random.sample( vals, k=len(vals) )

    def _distinct_field(self, field, pre_query=[], post_query=[], coll_name=''):
        query = { '$group' : { '_id' : '$' + field } } 
        agg_query = pre_query + [ query ] + post_query
        return list(map(lambda x: x['_id'], self.run_mongo_aggregate( agg_query, coll_name=coll_name ) ))

    def _distinct_field_len(self, field, pre_query=[], post_query=[], coll_name=''):
        query = { '$group' : { '_id' : { '$size' : '$' + field } } } 
        agg_query = pre_query + [ query ] + post_query
        return list(map(lambda x, coll_name=coll_name: x['_id'], self.run_mongo_aggregate( agg_query, coll_name=coll_name) ))

    #current implementation uses the symbol collection
    def distinct_bin_names(self):
        return self._rnd_distinct_field('bin_name', coll_name=self.collection_name+self.config.database.mongodb.symbol_collection_suffix)

    def distinct_binaries(self):
        return self._rnd_distinct_field('path', coll_name=self.collection_name+self.config.database.mongodb.symbol_collection_suffix)

    def distinct_symbol_names(self):
        return self._rnd_distinct_field('name', coll_name=self.collection_name + self.config.database.mongodb.symbol_collection_suffix)

    def run_mongo_aggregate(self, query, coll_name=''):
        #default collection name
        collection = self.collection_name
        if len(coll_name) > 0:
            collection = coll_name

        res = self.client[collection].aggregate( query, allowDiskUse=self.config.database.mongodb.allowDiskUse ) 
        vals = []
        for item in res:
            vals.append( item )
        return vals

    def symbol_name_in_db(self, name): 
        res = self.client[self.collection_name].find_one({ 'name' : name })
        return True if res else False

    def get_symbols_from_binary(self, path):
        query = { '$match' : { 'path' : path } }
        return self.get_symbols( [ query ] )

    def _raw_get_symbols_from_binary(self, path):
        query = { '$match' : { 'path' : path } }
        #return self.client[self.collection_name + self.config.database.mongodb.symbol_collection_suffix].aggregate([ query ])
        return self._raw_get_symbols_by_query(query)

    def _raw_get_symbols_by_query(self, query):
        return self.client[self.collection_name + self.config.database.mongodb.symbol_collection_suffix].aggregate([ query ])

    def get_symbol(self, path, name):
        query = { 'path' : path, 'name': name } 
        res = self.client[self.collection_name].find_one(query)
        if res:
            return classes.symbol.Symbol.from_dict( self.config, res )
        return False

    @staticmethod
    def _symbol_deserialize(config, symb_list):
        return list(map(lambda x,config=config: classes.symbol.Symbol.from_dict(config, x), symb_list))

    def get_symbols(self, aggregate_query):
        self.logger.debug("Starting DB query for symbols")
        self.logger.debug("Running query: {}".format( aggregate_query) )
        res = self.client[self.collection_name + '_symbols'].aggregate(aggregate_query)
        self.logger.debug("Got them! Parsing into symbols!")
        """
        #############
        ############# Cannot pickle methods, multiprocess
        ############# Takes more time than single-threaded.
        #############
        mp = ThreadPool(processes=self.config.analysis.THREAD_POOL_THREADS)
        #mp = multiprocess.Pool(processes=self.config.analysis.THREAD_POOL_THREADS)
        #tried using starmap, partial, itertools.repeat. Cannot pickle object instance!
        #symbs = mp.map( classes.symbol.Symbol.from_dict, res )
        ##do not create a new thread for each single symbol, too slow!
        #p = functools.partial( Database._symbol_deserialize, self.config )
        chunks = classes.utils.chunks_of_size(list(res), 64)
        symbs = mp.starmap( Database._symbol_deserialize, zip( itertools.repeat(self.config), chunks ) )
        #symbs = mp.starmap( p, chunks )
        #symbs = mp.map( p, chunks )
        mp.close()
        self.logger.debug("Finished parsing")
        #flatten list of chunks
        return [s for sl in symbs for s in sl]
        #return symbs
        """
        return Database._symbol_deserialize(self.config, res)

    @staticmethod
    def path2query(path):
        """
            Return a query object for databased optimised querying!
        """
        query = {}
        query['path'] = path
        return query

        """
        dynamic = int( subprocess.check_output('file {} | grep "dynamic" | wc -l'.format(path), shell=True) )
        if dynamic == 1:
            query['linkage'] = "dynamic"
        elif dynamic == 0: 
            query['linkage'] = "static"
        else:
            raise Exception("Error, Impossible linkage ( !(static|dynamic) )")

        query['bin_name'] = os.path.basename(path)

        #set compiler
        if path.find("gcc/") > 0:
            query['compiler'] = "gcc"
        elif path.find("clang/") > 0:
            query['compiler'] = "clang"
        elif path.find("vs/") > 0:
            query['compiler'] = "visualstudio"
        else:
            query['compiler'] = "unknown"


        #set architecture
        arm_arch = int( subprocess.check_output('file {} | cut -f 2 -d ":" | grep "ARM" | wc -l'.format(path), shell=True) )
        x86_64_arch = int( subprocess.check_output('file {} | cut -f 2 -d ":" | grep "x86-64" | wc -l'.format(path), shell=True) )
        x86_arch = int( subprocess.check_output('file {} | cut -f 2 -d ":" | grep "Intel 80386" | wc -l'.format(path), shell=True) )
        ppc64_arch = int( subprocess.check_output('file {} | cut -f 2 -d ":" |  grep "PowerPC" | wc -l'.format(path), shell=True) )

        if sum([arm_arch, x86_64_arch, x86_arch, ppc64_arch]) > 1:
            self.logger.error("Multiple architectures for binary! :: {}".format(path))
            assert(False)

        if x86_64_arch:
            query['arch'] = "x86_64"
        elif x86_arch:
            query['arch'] = "x86"
        elif ppc64_arch:
            query['arch'] = "PPC64"
        elif arm_arch:
            query['arch'] = "ARMv7"
        else:
            self.logger.error("Unknown ISA for {}".format(path))
            assert( False )

        #set optimisation
        #m = re.match(r'.*?o(\d{1})\/', path)
        m = re.match(r'.*?\/o((\d{1})|(\w{1}))\/', path)
        if m:
            query['optimisation'] = m.group(1)

        query['path'] = path

        return query
        """

    @staticmethod
    def gen_query(config, projection=None):
        sample = -1
        agg_query = []

        match_query = {}
        for k, v in config.items():
            if k not in [ "bin_names", "linkages", "optimisations", "compilers", "types", "names", "sample", "paths", "archs" ]:
                raise Exception("Error paring Symbol Query config. Unknown key {} of value: {}".format(k, v))

            if k == "sample":
                sample = v
                continue

            assert(isinstance(k, str))
            assert(isinstance(v, list))
            match_query[ k[:-1] ] = { '$in' : v }

        agg_query.append( { '$match' : match_query } )

        if projection:
            agg_query.append( { '$project': projection } )

        if sample != -1:
            agg_query.append( { '$sample' : { 'size' : sample } } )

        assert(isinstance(agg_query,list))
        return agg_query

    def caller_vaddr_lookup(self, path, vaddr):
        """
            Result should be unique. 1 Function per binary at a vaddr
        """
        res = self.client.symbols.find_one({ 'path': path, 'vaddr': vaddr})
        if not res:
            return False
        return res['name']

    def group_attr_by_symbol_name(self, attr, symbol_name):
        assert(isinstance(attr, str))
        match   = { '$match': { 'name': symbol_name } }
        proj    = { '$project' : { 'symb_attr' : '$'+attr, 'path': '$path' } }
        group   = { '$group' :{ '_id' :'$path', 'symb_attr' : {'$push':'$symb_attr' }}}
        unwind  = { '$unwind' : '$symb_attr' }

        attr_list = []
        m_res = self.run_mongo_aggregate( [ match, proj, group, unwind ] )
        if not m_res:
            logger.warning("SYMBOL `{}` has not attribute {}!".format( symbol_name, attr ) )
        for res in m_res:
            path = res['_id']
            attr = res['symb_attr']
            assert(isinstance(path, str))
            assert(isinstance(attr, list))

            attr_list += attr
        return attr_list

    def is_static_only_symbol(self, symbol_name, coll_name='symbols'):
        """
            If symbol only exists inside static binaries.
        """
        res = self.client[coll_name].find_one({ 'name' : symbol_name, 'linkage': 'dynamic' })
        return res == None

    def flatten_callees_callers(self):
        proj    = { '$project' : { 'name' : { '$concatArrays' : [ '$callers', '$callees'] } } }
        unwind  = { '$unwind' : '$name' }
        group   = { '$group' : { '_id' : '$name' } } 
        coll_name=self.collection_name + self.config.database.mongodb.symbol_collection_suffix
        return list(map(lambda x: x['_id'], self.run_mongo_aggregate( [ proj, unwind, group ], coll_name=coll_name ) ))

    def distinct_function_names(self):
        """
            Return the set of all function names seen or referenced (both static and dynamic
            imports) 
        """
        return self.get_set_all_xrefs().union(set(self.distinct_symbol_names))

    def get_set_all_xrefs(self, query=None):
        """
            Get all callers and callees for a match query
            :param query: Dict pymongo match query, optional
            :return: The set of all function names that are callers and callees
            :rtype: set([str])
        """
        match               = query
        project_call_calle  = { '$project' : { 'callees' : 1, 'callers': 1  }  }
        project_xrefs       = { '$project' : { 'xrefs' : { '$concatArrays' : ['$callees', '$callers'] } } }
        unwind              = { '$unwind': '$xrefs' }
        group_all           = { '$group' : { '_id' : None, 'xrefs': { '$addToSet' : '$xrefs' } } }

        agg_commands = [ project_call_calle, project_xrefs, unwind, group_all ]

        if match:
            agg_commands.insert(0, match)

        xrefs = set([])
        res = self.run_mongo_aggregate([ match, project_call_calle, project_xrefs, unwind, group_all ])
        for r in res:
            assert( isinstance(r['xrefs'], list) )
            xrefs = xrefs.union( set( r['xrefs']) )
        return xrefs

    def get_all_constants(self):
        proj    = { '$project' : { 'constants' : '$vex.constants' } }
        unwind  = { '$unwind' : '$constants' }
        coll_name=self.collection_name + self.config.database.mongodb.symbol_collection_suffix
        return list(map(lambda x: x['constants'], self.run_mongo_aggregate( [ proj, unwind ], coll_name=coll_name ) ))



    def get_dynamic_imports(self, query):

        res = self._raw_get_symbols_by_query(query)
        text_funcs, xrefs = set([]), set([])
        for r in res:
            text_funcs.add(r['name'])
            xrefs = xrefs.union( set( r['callers']) )
            xrefs = xrefs.union( set( r['callees']) )

        return xrefs - text_funcs

    def get_number_of_xrefs(self):
        """
            Get the number of XREFS per binary
            :return: A dictionary of path -> number of xrefs
            :rtype: dict 
        """
        project = { "$project": { "path": 1, "xrefs" : { "$size" : { "$concatArrays" : [ "$callees", "$callers" ] } } } }
        group   = { "$group" : { '_id': "$path", "xrefs" : { "$sum" : "$xrefs"  } } }

        xrefs_counts = {}
        res = self.run_mongo_aggregate([ project, group ])
        for r in res:
            xrefs_counts[ r['_id'] ] = r['xrefs']
        return xrefs_counts

    def get_unknown_symbol_names(self):
        not_lib_regex = re.compile(r'^((?!.*\.(so|a|o|oS|so\..*)$).+)$', re.IGNORECASE)
        return self._regex_group_symbols("path", not_lib_regex, "$name")

    def get_known_symbol_names(self):
        lib_regex = re.compile(r'(\.(o|so|oS|a)$)|(\.so\.)', re.IGNORECASE)
        return self._regex_group_symbols("path", lib_regex, "$name")

    def get_unknown_symbol_binaries(self):
        not_lib_regex = re.compile(r'^((?!.*\.(so|a|o|oS|so\..*)$).+)$', re.IGNORECASE)
        return self._regex_group_symbols("path", not_lib_regex, "$path")

    def get_known_symbol_binaries(self):
        lib_regex = re.compile(r'(\.(o|so|oS|a)$)|(\.so\.)', re.IGNORECASE)
        return self._regex_group_symbols("path", lib_regex, "$path")


    def _regex_group_symbols(self, match_field, match_regex, group_field):
        """
            Match symbols by regex and then group by group by
            :return: A set of known symbol names 
            :rtype: set<string>
        """
        match = { "$match" : { match_field : { "$regex" : match_regex } } }
        group = { "$group" : { "_id": group_field } }

        coll = set([])
        res = self.run_mongo_aggregate([ match, group ])
        for r in res:
            coll.add( r['_id'] )
        return coll

    def find_one_symbol_by_name(self, name):
        return self.client[self.collection_name].find_one( { "name": name } ) 

    def find_binary_like(self, pattern):
        return self.client[self.collection_name].find_one({ "bin_name": { "$regex" : pattern } })

    def get_all_xrefs(self):
        xrefs = []
        res = self.client['xrefs_pmfs'].find()
        for r in res:
            xrefs.append( { "name": r['name'], "type": r['type'], "pmf": r['pmf'] } )
        return xrefs



class RedisDB(Database):
    def __init__(self, config, collection_name=''):
        super().__init__(config, collection_name=collection_name)

        """
        ##Redisworks library faisl to save binary data longer than 100KB. Silently
        corrupts data
        self.root = redisworks.Root(host = self.config.database.redis.address, 
                port = self.config.database.redis.port)
        """

        self.rdb_conn = redis.Redis( host = self.config.database.redis.address, 
                port = self.config.database.redis.port,
                socket_timeout=600.0)

    def get(self, key):
        value = self.rdb_conn.get("{}:{}".format(self.collection_name, key))
        if not isinstance(value, int) and not isinstance(value, bytes) and not isinstance(value, str):
            raise TypeError("Error, redis values need to be binary, string or numeric")
        return value

    def get_py_obj(self, key):
        self.logger.debug("Reading Redis key: `{}:{}`".format(self.collection_name, key))
        data = self.rdb_conn.get("{}:{}".format(self.collection_name, key))

        if data[:18] == b'___DESYL___PART___':
            n = int(data[18:])
            chunks = list(map(lambda i: self.rdb_conn.get("{}:{}::part.{}".format(self.collection_name, key, i)), range(n)))
            data = functools.reduce(lambda x, y: x+y, chunks)

        return classes.utils.py_obj_from_bytes( data )

    def set(self, key, value):
        if not isinstance(value, int) and not isinstance(value, bytes) and not isinstance(value, str):
            raise TypeError("Error, redis values need to be binary, string or numeric")
        self.rdb_conn.set("{}:{}".format(self.collection_name, key), value)

    def set_py_obj(self, key, value):
        """
            BUG: Redis can only store 512MB in 1 value
            Chunk data into 512 MB and create a wrapper to load/save it
        """
        data = classes.utils.py_obj_to_bytes(value)
        if len(data) < 500 * 1024 * 1024:
            self.rdb_conn.set("{}:{}".format(self.collection_name, key), data)
            return

        chunks = classes.utils.chunks_of_size(data, 500 * 1024 * 1024)
        for i, chunk in enumerate(chunks):
            self.rdb_conn.set("{}:{}::part.{}".format(self.collection_name, key, i), chunk)
        self.rdb_conn.set("{}:{}".format(self.collection_name, key), '___DESYL___PART___{}'.format(i+1))


class PostgresDB(Database):
    def __init__(self, config):
        #super().__init__(config)
        classes.utils._desyl_init_class_(self, config)

        self.conn = None

    def connect(self):
        pass_str    = ""
        if hasattr(self.config.database.postgres, "password"):
            if len(self.config.database.postgres.password) > 0:
                pass_str    += "password={}".format(self.config.database.postgres.password)
        self.conn = psycopg2.connect("dbname={} user={} {} host={} port={} connect_timeout=3".format(
            self.config.database.postgres.database,
            self.config.database.postgres.username,
            pass_str,
            self.config.database.postgres.address,
            self.config.database.postgres.port
        ))

    def cursor(self):
        if not self.conn:
            raise RuntimeError("Error, need to connect to database before creating cursor")
        cur = self.conn.cursor()
        cur.execute("set jit=off;")
        return cur

    @timeout_decorator.timeout(5)
    def add_library(self, path):
        """
            Adds a new library to the database and returns its unique ID
        """
        curr = self.cursor()
        curr.execute("""
            INSERT INTO library (path, name) VALUES (%s, %s) RETURNING id
        """, (path, os.path.basename(path)))

        return curr.fetchall()[0][0]

    def library_id(self, path):
        """
            Check if the library is present in the database and return its ID
        """
        curr = self.cursor()
        curr.execute("""SELECT id FROM library WHERE path = %s""", (path, ))
        res = curr.fetchall()
        return False if len(res) == 0 else res[0][0]

    @timeout_decorator.timeout(5)
    def add_binary(self, b):
        """
            Adds a new binary to the database and returns its unique ID
        """
        curr = self.cursor()
        curr.execute("""
            INSERT INTO public.binary 
            (path, name, sha256, linkage, compiler, type, arch, stripped, size, optimisation, language)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) 
            RETURNING id
        """, (b.path, os.path.basename(b.path), b.sha256(), b.linkage, b.compiler,
            'ELF', b.arch, True if b.stripped else False, b.size, b.optimisation,
            b.lang
        ))

        return curr.fetchall()[0][0]

    def binary_symbols(self, binary):
        symbols = []
        curr = self.cursor()
        curr.execute("""
            SELECT public.binary_functions.id, binary_id, public.binary.path, 
                public.binary_functions.name, real_name, vaddr, arguments, 
                heap_arguments, tls_arguments, local_stack_bytes, num_args, 
                return, closure, callees, callers, public.binary_functions.sha256, 
                opcode_hash, asm_hash, public.binary_functions.size, binding, vex, 
                cfg, tainted_flows, public.binary.dynamic_imports 
            FROM public.binary_functions 
            LEFT JOIN public.binary 
            ON binary_id=public.binary.id 
            WHERE public.binary.path = %s;
            """, (binary,))
        known_functions = set()
        for r in curr.fetchall():
            f_id, bin_id, binary_path, name, real_name, vaddr, arguments, heap_arguments, tls_arguments, local_stack_bytes, num_args, ret, closure, callees, callers, sha256, opcode_hash, asm_hash, size, binding, vex, cfg, tainted_flows, dynamic_imports = r
            ##TODO: Need to include dynamic calls/callees to to_vec function
            known_functions = set(dynamic_imports)

            s = classes.symbol.Symbol(self.config, name=name, real_name=real_name, vaddr=vaddr, closure=closure, local_stack_bytes=local_stack_bytes,
                arguments=arguments, heap_arguments=heap_arguments, num_args=num_args, binding=binding, cfg=cfg, callers=callers,
                callees=callees, opcode_hash=bytes(opcode_hash), hash=bytes(sha256), vex=vex, tainted_flows=tainted_flows,
                size=size, _id=f_id)

            symbols.append(s)

        return symbols, known_functions

    def binaries(self):
        curr = self.cursor()
        curr.execute("SELECT path FROM public.binary;")
        for r in curr.fetchall():
            yield r[0]

    def binary_id(self, path):
        """
            Check if the binary is present in the database and return its ID
        """
        curr = self.cursor()
        curr.execute("""SELECT id FROM public.binary WHERE path = %s""", (path, ))
        res = curr.fetchall()
        return False if len(res) == 0 else res[0][0]

    def resolve_library(self, curr, regex_pattern):
        """
            Resolve libraries from database for a regex
        """
        curr.execute("""SELECT id FROM library WHERE name ~ %s""", (regex_pattern,))
        res = curr.fetchall()
        return False if len(res) == 0 else set(map(lambda x: x[0], res))

    def batch_resolve_library_prototypes(self, curr, lib_ids, regex_patterns):
        """
            Resolve libraries from database for a regex
        """
        sql = """SELECT real_name, name, arguments, heap_arguments, tls_arguments, num_args, local_stack_bytes, return FROM library_prototypes WHERE
            library = ANY(%s) AND name LIKE %s"""
 
        psycopg2.extras.execute_batch(curr, sql, zip(itertools.repeat(lib_ids), regex_patterns), page_size=256)
        res = curr.fetchall()

        return list(map(lambda f: False if len(f) == 0 else {
                    'name' : f[1], 'real_name': f[0],
                    'arguments': f[2], 'heap_arguments': f[3], 'tls_arguments': f[4],
                    'num_args': f[5], 'local_stack_bytes': f[6], 'return': f[7]
        }, res))

    def resolve_dynamic_function(self, curr, lib_ids, regex_pattern):
        """
        Resolve regex on function name given a list of library ids
        """
        curr.execute("""
            SELECT real_name, name, arguments, heap_arguments, tls_arguments, 
                num_args, local_stack_bytes, return 
            FROM library_prototypes
            WHERE library = ANY(%s) AND name LIKE %s;
            """, (lib_ids, regex_pattern,))
        res = curr.fetchall()
        for f in res:
            d = {
                    'name' : f[1], 'real_name': f[0],
                    'arguments': f[2], 'heap_arguments': f[3], 'tls_arguments': f[4],
                    'num_args': f[5], 'local_stack_bytes': f[6], 'return': f[7]
            }
            return d
        return False

    def all_known_functions(self):
        return self.all_callees() | self.all_callers()

    def all_callees(self):
        callees = set([])
        curr = self.cursor()
        curr.execute("""
            SELECT DISTINCT(a) 
            FROM (SELECT JSONB_ARRAY_ELEMENTS(callees) as a 
                FROM public.binary_functions) 
            AS foo;
            """)
        for row in curr.fetchall():
            callees.add(row[0])
        return callees

    def all_unknown_functions(self):
        names = set([])
        curr = self.cursor()
        curr.execute("SELECT DISTINCT(name) FROM public.binary_functions")
        for row in curr.fetchall():
            names.add(row[0])
        return names

    def all_callers(self):
        callers = set([])
        curr = self.cursor()
        curr.execute("""
            SELECT DISTINCT(a) 
            FROM (SELECT JSONB_ARRAY_ELEMENTS(callers) as a 
                    FROM public.binary_functions) 
            AS foo;
            """)
        for row in curr.fetchall():
            callers.add(row[0])
        return callers

    def all_referenced_symbol_names(self):
        names = set([])
        curr = self.cursor()
        curr.execute("SELECT name, callees, callers FROM public.binary_functions;")
        for name, callees, callers in curr.fetchall():
            names.add(name)
            names |= set(callers)
            names |= set(callees)

        return names

    def get_all_constants(self):
        curr = self.cursor()
        curr.execute("SELECT vex -> 'constants' FROM public.binary_functions;")
        return functools.reduce(lambda x, y: x + y[0], curr.fetchall(), [])

    def constants_freq(self, max_freq=5, min_freq=3):
        curr = self.cursor()
        curr.execute("""
            SELECT t.count, t.const 
            FROM (SELECT COUNT(*) as count, jsonb_array_elements(vex->'constants') as const 
                    FROM public.binary_functions GROUP BY const) t 
            WHERE t.count < %s AND t.count > %s;
            """, (max_freq, min_freq))
        freq = {}
        for count, const in curr.fetchall():
            freq[const] = count
        return freq

    def function_callers_callees(self, binary_path:str, function:str):
        """
            Return the callers and callees of a function in a binary
        """
        curr = self.cursor()
        curr.execute("""
            SELECT callers, callees 
            FROM public.binary_functions 
            LEFT JOIN public.binary 
            ON public.binary.id = public.binary_functions.binary_id 
            WHERE public.binary.path = %s AND public.binary_functions.name = %s;
            """, (binary_path, function))
        for callers, callees in curr.fetchall():
            return callers, callees
        return None, None

    def add_function_embedding(self, embed_t:str, values:dict):
        """
        UPSERT embeddings into database
        embed_t: type of embeddings to insert
        values: dictionary of column:values to insert

        NB: Need to call database.conn.commit() to commit values to database!
        """
        assert(embed_t in ('dexter', 'safe', 'asm2vec'))
        curr = self.cursor()
        query   = "INSERT INTO embeddings_{} ({}) VALUES ({})".format(embed_t, ", ".join(values.keys()), ", ".join(['%s']*len(values)))
        query   +=" ON CONFLICT (function_id) DO UPDATE SET"
        for key, value in values.items():
            ##skip function_id constraint
            if key == 'function_id':
                continue
            query += " {} = EXCLUDED.{},".format(key, key)
        query   = query[:-1] + ';'
        curr.execute(query, tuple(values.values()))
        return curr.rowcount

    def dexter_feature_vectors(self, limit:int=-1):
        """
            Fetch all function embeddings
            limmit to limit records
        """
        curr = self.cursor()
        query = """
            SELECT embeddings_dexter.function_id, binary_functions.name, binary_functions.real_name, 
                binary_functions.callers, binary_functions.callees, 
                public.binary.path, public.binary.name, 
                embeddings_dexter.categorical_vector, embeddings_dexter.quantitative_vector
            FROM public.embeddings_dexter
            LEFT JOIN public.binary_functions
                ON public.binary_functions.id = public.embeddings_dexter.function_id 
            LEFT JOIN public.binary
                ON public.binary_functions.binary_id = public.binary.id
            """
        if limit != -1:
            query += " LIMIT {}".format(limit)

        curr.execute(query)
        feat_t = namedtuple('feat_t', ['id', 'f_name', 'f_real_name', 'callers', 'callees', 'b_path', 'b_name', 'categorical_vector', 'quantitative_vector'])
        with tqdm(desc='XFL embeddings') as t:
            while True:
                res = curr.fetchmany(128)
                if not res:
                    break
                for r in res:
                    x = tuple(islice(r, 0, 7))
                    y, z = (classes.utils.py_obj_from_bytes_fast(r[7]),), (classes.utils.py_obj_from_bytes_fast(r[8]),)
                    feat = feat_t(*(x + y + z))
                    yield feat
                    t.update(1)

    def get_embeddings(self, mode:str):
        """
            Fetch tuple of name, embeddings from the embeddings_dexter table
            returns a namedtuple for the embedding row

            mode: ('dexter', 'asm2vec', 'safe', ... )
        """
        curr    = self.cursor()
        query   = """
            SELECT embeddings_{mode}.function_id, binary_functions.name, public.binary.name, public.binary.path, embeddings_{mode}.embedding
            FROM embeddings_{mode}
            LEFT JOIN binary_functions 
                ON embeddings_{mode}.function_id = binary_functions.id
            LEFT JOIN public.binary
                ON binary_functions.binary_id = public.binary.id
            WHERE embeddings_{mode}.embedding IS NOT NULL
            AND binary_functions.binding = 'GLOBAL';
        """.format(mode=mode)
        curr.execute(query)
        embed_t = namedtuple('embed_t', ['id', 'f_name', 'b_name', 'b_path', 'embedding'])
        while True:
            res = curr.fetchmany(128)
            if not res:
                break
            for r in res:
                _id, f_name, b_name, b_path, embeddings = r
                ##copy from memoryview
                dp  = embed_t(_id, f_name, b_name, b_path, classes.utils.py_obj_from_bytes_fast(embeddings))
                yield dp
        del curr

    def get_non_null_embeddings(self, mode:str, column: str = 'embedding'):
        curr = self.cursor()
        query = f"SELECT function_id FROM embeddings_{mode} WHERE {column} IS NULL"
        curr.execute(query)
        return list(map(lambda x: x[0], curr.fetchall()))

if __name__ == '__main__':

    from classes.config import Config
    from IPython import embed
    config = Config()
    db = PostgresDB(config)
    db.connect()
    embed()
