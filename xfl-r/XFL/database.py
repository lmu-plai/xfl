
"""

Copyright 2017-2024 by James Patrick-Evans, Moritz Dannehl, Tristan Benoit, and Johannes Kinder.

This file is part of XFL.

XFL is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

XFL is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with XFL. If not, see <https://www.gnu.org/licenses/>. 

"""

#!/usr/bin/python3
import json
import functools, itertools
import timeout_decorator
import pickle
import os
import psycopg2
import psycopg2.extras
from itertools import islice
from tqdm import tqdm
from collections import namedtuple

import utils
import symbol

class PostgresDB():
    def __init__(self, config):
        utils._desyl_init_class_(self, config)
        self.conn = None

    def connect(self):
        pass_str    = ""
        if hasattr(self.config.database.postgres, "password"):
            if len(self.config.database.postgres.password) > 0:
                pass_str    += "password={}".format(self.config.database.postgres.password)
        
        self.conn = psycopg2.connect("dbname={} user={} {} host={} port={} connect_timeout=3600".format(
            self.config.database.postgres.database,
            self.config.database.postgres.username,
            pass_str,
            self.config.database.postgres.address,
            self.config.database.postgres.port
        ))

    @timeout_decorator.timeout(500)
    def add_binary(self, b):
        """
            Adds a new binary to the database and returns its unique ID
        """
        curr = self.conn.cursor()
        curr.execute("""
            INSERT INTO binaries 
            (path, name, sha256, linkage, compiler, arch, stripped, size, optimisation, language, bin_format, bin_type)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) 
            RETURNING id
        """, (b.path, b.name, b.sha256(), b.linkage, b.compiler,
            b.arch, True if b.stripped else False, b.size, b.optimisation,
            b.lang, b.bin_format, b.bin_type
        ))

        return curr.fetchall()[0][0]        

    def binary_symbols(self, binary):
        symbols = []
        fIds = []
        curr = self.conn.cursor()
        
        
        curr.execute("""
            SELECT functions.id, functions.name, real_name, vaddr, arguments, 
                heap_arguments, local_stack_bytes, num_args, 
                noreturn, tls_arguments, closure, functions.sha256, 
                opcode_hash, asm_hash, functions.size, binding, vex, callers, 
                callees, cfg, tainted_flows, tainted_args,
                tainted_args_closure, icfg_embedding, callgraph_node_embedding,
                data_refs, imported_data_refs, opcode_minhash,
                signature, returns, sse, binaries.dynamic_imports
            FROM functions 
            LEFT JOIN binaries 
            ON binary_id=binaries.id 
            WHERE binaries.path = %s;
            """, (binary,))

        known_functions = set()
        for r in curr.fetchall():
            (fId, name, real_name, vaddr, arguments, heap_arguments, local_stack_bytes, num_args, noreturn, tls_arguments, closure, sha256, opcode_hash, asm_hash, size, binding, vex, callers, callees, cfg, tainted_flows, tainted_args, tainted_args_closure, icfg_embedding, callgraph_node_embedding, data_refs, imported_data_refs, opcode_minhash, signature, returns, sse, dynamic_imports) = r
            known_functions = set(dynamic_imports)
            
            s = symbol.Symbol(self.config, name=name, real_name=real_name, vaddr=int(vaddr), sse=sse, closure=closure, local_stack_bytes=local_stack_bytes,
               arguments=arguments, heap_arguments=heap_arguments, num_args=num_args, binding=binding, cfg=cfg, callers=callers,
               callees=callees, opcode_hash=bytes(opcode_hash), opcode_minhash=utils.py_obj_from_bytes(opcode_minhash), hash=bytes(sha256), vex=vex, tainted_flows=tainted_flows,
               size=size, returns=returns, noreturn=noreturn, signature=signature, tainted_args=tainted_args, tainted_args_closure=tainted_args_closure, 
               icfg_embedding=utils.py_obj_from_bytes(icfg_embedding), node_embedding=utils.py_obj_from_bytes(callgraph_node_embedding), data_refs=data_refs, imported_data_refs=imported_data_refs)
            
            symbols += [s]
            fIds    += [fId]
        return symbols, known_functions, fIds


    def binaries(self):
        curr = self.conn.cursor()
        curr.execute("SELECT path FROM binaries;")
        for r in curr.fetchall():
            yield r[0]

    def binary_ids(self):
        curr = self.conn.cursor()
        curr.execute("SELECT id FROM binaries;")
        for r in curr.fetchall():
            yield r[0]

    def binary(self, binary_id: int = -1, sha256: str = ''):
        """Return a binary object for a given Binary ID or SHA256 hash"""

        Binary = namedtuple('Binary', 'id path name optimisation linkage compiler bin_format bin_type arch sha256 stripped size language dynamic_imports version')
        curr = self.conn.cursor()

        # one parameter must be given
        assert(binary_id != -1 or sha256 != '')

        if binary_id != -1:
            curr.execute("SELECT id, path, name, optimisation, linkage, compiler, bin_format, bin_type, arch, sha256, stripped, size, language, dynamic_imports, version FROM binaries WHERE id = %s" , (binary_id, ))
        else:
            curr.execute("SELECT id, path, name, optimisation, linkage, compiler, bin_format, bin_type, arch, sha256, stripped, size, language, dynamic_imports, version FROM binaries WHERE sha256 = %s" , (sha256, ))

        res = curr.fetchone()
        if res:
            return Binary(*res)
        return None



    def binary_id(self, path: str):
        """
            Check if the binary is present in the database and return its ID
        """
        curr = self.conn.cursor()
        curr.execute("""SELECT id FROM binaries WHERE path = %s""", (path, ))
        res = curr.fetchall()
        return False if len(res) == 0 else res[0][0]

    def binary_ids_from_paths(self, paths):
        curr = self.conn.cursor()
        curr.execute("SELECT id FROM public.binaries WHERE public.binaries.path IN ('{}')".format("','".join(paths)))
        return list(map(lambda x: x[0], curr.fetchall()))        

    def binary_paths_from_ids(self, idS):
        curr = self.conn.cursor()
        curr.execute("SELECT path FROM public.binaries WHERE public.binaries.id IN ({})".format(",".join(map(lambda x: str(x), idS))))
        return list(map(lambda x: x[0], curr.fetchall()))        
        
    def all_known_functions(self, filter_bin_ids=None):
        return self.all_callees(filter_bin_ids) | self.all_callers(filter_bin_ids)

    def all_callees(self, filter_bin_ids=None):
        callees = set([])
        curr = self.conn.cursor()
        query = """
            SELECT DISTINCT(a) 
            FROM (SELECT JSONB_ARRAY_ELEMENTS(callees) as a 
                FROM functions  """

        if filter_bin_ids:
            query += " WHERE functions.binary_id IN ({})".format(",".join(map(lambda x: str(x), filter_bin_ids)))

        query += """) 
            AS foo
            """
        curr.execute(query)
        for row in curr.fetchall():
            callees.add(row[0])
        return callees

    def all_unknown_functions(self, filter_bin_ids=None):
        names = set([])
        curr = self.conn.cursor()
        query = "SELECT DISTINCT(name) FROM functions"
        if filter_bin_ids:
            query += " WHERE functions.binary_id IN ({})".format(",".join(map(lambda x: str(x), filter_bin_ids)))
        curr.execute(query)
        for row in curr.fetchall():
            names.add(row[0])
        return names

    def all_callers(self, filter_bin_ids=None):
        callers = set([])
        curr = self.conn.cursor()
        query = """
            SELECT DISTINCT(a) 
            FROM (SELECT JSONB_ARRAY_ELEMENTS(callers) as a 
                    FROM functions  """

        if filter_bin_ids:
            query += " WHERE functions.binary_id IN ({})".format(",".join(map(lambda x: str(x), filter_bin_ids)))

        query += """) 
            AS foo;
            """

        curr.execute(query)

        for row in curr.fetchall():
            callers.add(row[0])
        return callers

    def constants_freq(self, max_freq=30, min_freq=5, min_value=2**16, filter_bin_ids=None):
        curr = self.conn.cursor()
        query = """
            SELECT t.count, t.const 
            FROM (SELECT COUNT(*) as count, jsonb_array_elements(vex->'constants') as const 
                    FROM functions"""

        if filter_bin_ids:
            query += " WHERE functions.binary_id IN ({})".format(",".join(map(lambda x: str(x), filter_bin_ids)))

        query += """
                GROUP BY const) t 
            WHERE t.count < %s AND t.count > %s AND t.const::bigint > %s
            """

        self.logger.info("Postgres: Executing SQL: {}".format(query))
        curr.execute(query, (max_freq, min_freq, min_value))
        freq = {}
        for count, const in curr.fetchall():
            freq[const] = count
        return freq

    def add_functions_embedding(self, data):
        curr = self.conn.cursor()
        psycopg2.extras.execute_values ( curr, 'INSERT INTO embedding_binnet (function_id, embedding) values %s ON CONFLICT (function_id) DO UPDATE SET embedding = excluded.embedding', data, template=None, page_size=100 )

    def binary_functions_names(self, binary):
        symbols = []

        curr = self.conn.cursor()
        curr.execute("""
            SELECT binaries.id , functions.id, functions.name, functions.real_name
            FROM functions 
            LEFT JOIN binaries
            ON binary_id=binaries.id 
            WHERE binaries.path = %s AND functions.binding = 'GLOBAL';
            """, (binary,))

        for r in curr.fetchall():
            (bId, fId, name, real_name) = r
            symbols += [[bId, fId, name, real_name]]

        return symbols

    def binary_functions_blens_info(self, binary, inference_mode=False):
        symbols = []

        curr = self.conn.cursor()
        req = """
            SELECT binaries.id , functions.id, functions.name, functions.real_name, functions.vaddr
            FROM functions 
            LEFT JOIN binaries
            ON binary_id=binaries.id 
            WHERE binaries.path = %s
            """
        if inference_mode == False:
            req += " AND functions.binding = 'GLOBAL';"
        else:
            req += ";"
        curr.execute(req, (binary,))

        for r in curr.fetchall():
            (bId, fId, name, real_name, vaddr) = r
            symbols += [[bId, fId, name, real_name, vaddr]]

        return symbols

    def functions_embeddings(self):
        embeddings = {}
        curr = self.conn.cursor()        
        
        curr.execute("""
            SELECT function_id, embedding
            FROM embedding_binnet           
            """)

        for r in tqdm(curr.fetchall()):
            (fId, X) = r
            embeddings[fId] = utils.py_obj_from_bytes(X)            
        return embeddings

    """
        Return binary info from postgres 
    """
    def get_binaries(self, bin_ids=None):
        curr    = self.conn.cursor()
        query   = """
            SELECT id, path, name, optimisation, linkage, compiler, bin_type, bin_format, arch,
                    sha256, stripped, size, language 
            FROM binaries
            """

        if bin_ids:
            query += " WHERE id IN ({})".format(",".join(map(lambda x: str(x), bin_ids)))

        curr.execute(query)
        binary_t    = namedtuple('binary_t', 
                ['id', 'path', 'name', 'optimisation', 'linkage', 'compiler', 
                    'bin_type', 'bin_format', 'arch', 'sha256', 'stripped', 'size', 'language'])

        while True:
            res = curr.fetchmany(128)
            if not res:
                break

            for r in res:
                sha_hash   = bytes(r[9])
                yield binary_t(*r[:9] + tuple([sha_hash]) + r[10:])
 

    def add_analysed_binary(self, b):
        ##safety checks
        assert(len(b.symbols) > 0)

        ##add binary and get ID
        bin_id = self.add_binary(b)

        cur = self.conn.cursor()
        imp_funcs = list(map(lambda x: x['name'], b.dyn_imports))
        cur.execute("UPDATE binaries SET dynamic_imports = %s WHERE id = %s", (json.dumps(imp_funcs), bin_id))

        for s in tqdm(b.symbols, desc="Database insertion"):
            ##convert sets to lists to serialise them
            s.vex['constants'] = list(s.vex['constants'])
            ##tainted struct to lists
            for s_attr in ('tainted_args', 'tainted_args_closure'):
                val = getattr(s, s_attr)
                for arg in val.keys():
                    for func in val[arg].keys():
                        val[arg][func]   = list(val[arg][func])
                ##write back
                setattr(s, s_attr, val)

            cur.execute("""
                INSERT INTO functions (
                    binary_id, name, real_name, vaddr, arguments, heap_arguments, local_stack_bytes, 
                    num_args, noreturn, tls_arguments, closure, sha256, opcode_hash, asm_hash, size, 
                    binding, vex, callers, callees, cfg, tainted_flows, tainted_args, 
                    tainted_args_closure, icfg_embedding, callgraph_node_embedding, data_refs, 
                    imported_data_refs, opcode_minhash, signature, returns, sse)
                VALUES (
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
                );
            """, ( bin_id,
                s.name, s.real_name, s.vaddr, json.dumps(s.arguments), 
                json.dumps(s.heap_arguments), s.local_stack_bytes,
                s.num_args, s.noreturn,
                json.dumps(s.tls) ,
                json.dumps(s.closure), s.sha256(), s.opcode_hash, s.hash,
                s.size, s.binding, json.dumps(s.vex), json.dumps(list(s.callers)), 
                json.dumps(list(s.callees)), utils.nx_to_str(s.cfg),
                json.dumps(s.tainted_flows), json.dumps(s.tainted_args), json.dumps(s.tainted_args_closure), 
                pickle.dumps(s.icfg_embedding), pickle.dumps(s.node_embedding), json.dumps(s.data_refs), json.dumps(s.imported_data_refs), 
                pickle.dumps(s.opcode_minhash), s.signature, s.returns, json.dumps(s.sse))
            )
    
    def library_id(self, path):
        """
            Check if the library is present in the database and return its ID
        """
        curr = self.conn.cursor()
        curr.execute("""SELECT id FROM public.library_p WHERE path = %s""", (path, ))
        res = curr.fetchall()
        return False if len(res) == 0 else res[0][0]

    def resolve_library(self, curr, regex_pattern):
        """
            Resolve libraries from database for a regex
        """
        curr.execute("""SELECT id FROM public.library_p WHERE name ~ %s""", (regex_pattern,))
        res = curr.fetchall()
        return False if len(res) == 0 else set(map(lambda x: x[0], res))

    def batch_resolve_library_prototypes(self, curr, lib_ids, regex_patterns):
        """
            Resolve libraries from database for a regex
        """
        sql = """SELECT real_name, name, arguments, heap_arguments, tls_arguments, num_args, local_stack_bytes, return FROM public.library_prototypes WHERE
            library = ANY(%s) AND name LIKE %s"""
 
        psycopg2.extras.execute_batch(curr, sql, zip(itertools.repeat(lib_ids), regex_patterns), page_size=256)
        res = curr.fetchall()

        return list(map(lambda f: False if len(f) == 0 else {
                    'name' : f[1], 'real_name': f[0],
                    'arguments': f[2], 'heap_arguments': f[3], 'tls_arguments': f[4],
                    'num_args': f[5], 'local_stack_bytes': f[6], 'returns': f[7]
        }, res))

    def resolve_dynamic_function(self, curr, lib_ids, regex_pattern):
        """
        Resolve regex on function name given a list of library ids
        """
        curr.execute("""
            SELECT real_name, name, arguments, heap_arguments, tls_arguments, 
                num_args, local_stack_bytes, return
            FROM public.library_prototypes
            WHERE library = ANY(%s) AND name LIKE %s;
            """, (lib_ids, regex_pattern,))
        res = curr.fetchall()
        for f in res:
            d = {
                    'name' : f[1], 'real_name': f[0],
                    'arguments': f[2], 'heap_arguments': f[3], 'tls_arguments': f[4],
                    'num_args': f[5], 'local_stack_bytes': f[6], 'returns': f[7]
            }
            return d
        return False

    def binary_paths(self):
        curr = self.conn.cursor()
        curr.execute("SELECT path FROM public.binaries;")
        return set(map(lambda x:x[0], curr.fetchall()))

    def library_paths(self):
        curr = self.conn.cursor()
        curr.execute("SELECT path FROM public.library_p;")
        return set(map(lambda x:x[0], curr.fetchall()))

    @timeout_decorator.timeout(500)
    def add_library_p(self, path):
        curr = self.conn.cursor()
        curr.execute("""
            INSERT INTO public.library_p (path, name) VALUES (%s, %s) RETURNING id
        """, (path, os.path.basename(path)))

        return curr.fetchall()[0][0]
                        
    @timeout_decorator.timeout(500)
    def add_library_prototype(self, idLibrary, d):        
        d["args"] = psycopg2.extras.Json(d["args"])
        d["heap_args"] = psycopg2.extras.Json(d["heap_args"])
        d["tls_args"] = psycopg2.extras.Json(d["tls_args"])

        l =  [ d[x] for x in  ["name", "real_name", "local_stack_bytes", "args", "num_args", "heap_args", "ret", "tls_args"]]
        curr = self.conn.cursor()
        curr.execute("""
            INSERT INTO public.library_prototypes 
            (library, name, real_name, local_stack_bytes, arguments, num_args, heap_arguments, return, tls_arguments)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id
        """, (idLibrary, *l))
        return curr.fetchall()[0][0]
    
    @timeout_decorator.timeout(500)
    def add_binary_from_data(self, d):
        d["dynamic_imports"] = psycopg2.extras.Json(d["dynamic_imports"])
        l =  [ d[x] for x in ["path", "name", "sha256", "linkage", "compiler", "arch", "stripped", "size", "optimisation", "language", "bin_format", "bin_type", "dynamic_imports"] ]
        curr = self.conn.cursor()
        curr.execute("""
            INSERT INTO binaries 
            (path, name, sha256, linkage, compiler, arch, stripped, size, optimisation, language, bin_format, bin_type, dynamic_imports)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) 
            RETURNING id
        """, (*l,))
        return curr.fetchall()[0][0]
        
    @timeout_decorator.timeout(500)
    def add_function_fron_data(self, binId, d):
        d["arguments"] = psycopg2.extras.Json(d["arguments"])
        d["heap_arguments"] = psycopg2.extras.Json(d["heap_arguments"])
        d["tls_arguments"] = psycopg2.extras.Json(d["tls_arguments"])
        d["tainted_flows"] = psycopg2.extras.Json(d["tainted_flows"])
        d["callers"] = psycopg2.extras.Json(d["callers"])
        d["callees"] = psycopg2.extras.Json(d["callees"])
        d["vex"] = psycopg2.extras.Json(d["vex"])
        d["closure"] = psycopg2.extras.Json(d["closure"])
        d["tainted_args"] = psycopg2.extras.Json(d["tainted_args"])
        d["tainted_args_closure"] = psycopg2.extras.Json(d["tainted_args_closure"])
        d["data_refs"] = psycopg2.extras.Json(d["data_refs"])
        d["imported_data_refs"] = psycopg2.extras.Json(d["imported_data_refs"])
        d["sse"] = psycopg2.extras.Json(d["sse"])
              
        l =  [ d[x] for x in ["real_name", "name", "local_stack_bytes", "arguments", "num_args", "heap_arguments", "returns", "tls_arguments", "tainted_flows", "cfg", "callers", "callees", "vex", "closure", "sha256", "opcode_hash", "asm_hash", "size", "binding", "vaddr", "tainted_args", "tainted_args_closure", "callgraph_node_embedding", "icfg_embedding", "data_refs", "opcode_minhash", "imported_data_refs", "signature", "noreturn", "sse"] ]
        curr = self.conn.cursor()
        curr.execute("""
            INSERT INTO functions (
                binary_id, real_name, name, local_stack_bytes, arguments, num_args, heap_arguments, returns, tls_arguments, 
                tainted_flows, cfg, callers, callees, vex, closure, sha256, opcode_hash, asm_hash, size, binding, vaddr,
                tainted_args, tainted_args_closure, callgraph_node_embedding, icfg_embedding, data_refs, opcode_minhash,
                imported_data_refs, signature, noreturn, sse)
            VALUES (
                %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
            );
        """, (binId, *l))

            
