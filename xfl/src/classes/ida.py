
"""

Copyright 2017-2024 by James Patrick-Evans, Moritz Dannehl, and Johannes Kinder.

This file is part of XFL.

XFL is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

XFL is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with XFL. If not, see <https://www.gnu.org/licenses/>. 

"""

#!/usr/bin/pyhton3

import os, sys, json, copy, glob, logging
import multiprocess, progressbar
from multiprocess.pool import ThreadPool
import networkx as nx
from networkx.drawing import nx_agraph
from networkx.drawing.nx_pydot import write_dot
import time, re
import pymongo
from tqdm import tqdm

import context
import classes.utils
import classes.config
import classes.database
import classes.NLP

class IDA:
        def __init__(self, config):
            classes.utils._desyl_init_class_(self, config)
            self.symbol_names_in_db = None
            self.binary_names_in_db = None

        def __del__(self):
            pass

        def canonical_set(self, seta):
            nlp = classes.NLP.NLP(self.config)
            return set( map(lambda x: nlp.canonical_name(x) , seta) )

        def _preload_symbols_in_db(self):
            self.logger.debug("Preloading database symbol names")
            db = classes.database.Database(self.config)
            if not self.symbol_names_in_db:
                #buffer symbols in database
                self.symbol_names_in_db = set( db.distinct_symbol_names() )

            self.logger.debug("Preloading database ELF binary names")
            if not self.binary_names_in_db:
                #self.binary_names_in_db = set( db.distinct_binaries() )
                #get binaries with no xrefs in them!
                self.binary_names_in_db = set([])
                xrefs_counts = db.get_number_of_xrefs()
                for bin_name, num_xrefs in xrefs_counts.items():
                    if num_xrefs == 0:
                        self.binary_names_in_db.add( bin_name )


        def import_xrefs(self, xrefs_path, binary_path):
            self.logger.info("Importing XREFS from {} for {}".format( xrefs_path, binary_path ))
            if not os.path.isfile(binary_path) or not os.access(binary_path, os.X_OK):
                raise Exception("Error, binary_path argument to binary ({}) is not an EXEcutable file!".format(binary_path))
            db = classes.database.Database(self.config)
            nlp = classes.NLP.NLP(self.config)

            #if we have already imported xrefs, skip       
            """
            xrefs = db.get_set_all_xrefs( { '$match' : { 'path' : binary_path } } )
            if len(xrefs) > 0:
                self.logger.warn("Binary {} already has XREFS, skipping IDA import.".format(binary_path))
                return
            """

            #buffer symbols from binary 
            symbols_in_bin = db.get_symbols_from_binary( binary_path )
            symbol_names_in_bin = set(map(lambda x: x.name, symbols_in_bin))
            if len(symbol_names_in_bin) == 0:
                self.logger.warn("No symbols in database for binary :: {}".format( binary_path ))
                return

            xref_counter = 0
            with open(xrefs_path, 'r') as f:
                xrefs = json.load(f)
                q = db.path2query( binary_path )
                updates = []
                for xref in xrefs:
                    ida_name = nlp.strip_ida_decorations( xref['name'] )
                    filtered_name = nlp.strip_library_decorations( ida_name )


                    if filtered_name not in symbol_names_in_bin:
                        self.logger.debug("Symbol name from IDA was not contained in database for this binary! - {} - {}".format(filtered_name, xrefs_path))
                        continue

                    q['name'] = filtered_name


                    #new_callees = list( set(filter(lambda x: x in self.symbol_names_in_db, filtered_callees)) )
                    ##CALL REFERENCES TO
                    filtered_callees = set( nlp.filter_ida_junk( xref['CT'] ) )
                    new_callees = list(set(map(lambda x: nlp.strip_library_decorations( nlp.strip_ida_decorations( x ) ), filtered_callees )))
                    new_callees = nlp.filter_null(new_callees)


                    ##CALL REFERENCES FROM
                    filtered_callers = set( nlp.filter_ida_junk( xref['CF'] ) )
                    new_callers = list( set(map(lambda x: nlp.strip_library_decorations( nlp.strip_ida_decorations( x ) ), filtered_callers)) )
                    new_callers = nlp.filter_null(new_callers)

                    ##DATA REFERENCES FROM
                    filtered_dcallers = set( nlp.filter_ida_junk( list( set(filter(lambda x: isinstance(x, str), xref['DF'])) ) ) )
                    new_dcallers = list( set(map(lambda x: nlp.strip_library_decorations( nlp.strip_ida_decorations( x ) ), filtered_dcallers)) )
                    new_dcallers = nlp.filter_null(new_dcallers)

                    ##DATA REFERENCES TO
                    filtered_dcallees = set( nlp.filter_ida_junk( list( set(filter(lambda x: isinstance(x, str), xref['DT'])) ) ) )
                    new_dcallees = list( set(map(lambda x: nlp.strip_library_decorations( nlp.strip_ida_decorations( x ) ), filtered_dcallees)) )
                    new_dcallees = nlp.filter_null(new_dcallees)

                    ### Append callers and Callees, for each symbol named {{name}} in this binary (may be multiple)
                    #############

                    #print(new_callers)
                    #print(new_callees)
                    #res = db.client[self.config.database.collection_name].find( q )


                    #update all with updateMany i.e. UPDATE ALL SYMBOSL NAMED X IN BINARY, not just the first occourance! and yes, this does happen in real life!
                    db_update = pymongo.UpdateMany( copy.deepcopy(q), { '$addToSet': {
                            'callers':  { '$each' : copy.deepcopy(new_callers)  },
                            'callees':  { '$each' : copy.deepcopy(new_callees)  },
                            'dcallers': { '$each' : copy.deepcopy(new_dcallers) },
                            'dcallees': { '$each' : copy.deepcopy(new_dcallees) }
                        }
                    } )
                    
                    """
                    for r in res:
                        db.client[self.config.database.collection_name].update( q, 
                            { '$addToSet': {
                                'callers': { '$each' : new_callers },
                                'callees': { '$each' : new_callees }
                                }
                            })
                    """
                    new_xrefs = len(new_callers) + len(new_callees)
                    xref_counter += new_xrefs
                    ##only add DB operation if new xrefs are found
                    if new_xrefs > 0:
                        updates.append( db_update )


                if len(updates) == 0:
                    logger.info("No XREFS to import for binary {}".format(binary_path))
                    return

                try:
                    res = db.client[self.config.database.collection_name].bulk_write( updates, ordered=False )
                    #logger.info(res)
                    #import IPython
                    #IPython.embed()
                    #logger.info(res.bulk_api_result)
                    if len(res.bulk_api_result['writeErrors']) > 0:
                        logger.error("Error bulk insert xrefs, dropping to IPython shell")
                        import IPython
                        IPython.embed()
                        raise Exception("Did not successfully update all XREFS for binary {}!".format(binary_path))
                except pymongo.errors.BulkWriteError as bwe:
                    logger.error(bwe.details)
                    
            self.logger.info("Imported {} XREFS for {}".format( xref_counter, binary_path))



        @staticmethod
        def _mt_import_xrefs(xrefs_path, binary_path):
            config = classes.config.Config(no_logging=True)
            ida = IDA(config)
            db = classes.database.Database(config)
            nlp = classes.NLP.NLP(config)

            ida.logger.info("Importing XREFS from {} for {}".format( xrefs_path, binary_path ))
            if not os.path.isfile(binary_path) or not os.access(binary_path, os.X_OK):
                raise Exception("Error, binary_path argument to binary ({}) is not an EXEcutable file!".format(binary_path))
            db = classes.database.Database(ida.config)
            nlp = classes.NLP.NLP(ida.config)

            #buffer symbols from binary 
            symbols_in_bin = db.get_symbols_from_binary( binary_path )
            symbol_names_in_bin = set(map(lambda x: x.name, symbols_in_bin))
            if len(symbol_names_in_bin) == 0:
                ida.logger.warn("No symbols in database for binary :: {}".format( binary_path ))
                return

            xref_counter = 0
            with open(xrefs_path, 'r') as f:
                xrefs = json.load(f)
                q = db.path2query( binary_path )
                updates = []
                for xref in xrefs:
                    ida_name = nlp.strip_ida_decorations( xref['name'] )
                    filtered_name = nlp.strip_library_decorations( ida_name )

                    if filtered_name not in symbol_names_in_bin:
                        ida.logger.debug("Symbol name from IDA was not contained in database for this binary! - {} - {}".format(filtered_name, xrefs_path))
                        continue

                    q['name'] = filtered_name

                    #new_callees = list( set(filter(lambda x: x in ida.symbol_names_in_db, filtered_callees)) )
                    ##CALL REFERENCES TO
                    filtered_callees = set( nlp.filter_ida_junk( xref['CT'] ) )
                    new_callees = list(set(map(lambda x: nlp.strip_library_decorations( nlp.strip_ida_decorations( x ) ), filtered_callees )))


                    ##CALL REFERENCES FROM
                    filtered_callers = set( nlp.filter_ida_junk( xref['CF'] ) )
                    new_callers = list( set(map(lambda x: nlp.strip_library_decorations( nlp.strip_ida_decorations( x ) ), filtered_callers)) )

                    ##DATA REFERENCES FROM
                    filtered_dcallers = set( nlp.filter_ida_junk( list( set(filter(lambda x: isinstance(x, str), xref['DF'])) ) ) )
                    new_dcallers = list( set(map(lambda x: nlp.strip_library_decorations( nlp.strip_ida_decorations( x ) ), filtered_dcallers)) )

                    ##DATA REFERENCES TO
                    filtered_dcallees = set( nlp.filter_ida_junk( list( set(filter(lambda x: isinstance(x, str), xref['DT'])) ) ) )
                    new_dcallees = list( set(map(lambda x: nlp.strip_library_decorations( nlp.strip_ida_decorations( x ) ), filtered_dcallees)) )

                    #update all with updateMany i.e. UPDATE ALL SYMBOSL NAMED X IN BINARY, not just the first occourance! and yes, this does happen in real life!
                    db_update = pymongo.UpdateMany( copy.deepcopy(q), { '$addToSet': {
                            'callers':  { '$each' : copy.deepcopy(new_callers)  },
                            'callees':  { '$each' : copy.deepcopy(new_callees)  },
                            'dcallers': { '$each' : copy.deepcopy(new_dcallers) },
                            'dcallees': { '$each' : copy.deepcopy(new_dcallees) }
                        }
                    } )

                    new_xrefs = len(new_callers) + len(new_callees)
                    xref_counter += new_xrefs
                    ##only add DB operation if new xrefs are found
                    if new_xrefs > 0:
                        updates.append( db_update )

                if len(updates) == 0:
                    logger.info("No XREFS to import for binary {}".format(binary_path))
                    return

                return -1

                try:
                    res = db.client[ida.config.database.collection_name].bulk_write( updates, ordered=False )
                    if len(res.bulk_api_result['writeErrors']) > 0:
                        logger.error("Error bulk insert xrefs, dropping to IPython shell")
                        raise Exception("Did not successfully update all XREFS for binary {}!".format(binary_path))
                except pymongo.errors.BulkWriteError as bwe:
                    logger.error(bwe.details)
                    
            ida.logger.info("Imported {} XREFS for {}".format( xref_counter, binary_path))

        def __import_xref_cb(self, res):
            self.pbar.value += 1
            logger.info(res)
            self.pbar.update()

        def __import_xref_err(self, err):
            self.pbar.value += 1
            self.logger.error("Error importing XREFs")
            self.logger.error(err)
            self.pbar.update()

        def __init_pbar(self):
            self.pbar = progressbar.ProgressBar(widgets=classes.utils.pbar_config,max_value=0)
            self.pbar.value = 0

        def import_xref_corpus(self, dir):
            self.logger.info("Importing XREF files from " + self.config.corpus + "/" + dir)

            self.logger.info("Preloading symbols in Database!")
            self._preload_symbols_in_db()

            self.logger.info("Loading processbar and starting import")
            self.__init_pbar()

            results = []
            args = []
            mp = ThreadPool(processes=32)
            lib_regex = re.compile(r'(\.(o|so|oS|a)$)|(\.so\.)', re.IGNORECASE)
            for f in glob.iglob(self.config.corpus + "/" + dir + '/**/*.xrefs', recursive=True):
                m = lib_regex.match(f)
                if m:
                    continue

                self.logger.debug("Using file: " + f)
                
                if f[:-6] not in self.binary_names_in_db:
                    self.logger.info("{} is not contained in db".format( f[:-6] ))
                    continue

                xrefs_fname = f[:]
                bin_fname = f[:-6]

                r = mp.apply_async( IDA._mt_import_xrefs, ( xrefs_fname, bin_fname ), error_callback=self.__import_xref_err )
                results.append( r )
                self.pbar.max_value += 1


            self.logger.info("Getting results!")
            for r in results:
                while True:
                    r.wait(1) #1s timeout
                    if r.ready():
                        r.get()
                        self.pbar.value += 1
                        break
                    self.pbar.update()

            self.pbar.value = self.pbar.max_value
            self.pbar.update()
            self.pbar.finish()


            self.logger.info("Got all results!!")

        def import_xref_corpus_from_db_list(self, paths):
            self.logger.info("Importing XREF files from unknowns in db")

            self.logger.info("Preloading symbols in Database!")
            self._preload_symbols_in_db()

            self.logger.info("Fetching all unknown symbol binaries")
            db = classes.database.Database(self.config)

            self.logger.info(len(paths))

            for f in tqdm(paths):
                self.logger.debug("Using binary: " + f)

                if not os.path.isfile(f+".xrefs"):
                    self.logger.error("Missing XREFS for binary {}".format(f))
                    continue

                self.import_xrefs(f + ".xrefs", f)

            self.logger.info("Finished importing XREFS!")
            return


        def _mt_import_xref_corpus_from_db_list(self, paths):
            self.logger.info("Importing XREF files from unknowns in db")

            self.logger.info("Preloading symbols in Database!")
            self._preload_symbols_in_db()

            self.logger.info("Fetching all unknown symbol binaries")
            db = classes.database.Database(self.config)

            self.logger.info(len(paths))



            results = []
            args = []
            mp = multiprocess.Pool(processes=32)
            for f in paths:
                self.logger.debug("Using file: " + f)
                
                if f[:-6] not in self.binary_names_in_db:
                    self.logger.info("{} is not contained in db".format( f[:-6] ))
                    continue

                #"""
                xrefs_fname = f[:]
                bin_fname = f[:-6]

                #r = mp.apply_async( self.import_xrefs, ( xrefs_fname, bin_fname ), error_callback=self.__import_xref_err )
                #r = mp.apply_async( self.import_xrefs, ( xrefs_fname, bin_fname ) )

                ####Try using mp.start!

                #results.append( r )
                #args.append( (f[:], f[:-6] ) )
                #self.pbar.max_value += 1
                self.import_xrefs(f[:], f[:-6])
                #"""






                if not os.path.isfile(f+".xrefs"):
                    self.logger.error("Missing XREFS for binary {}".format(f))
                    continue

                self.import_xrefs(f + ".xrefs", f)

            self.logger.info("Finished importing XREFS!")
            return





if __name__ == '__main__':
    global config
    global logger
    config = classes.config.Config()
    config.logger.setLevel( logging.INFO )
    logger = config.logger
    ida = IDA(config)

    db = classes.database.Database(config)
    #unknowns = db.get_unknown_symbol_binaries()
    unknowns = classes.utils.load_py_obj(config, "unknown_symbol_binaries")
    logger.info("Importing XREFS from {} binaries".format(len(unknowns)))

    ida.import_xref_corpus("debian")
    #ida.import_xref_corpus_from_db_list(unknowns)
    #ida.import_xrefs("/root/friendly-corpus/debian/xmms2-client-cli/usr/bin/xmms2.xrefs.old", "/root/friendly-corpus/debian/xmms2-client-cli/usr/bin/xmms2")

    #ida.import_xref_corpus("bin/dynamic/clang/og")

