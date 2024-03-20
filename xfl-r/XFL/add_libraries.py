
"""

Copyright 2017-2024 by James Patrick-Evans, Moritz Dannehl, Tristan Benoit, and Johannes Kinder.

This file is part of XFL.

XFL is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

XFL is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with XFL. If not, see <https://www.gnu.org/licenses/>. 

"""

#!/usr/bin/python3
import sys, os, re
import logging
import glob
import lief
import psycopg2
import timeout_decorator

from config import Config
from binary import Binary, UnsupportedISA, UnsupportedLang, StrippedBinaryError, FunctionTooLarge, BinaryTooLarge
from database import PostgresDB
from basicblock import NoNativeInstructionsError

from joblib import Parallel, delayed

FAST_MODE = True

#24h timeout
@timeout_decorator.timeout(3600*24)
def custom_analyse_library(c, bin_path):

    c.logger.info("Analysing binary {}".format(bin_path))
    
    try:
        b = Binary(c, path=bin_path, must_resolve_libs=False)

        if b.arch != "x86_64":
            c.logger.warning("Refusing to analyse non-x86_64 binary")
            return False

        #do not analyse c++ binary
        if b.lang != 'c':
            c.logger.warning("Support for non-C binary is experimental")

		
        res = b.analyse_fast()

        db = PostgresDB(c)
        db.connect()
        idLibrary = db.add_library_p(bin_path)
        for proto in res:
            db.add_library_prototype(idLibrary, proto)
        db.conn.commit()
        c.logger.info("Success for {}".format(bin_path))

    except (UnsupportedISA, UnsupportedLang, StrippedBinaryError, BinaryTooLarge,
            FunctionTooLarge, NoNativeInstructionsError) as e:
        c.logger.exception(e.stderror)
        if debug:
            raise e
        return

    except psycopg2.DatabaseError as e:
        c.logger.exception(e)
        if debug:
            raise e
        return

    except Exception as e:
        c.logger.exception(e)
        if debug:
            raise e
        return

def is_elf(fname):
    """
    Determine is a file is an ELF executable
    """
    return lief.is_elf(fname)

#recursively find binaries and analyse symbols
def scan_directory_update(config, d):
    db = PostgresDB(config)
    db.connect()
    bins = set([])
    lib_re = re.compile(r'^.*\.so\.*.*$')
    obj_re = re.compile(r'^.*\.[oa]\.*.*$')

    g = None
    if os.path.isdir(d):
        g = glob.iglob(d + '/**/*', recursive=True)
    elif os.path.isfile(d):
        g = glob.iglob(d + '*', recursive=True)
    else:
        raise Exception("Unknown path `{}`".format(d))

    for f in g:
        try:
            if os.path.isdir(f):
                continue

            if f == '/dbg_elf_bins/libblocksruntime0/usr/lib/x86_64-linux-gnu/libBlocksRuntime.so.0.0.0':
                continue

            if re.match(obj_re, f):
                config.logger.debug("Skipping ELF object file {}".format(f))
                continue

            if not re.match(lib_re, f):
                config.logger.debug("Skipping {}".format(f))
                continue
			
            print(f)
            statinfo = os.stat(f)
            if statinfo.st_size == 0:
                continue

            if statinfo.st_size > 1024 * 1024 * 128:
                config.logger.error("Not analysing >128 MB binary")
                continue

            if not is_elf(f):
                config.logger.warning("{} is not an ELF file! Skipping...".format(f))
                continue

            if db.library_id(f):
                #already analysed
                config.logger.warning("{} is already in the database! Skipping...".format(f))
                continue

            #single threaded
            if not FAST_MODE:
                custom_analyse_library(config, f)
            else:
                bins.add(f)
        except Exception as e:
            config.logger.error(e)
            raise e
            pass

    if FAST_MODE:
        res = Parallel(n_jobs=config.analysis.THREAD_POOL_THREADS)(
                delayed(custom_analyse_library)(config, f) for f in bins
                )
        config.logger.info("Finished analysing {}".format(d))

if __name__ == "__main__":
    config = Config(level=logging.INFO)
    if len(sys.argv) == 3:
        config.logger.info("Enabling DEBUG output")
        config.logger.setLevel(logging.DEBUG)

    config.logger.info("[+] Adding prototypes from libraries in {} with {} processes".format(sys.argv[1], config.analysis.THREAD_POOL_THREADS * FAST_MODE) )
    scan_directory_update(config, sys.argv[1])

