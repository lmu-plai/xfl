
"""

Copyright 2017-2024 by James Patrick-Evans, Moritz Dannehl, Tristan Benoit, and Johannes Kinder.

This file is part of XFL.

XFL is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

XFL is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with XFL. If not, see <https://www.gnu.org/licenses/>. 

"""

#!/usr/bin/python3
import os
import logging
import glob
import lief
import psycopg2
import timeout_decorator
from argparse import ArgumentParser

from config import Config
from binary import Binary, MissingLibrary, UnsupportedISA, UnsupportedLang, StrippedBinaryError, FunctionTooLarge, BinaryTooLarge
from database import PostgresDB
from basicblock import NoNativeInstructionsError
import utils

from joblib import Parallel, delayed


#1 1/2 hour timeout
@timeout_decorator.timeout(5400)
def analyse_binary(c, bin_path, debug=False):
    c.logger.info("Analysing binary {}".format(bin_path))

    try:
        b = Binary(c, path=bin_path, must_resolve_libs=True, linkage="dynamic")

        if b.arch != "x86_64":
            c.logger.warning(f"Binary {bin_path} ISA is not currently supported")
            return

        db = PostgresDB(c)
        db.connect()

        #do not analyse c++ binary
        if b.lang != 'c':
            c.logger.warning("Analysing non-C binary")

        b.analyse(SE_ANALYSIS=True)
        b.taint_func_flows()        
        db.add_analysed_binary(b)
        db.conn.commit()

    except (UnsupportedISA, UnsupportedLang, StrippedBinaryError, BinaryTooLarge, MissingLibrary,
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
    return fname[-2:] != ".o" and lief.is_elf(fname)

# recursively find binaries
def collect_binaries(config, d):
    db = PostgresDB(config)
    db.connect()
    bins = []

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

            statinfo = os.stat(f)
            if statinfo.st_size == 0:
                continue

            if statinfo.st_size > 1024 * 1024 * 128:
                config.logger.error("Not analysing >128 MB binary")
                continue

            if not is_elf(f):
                config.logger.info("{} is not an ELF file! Skipping...".format(f))
                continue

            if db.binary_id(f):
                config.logger.info("{} is already in the database! Skipping...".format(f))
                continue

            bins += [(statinfo.st_size, f)]
        except Exception as e:
            config.logger.error(e)
            raise e    
    return bins

# analyse binaries, sorted by size
def analysis(config, bins, debug, fast):
    config.logger.critical("[+] Analysing {} binaries".format(len(bins)) )
    bins.sort(key=lambda x:x[0])
    bins = [x[1] for x in bins]
    bins.reverse()
    if fast:
        Parallel(n_jobs=config.analysis.THREAD_POOL_THREADS)( delayed(analyse_binary)(config, f, debug=False) for f in bins )
    else:
        for f in bins:
            analyse_binary(config, f, debug=debug)

# recursively find binaries and analyse symbols
def analyse_from_directory(config, d, debug=False, fast=False):    
    bins = collect_binaries(config, d)
    analysis(config, bins, debug, fast)

# get binaries from files and analyse symbols
def analyse_from_file(config, path, debug=False, fast=False):
    FAILED_FILES = [
        '/dbg_elf_bins/eliom/usr/bin/eliomcp',
        '/dbg_elf_bins/binutils-msp430/usr/bin/msp430-nm'
        '/dbg_elf_bins/paxtest/usr/lib/paxtest/getexhaust2',
        '/dbg_elf_bins/paxtest/usr/lib/paxtest/getexhaust1', 
        '/dbg_elf_bins/jfsutils/sbin/fsck.jfs', 
        '/dbg_elf_bins/binutils-msp430/usr/msp430/bin/nm', 
        '/dbg_elf_bins/ncftp/usr/bin/ncftpspooler', 
        '/dbg_elf_bins/eliom/usr/bin/eliomopt', 
        '/dbg_elf_bins/eliom/usr/bin/js_of_eliom', 
        '/dbg_elf_bins/ncftp/usr/bin/ncftpbatch'
    ]
    bins = []
    for f in utils.read_file_lines(path):
        if f in FAILED_FILES:
            continue
        try:
            bins += collect_binaries(config, f)
        except Exception as e:
            config.logger.exception(e)
            if debug:
                raise e
    analysis(config, bins, debug, fast)

if __name__ == "__main__":
    config = Config(level=logging.INFO)

    parser = ArgumentParser()
    parser.add_argument('-v', '--verbose', action='store_true')
    parser.add_argument('-F', '--from-file')
    parser.add_argument('-p', '--path')
    parser.add_argument('--debug', action='store_true', help='Debug mode. Do not ignore errors or undefined behavior.')
    parser.add_argument('--fast', action='store_true' , help='Multiple processes enable.')
    
    args = parser.parse_args()

    if args.verbose:
        config.logger.critical("Enabling DEBUG output")
        config.logger.setLevel(logging.DEBUG)
    else:
        config.logger.setLevel(logging.ERROR)
        
    if args.from_file and args.path:
        config.logger.critical("Error, cannot specify --from-file and --path at the same time")
        exit()

    if args.from_file:
        config.logger.critical("[+] Analsing binaries from file {} with {} processes".format(args.from_file, config.analysis.THREAD_POOL_THREADS * args.fast) )
        analyse_from_file(config, args.from_file, debug=args.debug, fast=args.fast)

    elif args.path:
        config.logger.critical("[+] Analsing binaries in {} with {} processes".format(args.path, config.analysis.THREAD_POOL_THREADS * args.fast) )
        analyse_from_directory(config, args.path, debug=args.debug, fast=args.fast)

    print("Done. Bye!")
