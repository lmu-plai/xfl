
"""

Copyright 2017-2024 by James Patrick-Evans, Moritz Dannehl, Tristan Benoit, and Johannes Kinder.

This file is part of XFL.

XFL is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

XFL is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with XFL. If not, see <https://www.gnu.org/licenses/>. 

"""

#!/usr/bin/python3
import json
import os
import sys
import re
import logging
import copy
import coloredlogs


class Config:
    config = None
    ##custom colors for each log level
    ##below colours all logs from external libraries and enables their output!
    #coloredlogs.install()

    def __new__(cls, config_file="desyl.conf", level=logging.DEBUG, format='%(asctime)s [%(levelname)s] %(message)s', no_logging=False):
        if Config.config != None:
            return Config.config
        return super(Config, cls).__new__(cls)

    #def __init__(self, config_file="desyl.conf", level=logging.DEBUG, format='%(asctime)s [%(levelname)s] %(filename)s | %(lineno)s | %(function)s :: %(message)s', no_logging=False):
    def __init__(self, config_file="desyl.conf", level=logging.DEBUG, format='%(asctime)s :: %(message)s', no_logging=False):

        # check if global config has already been initialised
        if Config.config != None:
            self = copy.copy(Config.config)
            return

        # dynamically find desyl.conf from cwd
        for i in range(4):
            if os.path.isfile(config_file):
                break
            config_file = "../" + config_file

        self.format = format
        self.conf_file = config_file

        self.loggerConsoleHandler = None
        self.loggerFileHandler = None

        ##disable logging from other loggers
        logging.getLogger("claripy.ast.bool").setLevel(logging.WARNING)
        logging.getLogger("claripy.backends.backend_z3").setLevel(logging.WARNING)

        assert(os.path.isfile(config_file))
        self._parse_config()
        if no_logging:
            self.removeLoggerHandlers()
        else:
            self.logger.setLevel(level)

        ##expeirment name should be made to SQL table in postgres
        ##limit to allowed chars only, remove '-'
        if not re.match(r'^[a-zA-Z0-9_]+$', self.experiment.name):
            print("Experiment name configuration must only contain alphanumeric characters and underscores")
            raise ValueError("Error in configuration file. Key `experiment.name` must be alpha-numeric or underscores.")

        # Should only be one instance of Config() per python env!
        #global config
        #global logger
        Config.config = copy.copy(self)

        # register pickle function to allow pickling of instances of methods
        #self.allow_pickle_methods()

        coloredlogs.install(logger=self.logger, level='DEBUG')
        self.logger.debug( "[+] config :: Successfully initialised config.")

    @staticmethod
    def dict_to_attr(self, d):
        for k in d.keys():
            if isinstance(d[k], dict):
                setattr(self, k, Config.dict_to_attr(lambda: None, d[k]))
            # support bool types
            elif isinstance(d[k], str):
                if d[k].lower() in ["true", "false"]:
                    setattr(self, k, True if d[k].lower() == "true" else False)
                else:
                    setattr(self, k, d[k])
            else:
                setattr(self, k, d[k])
        return self

    def _parse_config(self):
        with open(self.conf_file, "r") as f:
            #jsc = f.read()
            ignore_comments = list(filter(lambda x: not re.match(r'^\s*#', x) ,f.read().split('\n')))
            try:
                cf_obj = json.loads("\n".join(ignore_comments))
            except Exception as e:
                print("[!] Error parsing desyl config file")
                ##print config file with line numbers as we see it
                for i, line in enumerate(ignore_comments):
                    print(i, line)
                raise e

            assert(isinstance(cf_obj, dict))
            for s in ['log2file', 'analysis', 'experiment', 'database']:
                if s not in cf_obj:
                    print("[!] Error parsing desyl config file - `{}`! Could not find section `{}`".format(
                        self.conf_file, s), file=sys.stderr)
                    sys.exit(-1)

            self = Config.dict_to_attr(self, cf_obj)
            ABS_PATH = "/".join(os.path.abspath(__file__).split("/")[:-1])
            self.desyl =  ABS_PATH
            self.res   =  os.path.join(ABS_PATH,"res")

            #self.logger.addFilter(ContextFilter())
            formatter   = logging.Formatter(self.format)
            self.logger = logging.getLogger("desyl")
            #self.logger.propagate = False
            #self.loggerConsoleHandler = logging.StreamHandler()
            #self.loggerConsoleHandler.setFormatter(formatter)

            #self.loggerConsoleHandler.setLevel(logging.DEBUG)
            #self.logger.addHandler(self.loggerConsoleHandler)


            # if res dir doesn't exist, create directory
            if not os.path.isdir(self.res):
                os.makedirs(self.res)

            if not os.access(self.res, os.X_OK):
                raise Exception(
                    "[!] Error, we don't have executable access to res directory! - `{}`".format(self.res))

            if self.log2file:
                self.loggerDebugFileHandler = logging.FileHandler(
                    self.res + "/" + "desyl.debug")
                self.loggerDebugFileHandler.setFormatter(formatter)
                self.loggerDebugFileHandler.setLevel(logging.DEBUG)

                self.loggerInfoFileHandler = logging.FileHandler(
                    self.res + "/" + "desyl.info")
                self.loggerInfoFileHandler.setFormatter(formatter)
                self.loggerInfoFileHandler.setLevel(logging.INFO)

                self.loggerWarnFileHandler = logging.FileHandler(
                    self.res + "/" + "desyl.warn")
                self.loggerWarnFileHandler.setFormatter(formatter)
                self.loggerWarnFileHandler.setLevel(logging.WARNING)

                self.loggerErrorFileHandler = logging.FileHandler(
                    self.res + "/" + "desyl.err")
                self.loggerErrorFileHandler.setFormatter(formatter)
                self.loggerErrorFileHandler.setLevel(logging.ERROR)

                self.logger.addHandler(self.loggerDebugFileHandler)
                self.logger.addHandler(self.loggerInfoFileHandler)
                self.logger.addHandler(self.loggerWarnFileHandler)
                self.logger.addHandler(self.loggerErrorFileHandler)

            return

    def removeLoggerHandlers(self):
        for fileHandler in [ 
            self.loggerWarnFileHandler, self.loggerErrorFileHandler, 
            self.loggerInfoFileHandler, self.loggerDebugFileHandler, ]:
            if fileHandler:
                self.logger.removeHandler(fileHandler)

        #self.logger.removeHandler(self.loggerConsoleHandler)
        if self.loggerFileHandler:
            self.logger.removeHandler(self.loggerFileHandler)

    def addStreamHandler(self, stream):
        """
            :param stream: Open file stream to log to
        """
        formatter = logging.Formatter(self.format)
        sh = logging.StreamHandler(stream=stream)
        sh.setFormatter(formatter)
        sh.setLevel(logging.DEBUG)
        self.logger.addHandler(sh)
