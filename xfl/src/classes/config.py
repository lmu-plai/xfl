#!/usr/bin/python3
import json
import os
import sys
import re
import logging
import copy
#import inspect
import IPython
import copyreg
import types
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

        assert(os.path.isfile(config_file))
        self._parse_config()
        if no_logging:
            self.removeLoggerHandlers()
        else:
            self.logger.setLevel(level)

        # Should only be one instance of Config() per python env!
        #global config
        #global logger
        Config.config = copy.copy(self)

        # register pickle function to allow pickling of instances of methods
        #self.allow_pickle_methods()

        coloredlogs.install(logger=self.logger, level='DEBUG')
        self.logger.debug( "[+] classes.config :: Successfully initialised config.")

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
            for s in ['desyl', 'corpus', 'res', 'log2file', 'analysis', 'experiment', 'database']:
                if s not in cf_obj:
                    print("[!] Error parsing desyl config file - `{}`! Could not find section `{}`".format(
                        self.conf_file, s), file=sys.stderr)
                    sys.exit(-1)

            self = Config.dict_to_attr(self, cf_obj)

            #self.logger.addFilter(ContextFilter())
            formatter = logging.Formatter(self.format)
            self.logger = logging.getLogger("desyl.log")

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

    """
    #does not work
    def allow_pickle_methods(self):
        def _pickle_method(method):
            func_name = method.im_func.__name__
            obj = method.im_self
            cls = method.im_class
            return _unpickle_method, (func_name, obj, cls)

        def _unpickle_method(func_name, obj, cls):
            for cls in cls.mro():
                try:
                    func = cls.__dict__[func_name]
                except KeyError:
                    pass
                else:
                    break
            return func.__get__(obj, cls)

        copyreg.pickle(types.MethodType, _pickle_method, _unpickle_method)
    """

"""
class ContextFilter(logging.Filter):
    #This is a filter which injects contextual information into the log.
    #
    #Rather than use actual contextual information, we just use random
    #data in this demo.

    def frame_info(): return inspect.getframeinfo(inspect.stack()[6][0])
    def dbg_format(x): return x.filename + ' :: ' + \
        x.function + ' :: ' + str(x.lineno) + ' :: '

    def filter(self, record):

        info = ContextFilter.frame_info()
        # set records
        record.lineno = str(info.lineno)
        record.filename = info.filename
        record.function = info.function
        return True

"""
