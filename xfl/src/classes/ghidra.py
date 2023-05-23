import os
import context
import classes.utils
import subprocess

class Ghidra():
    def __init__(self):
        self.ghidraSupportDir    = '/opt/ghidra/support/'
        self.ghidraBin           = 'analyzeHeadless'
        self.ghidra              = self.ghidraSupportDir + '/'+ self.ghidraBin

        self.functionboundaryscript = "../../deps/FunctionBoundary/ghidra_scripts/FunctionBoundaryList.java"
        self.ghidra_tmp_folder  = "/tmp/ghidra_tmp_project"

    def run_fb_analysis(self, path:str, dynamic:bool):
        if not os.path.exists(self.ghidra_tmp_folder):
            os.mkdir(self.ghidra_tmp_folder)

        cmd = "{} {} tProject -postScript {} -import {} -deleteProject".format(self.ghidra, self.ghidra_tmp_folder, self.functionboundaryscript, path)
        if dynamic: 
            cmd += ' -loader ElfLoader -loader-imagebase 0'
        subprocess.call(cmd,shell=True)

        fbs = classes.utils.read_file_lines("/tmp/" + os.path.basename(path) + '.funcbd')
        fbs_e = list(map(lambda x: x.split(), fbs))
        return list(map(lambda x: [int(x[0], 16), int(x[1])], fbs_e ))
