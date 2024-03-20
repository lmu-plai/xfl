
"""

Copyright 2017-2024 by James Patrick-Evans, Moritz Dannehl, Tristan Benoit, and Johannes Kinder.

This file is part of XFL.

XFL is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

XFL is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with XFL. If not, see <https://www.gnu.org/licenses/>. 

"""

import os
import utils
import subprocess

class Ghidra():
    def __init__(self, config):
        ABS_PATH = "/".join(os.path.abspath(__file__).split("/")[:-1])
		
        self.ghidraSupportDir    = "/opt/ghidra/support/" # Set ghidra support directory <!>
        self.ghidraBin           = 'analyzeHeadless'
        self.ghidra              = self.ghidraSupportDir + '/'+ self.ghidraBin
        self.functionboundaryScript = "'FunctionBoundaryList.java'"
        self.functionboundaryPath   = ABS_PATH
        self.ghidra_tmp_folder  = os.path.join(ABS_PATH,"ghidraTMP")

    def run_fb_analysis(self, path:str, dynamic:bool):
        if not os.path.exists(self.ghidra_tmp_folder):
            os.mkdir(self.ghidra_tmp_folder)

        cmd = "{} {} tProject -scriptPath {} -postScript {} -import {} -deleteProject".format(self.ghidra, self.ghidra_tmp_folder, self.functionboundaryPath, self.functionboundaryScript, path)
        if dynamic: 
            cmd += ' -loader ElfLoader -loader-imagebase 0'
        print(cmd)
        subprocess.call(cmd,shell=True)

        fbs = utils.read_file_lines("/tmp/" + os.path.basename(path) + '.funcbd')
        fbs_e = list(map(lambda x: x.split(), fbs))
        return list(map(lambda x: [int(x[0], 16), int(x[1]), '__name__'], fbs_e ))
