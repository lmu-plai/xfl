
"""

Copyright 2017-2024 by James Patrick-Evans, Moritz Dannehl, Tristan Benoit, and Johannes Kinder.

This file is part of XFL.

XFL is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

XFL is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with XFL. If not, see <https://www.gnu.org/licenses/>. 

"""

from config import Config
from database import PostgresDB

from tqdm import tqdm
import pickle

with open("../Tables/binaries.pck", "rb") as f:
	binaries = pickle.load(f)
	
with open("../Tables/functions.pck", "rb") as f:
	functions = pickle.load(f)

config = Config()
db = PostgresDB(config)
db.connect()

binsPath = {}
paths = db.binary_paths()

for i in tqdm(range(len(functions))):
	binSaved = binaries[functions[i]["binary_id"]]
	binPath = binSaved["path"]
	if not(binPath in binsPath):
		if binPath in paths:
			binsPath[binPath] = db.binary_id(binPath)
		else:
			binsPath[binPath] = db.add_binary_from_data(binSaved)
	idBin = binsPath[binPath]
	db.add_function_fron_data(idBin, functions[i])
 
	if i % 10000 == 0:
		db.conn.commit()

db.conn.commit()
