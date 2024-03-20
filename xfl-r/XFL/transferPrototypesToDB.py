
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

with open("../Tables/libraries.pck", "rb") as f:
	libsP = pickle.load(f)
	
with open("../Tables/libraryPrototypes.pck", "rb") as f:
	prototypes = pickle.load(f)

config = Config()
db = PostgresDB(config)
db.connect()

libsId = {}
paths = db.library_paths()

for i in tqdm(range(len(prototypes))):
	libPath = libsP[prototypes[i]["library"]][0]
	if not(libPath in libsId):
		if libPath in paths:
			libsId[libPath] = db.library_id(libPath)
		else:
			libsId[libPath] = db.add_library_p(libPath)
	idLib = libsId[libPath]
	db.add_library_prototype(idLib, prototypes[i])
	
	if i % 10000 == 0:
		db.conn.commit()

db.conn.commit()
