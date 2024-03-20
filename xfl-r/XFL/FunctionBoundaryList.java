//This script prints out listing of function boundary
// information from Ghidra headless analyzer
//@author Jim Alvews-Foss
//@category _NEW_
//@keybinding 
//@menupath 
//@toolbar 

import ghidra.app.script.GhidraScript;
import ghidra.program.model.util.*;
import ghidra.program.model.reloc.*;
import ghidra.program.model.data.*;
import ghidra.program.model.block.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.scalar.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.lang.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.address.*;
import java.io.*;

public class FunctionBoundaryList extends GhidraScript {

    public void run() throws Exception {
        String fname=currentProgram.getName();
	println(" Reading: "+fname);
	FunctionIterator functions = currentProgram.getListing().getFunctions(true);
	int cnt=0;
	Function func;

	BufferedWriter out = null;

	try {
	    FileWriter fstream = new FileWriter("/tmp/"+fname+".funcbd",false); //true tells to append data.
	    out = new BufferedWriter(fstream);
	}

	catch (IOException e) {
    	    System.err.println("Error: " + e.getMessage());
	    return;
	}


	while(functions.hasNext()) {
	   func=functions.next();
	   if(func.isThunk()) continue;
	   Address addr = func.getEntryPoint();
           AddressSetView  addrSV = func.getBody();
	   Address addr2 = addrSV.getMaxAddress();
	   out.write("0x"+addr+"   "+(addr2.next().subtract(addr))+"\n");
 	   cnt+=1;
        }
	println("Count = "+cnt);
	println("Image base = "+currentProgram.getImageBase());

	if(out != null) {
           out.close();
	}
    }

}
