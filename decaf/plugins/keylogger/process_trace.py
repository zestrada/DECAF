#!/usr/bin/env python
import sys
import pandas as pd
import numpy as np

#Expect input of the form:
#Process Read(0)/Write(1) vaddOfTaintedMem   paddrOfTaintedMem    Size
#TaintInfo   CurEIP       ModuleName      CallerModuleName
#CallerSystemCall valueOfTaintedMem

df = pd.read_csv(sys.argv[1], delim_whitespace=True)

#We sent tainted keystrokes of 'a' and 'b'
keystrokes=['1e','30']

#Now we want to find which different processes read the same address
#print df.eq(df['paddrOfTaintedMem'], axis='index')
#for addr, rows in df.groupby('paddrOfTaintedMem'):

min_row = df.count #the row index corresponding to the earliest we see this
max_procs = 0 #the number of processes that use this function
eip = 0
#We want to minimize rownumber for the maximal process_count the use the tainted
#data
for addr, rows in df.groupby('CurEIP'):
  #print rows[rows['valueOfTaintedMem'].str.contains(keystrokes[0]) | \
  #           rows['valueOfTaintedMem'].str.contains(keystrokes[1])]
  num_procs = rows['Process'].unique().size
  if(num_procs >= max_procs):
    max_procs = num_procs
    if(rows['valueOfTaintedMem'].str.contains(keystrokes[0]).any() and 
       rows['valueOfTaintedMem'].str.contains(keystrokes[1]).any()):
      #print addr, rows['Process'].unique()
      #print rows[['CurEIP','valueOfTaintedMem']].index.min()
      #Converted to a numpy array to avoid recursion depth complaints:
      row_index = np.min(np.array(rows[['CurEIP','valueOfTaintedMem']].index))
      if(row_index<min_row):
        min_row = row_index
        eip = addr

print df[df['CurEIP'].str.contains(eip)]
print "Event number: %d, Number of processes: %d eip: %s" % \
      (min_row, max_procs, eip)
