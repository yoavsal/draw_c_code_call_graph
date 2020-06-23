#!/usr/bin/python

import os
import re
import sys
from pathlib import Path
from enum import Enum
import subprocess
import argparse
import collections

# Define a node class
Node = collections.namedtuple('Node', 'callee, caller')

def get_syms_for_file(path, scan_type):
	if scan_type=="defined":
		params="--defined-only --extern-only"
	elif scan_type=="undefined":
		params="--undefined-only"

	syms=[]

	# Run nm command on object file 
	p = subprocess.Popen('nm {} {}'.format(params, path), shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

	# Take last token from each line (symbol name) 
	for line in p.stdout.readlines():
		syms.append(line.split()[-1])
	
	# Rip process
	retval = p.wait()

	return syms

# Process call graph edges and leave only nodes reachable from root
def filter_root(edges, root):

	# Create a dummy graph calling root from nowhere 
	prev_sz=0
	dummy = Node(callee=root, caller="")
	select=[ dummy ]

    # read edges as list
	source=map(lambda x: x[0], edges.items())

	# Iteratively select nodes from graph (until no more nodes are added)
	while len(select) != prev_sz:
		prev_sz=len(select)

		# Create a list of all nodes that are currently 'called' in the graph
		roots=map(lambda x: x.callee, select)

		# select the edges called by the previous list of edges 
		cur=filter(lambda x: x.caller in roots, source)

		# Union the list
		select=set(select) | set(cur)

    # At the end, remove the dummy node
	select=filter(lambda x: x!=dummy, select)

    # Filter selected nodes
	edges = dict(filter(lambda x: x[0] in select, edges.items()))

	return edges


def build_graph(path, root, exclude, sink, mode, external, include):

	# Get all object files under root path
	objs = Path(path).glob('**/*.o')
	
	# Extract symbols from object files
	defined_in={}
	called_from={}
	for obj in objs:
		if mode == 'obj':
			# Base name of object file (remove leading path, remove '.o')
			base=str(obj).split('/')[-1].split('.')[0]
		elif mode == 'dir':
			base="__".join(str(obj)[len(path):].split('/')[0:-2])
		else:
			return -1

		# Get the symbols defined in the object
		syms=get_syms_for_file(obj, "defined")

		# Add to global list
		defined_in.update(dict.fromkeys(syms, base))

		# Get the symbols called from the object
		syms=get_syms_for_file(obj, "undefined")

		# For each called symbol create a global list of files using it 
		for s in syms:
			try:
				called_from[s].append(base)
			except KeyError:
				called_from[s]=[]
				called_from[s].append(base)

	ext={}
	if (external):
		ext["libc_mount"] = ["mount", "umount", "umount2" ]
#ext["libc_alloc"] = ["malloc", "free", "calloc", "realloc" ]

	# Add stdlib functions
	for lib in ext:
		defined_in.update(dict.fromkeys(ext[lib], lib))

	print("Building graph...")

	# Build the full callgraph
	edges={}
	for func in called_from:
		for caller in called_from[func]:
			try:
				callee = defined_in[func]
			except KeyError:
				continue
				
			if caller != callee:
				N = Node(callee=callee, caller=caller)
				if not N in edges:
					edges[N]=[]
				edges[N].append(func)

	print("Processing graph...")

	# Remove excluded edges if specified 
	if exclude is not None:
		edges=dict(filter(lambda x: not (x[0].callee in exclude or x[0].caller in exclude), edges.items()))

	if include is not None:
		edges=dict(filter(lambda x: x[0].callee in include or x[0].caller in include, edges.items()))

	if sink is not None:
		edges=dict(filter(lambda x: x[0].caller not in sink, edges.items()))


	# Process root node if specified
	if root is not None:
		edges = filter_root(edges, root)

	# Output files
	dot_file="/tmp/callgraph.dot"
	svg_out="/tmp/callgraph.svg"

	# Write edges into a dot file
	with open(dot_file, "w+") as dot:
		dot.write("digraph callgraph {\n")

		dot.write("splines = polyline\n")

		# Highlight root node and set at top
		if root is not None:
			dot.write("{} [fontcolor=red]\n".format(root))

		# Draw an unconnected box for filtered nodes
		if exclude is not None:
			[ dot.write("{} [fontcolor=blue]\n".format(f)) for f in exclude ]

		# Highlight sink nodes
		if sink is not None:
			[ dot.write("{} [fontcolor=green]\n".format(f)) for f in sink ]

		# Highlight include nodes
		if include is not None:
			[ dot.write("{} [fontcolor=purple]\n".format(f)) for f in include ]

		# Highlight external libs
		for lib in ext:
			dot.write("{} [style=filled fillcolor=grey]\n".format(lib))

		# Draw all edges
		for e in sorted(edges.keys()):
			tt="".join(["{}();\n ".format(a) for a in edges[e]])
			dot.write("{} -> {} [tooltip=\"{}\" label=\"{}\"]\n".format(e[1], e[0], tt, tt))
		dot.write("}\n")

	print("Generating SVG...\n")

	# Generate SVG from the dot file
	ret = subprocess.call("dot -Tsvg -o {} {}".format(svg_out, dot_file), shell=True)
	if not ret:
		print("Successfully created {}".format(svg_out))
	else:
		print("Failed creating graph")


def main():
	# Get args
	parser = argparse.ArgumentParser(description='Draw a callgraph for a given set of object files')
	parser.add_argument('-p', '--path', dest="path", required=True, help='Search path for object files')
	parser.add_argument('-r', '--root', dest='root', help='Node to start from')
	parser.add_argument('-e', '--exclude', dest='exclude', action='append', help='Node to filter out. May be specified more than once')
	parser.add_argument('-s', '--sink', dest='sink', action='append', help='Node to make a graph sink (remove edges sourceing from it). May be specified more than once')
	parser.add_argument('-m', '--mode', dest="mode", default='obj', choices=['obj', 'dir'], help='Operate on object level or aggregate all objects in a directory')
	parser.add_argument('-i', '--include', dest="include", action='append', help='Draw only these nodes. May be specified more than once')
	parser.add_argument('-ex', '--external', dest="external", action='store_true', default=False, help='Include built in external library calls')
	args = parser.parse_args()

	build_graph(args.path, args.root, args.exclude, args.sink, args.mode, args.external, args.include)
	
if __name__ == "__main__":
	main()


