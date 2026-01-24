#!/usr/bin/env python3
# hs-toxcore's libraries and the imports between them, as Graphviz:
#   tools/layers.py | dot -Tsvg > layers.svg
# The libraries and their modules come from Bazel. Solid edges step down a
# layer, red dashed ones reach past one, and grey ones go to a library tagged
# "vocabulary", which every layer may use.
import collections
import os
import re
import subprocess

repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
package = '//' + os.path.basename(repo)

query = subprocess.run(
    ['bazel', 'query', f'kind(haskell_library, {package}:all)', '--output=build'],
    cwd=os.path.dirname(repo), capture_output=True, text=True, check=True).stdout

libs = {}  # Module name to its library.
vocabulary = set()
for rule in query.split('\n\n'):
    name = re.search(r'^  name = "([^"]+)"', rule, re.M)
    if re.search(r'^  tags = \[[^]]*"vocabulary"', rule, re.M):
        vocabulary.add(name.group(1))
    for path in re.findall(rf'"{package}:src/([^"]+)\.l?hs"', rule):
        libs[path.replace('/', '.')] = name.group(1)

modules = collections.Counter(libs.values())
edges = collections.Counter()
for module, here in libs.items():
    path = os.path.join(repo, 'src', module.replace('.', '/'))
    path += '.hs' if os.path.exists(path + '.hs') else '.lhs'
    for imported in re.findall(r'^import\s+(?:qualified\s+)?([\w.]+)', open(path).read(), re.M):
        there = libs.get(imported)
        if there and there != here:
            edges[(here, there)] += 1

deps = collections.defaultdict(set)
for a, b in edges:
    deps[a].add(b)


def reachable(a, skip):
    seen, todo = set(), [x for x in deps[a] if (a, x) != skip]
    while todo:
        x = todo.pop()
        if x not in seen:
            seen.add(x)
            todo.extend(deps[x])
    return seen


print('digraph layers {')
print('  node [shape=box, style=rounded];')
for lib, n in sorted(modules.items()):
    print(f'  "{lib}" [label="{lib}\\n{n} modules"{", style=\"rounded,dashed\"" if lib in vocabulary else ""}];')
for (a, b), n in sorted(edges.items()):
    if b not in reachable(a, skip=(a, b)):
        style = 'penwidth=1.5'
    elif b in vocabulary:
        style = 'color=grey80, fontcolor=grey60, constraint=false'
    else:
        style = 'color=red, fontcolor=red, style=dashed'
    print(f'  "{a}" -> "{b}" [label="{n}", {style}];')
print('}')
