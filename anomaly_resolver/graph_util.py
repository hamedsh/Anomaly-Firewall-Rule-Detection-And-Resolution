from typing import Dict, Tuple, Any

import networkx as nx  # type: ignore
import random

from networkx import DiGraph


def hierarchy_pos(
        graph: DiGraph,
        root: str = None,
        width: float = 1.,
        vert_gap: float = 0.2,
        vert_loc: float = 0,
        xcenter: float = 0.5,
) -> Dict[str, Tuple[Any]]:
    """
    From Joel's answer at https://stackoverflow.com/a/29597209/2966723.
    Licensed under Creative Commons Attribution-Share Alike

    If the graph is a tree this will return the positions to plot this in a
    hierarchical layout.

    G: the graph (must be a tree)

    root: the root node of current branch
    - if the tree is directed and this is not given,
      the root will be found and used
    - if the tree is directed and this is given, then
      the positions will be just for the descendants of this node.
    - if the tree is undirected and not given,
      then a random choice will be used.

    width: horizontal space allocated for this branch - avoids overlap with other branches

    vert_gap: gap between levels of hierarchy

    vert_loc: vertical location of root

    xcenter: horizontal location of root
    """
    if not nx.is_tree(graph):
        raise TypeError('cannot use hierarchy_pos on a graph that is not a tree')

    if root is None:
        if isinstance(graph, nx.DiGraph):
            root = next(iter(nx.topological_sort(graph)))  # allows back compatibility with nx version 1.11
        else:
            root = random.choice(list(graph.nodes))

    def _hierarchy_pos(
            graph: DiGraph,
            root: str,
            width: float = 1.,
            vert_gap: float = 0.2,
            vert_loc: float = 0,
            xcenter: float = 0.5,
            pos: Dict[str, Tuple[Any]] = None,
            parent: str = None,
    ) -> Dict[str, Tuple[Any]]:
        """
        see hierarchy_pos docstring for most arguments

        pos: a dict saying where all nodes go if they have been assigned
        parent: parent of this branch. - only affects it if non-directed

        """

        if pos is None:
            pos = {root: (xcenter, vert_loc)}
        else:
            pos[root] = (xcenter, vert_loc)
        children = list(graph.neighbors(root))
        if not isinstance(graph, nx.DiGraph) and parent is not None:
            children.remove(parent)
        if len(children) != 0:
            dx = width / len(children)
            nextx = xcenter - width / 2 - dx / 2
            for child in children:
                nextx += dx
                pos = _hierarchy_pos(graph, child, width=dx, vert_gap=vert_gap,
                                     vert_loc=vert_loc - vert_gap, xcenter=nextx,
                                     pos=pos, parent=root)
        return pos

    return _hierarchy_pos(graph, root, width, vert_gap, vert_loc, xcenter)
