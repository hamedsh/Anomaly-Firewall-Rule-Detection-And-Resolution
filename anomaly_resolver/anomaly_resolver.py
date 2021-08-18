# Firewall Rule Anomaly Resolver for Ryu restfull firewall 
# https://github.com/osrg/ryu/blob/master/ryu/app/rest_firewall.py
import logging
import logging.handlers
import itertools
from typing import List, Optional, Set, Tuple, Dict

import networkx as nx  # type: ignore
import matplotlib  # type: ignore
from networkx import DiGraph

from anomaly_resolver.rule_utils import Rule

matplotlib.use('Agg')
import matplotlib.pyplot as plt
from anomaly_resolver.graph_util import hierarchy_pos


class AnomalyResolver:
    # TODO support for
    # dl_src, dl_dst, dl_type, ipv6_src, ipv6_dst, multiple protocol
    attr_list = ['direction', 'nw_proto', 'nw_src', 'tp_src', 'nw_dst', 'tp_dst', 'actions', 'None']
    attr_dict: Dict[str, int] = {}
    tree = None

    def __init__(self, log_output: str = 'console', log_level: str = 'INFO') -> None:

        for key in self.attr_list:
            self.attr_dict[key] = 0

        self.resolver_logger = logging.getLogger('AnomalyResolver')
        self.resolver_logger.setLevel(logging.DEBUG)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        if log_level not in ['CRITICAL', 'ERROR', 'WARNING', 'INFO', 'DEBUG', 'NOTSET']:
            log_level = 'INFO'
        log_level = eval('logging.' + log_level)
        if 'file' in log_output:
            self.LOG_FILENAME = 'anomaly_resolver.log'
            file_handler = logging.FileHandler(self.LOG_FILENAME)
            file_handler.setFormatter(formatter)
            file_handler.setLevel(log_level)
            self.resolver_logger.addHandler(file_handler)
        if 'console' in log_output:
            console_handler = logging.StreamHandler()
            console_handler.setFormatter(formatter)
            console_handler.setLevel(log_level)
            self.resolver_logger.addHandler(console_handler)
        self.resolver_logger.info('Start Anomaly Resolver')

    def detect_anomalies(self, rules_list: List[Rule]) -> None:
        self.resolver_logger.info('Perform Detection')
        self.print_rules_list(rules_list)

        combination_list = list(itertools.combinations(rules_list, 2))
        for rule_tuple in combination_list:
            rule_0 = rule_tuple[0]
            rule_1 = rule_tuple[1]
            if rule_0.disjoint(rule_1):
                continue
            if rule_0.issubset(rule_1) or rule_1.issubset(rule_0):
                if rule_0.actions == rule_1.actions:
                    self.resolver_logger.info('Redundancy Anomaly\n\t%s\n\t%s', str(rule_0), str(rule_1))
                else:
                    self.resolver_logger.info('Shadowing Anomaly\n\t%s\n\t%s', str(rule_0), str(rule_1))
                continue
            if not rule_0.disjoint(rule_1) and not rule_0.issubset(rule_1) and \
                    not rule_1.issubset(rule_0) and rule_0.actions != rule_1.actions:
                self.resolver_logger.info('Correlation Anomaly\n\t%s\n\t%s', str(rule_0), str(rule_1))
                continue

    def print_rules_list(self, rules_list: List[Rule]) -> None:
        self.resolver_logger.info('Rules list:\n\t' + '\n\t'.join(map(str, rules_list)))

    def resolve_anomalies(self, old_rules_list: List[Rule]) -> List[Rule]:
        """
        Resolve anomalies in firewall rules file
        """
        self.resolver_logger.info('Perform Resolving')
        self.print_rules_list(old_rules_list)

        new_rules_list: List[Rule] = list()

        for rule in old_rules_list:
            self.insert(rule, new_rules_list)

        combination_list = list(itertools.combinations(new_rules_list, 2))
        removed_rules = list()
        for rule_tuple in combination_list:
            rule = rule_tuple[0]
            if rule in removed_rules:
                continue
            subset_rule = rule_tuple[1]

            if rule.issubset(subset_rule) and \
                    rule.actions == subset_rule.actions:
                if rule in new_rules_list:
                    self.resolver_logger.info('Redundant rule %s', str(rule))
                    new_rules_list.remove(rule)
                    removed_rules.append(rule)
        # TODO reassign priority

        self.resolver_logger.info('New rules list:\n\t' + \
                                  '\n\t'.join(map(str, new_rules_list)))
        self.resolver_logger.info('Finish anomalies resolving')
        return new_rules_list

    def insert(self, r: Rule, new_rules_list: List[Rule]) -> None:
        """
        Insert the rule r into new_rules_list
        """
        if not new_rules_list:
            new_rules_list.append(r)
        else:
            inserted = False
            for subset_rule in new_rules_list:

                if not r.disjoint(subset_rule):
                    inserted = self.resolve(r, subset_rule, new_rules_list)
                    if inserted:
                        break
            if not inserted:
                new_rules_list.append(r)

    def resolve(self, rule: Rule, subset_rule: Rule, new_rules_list: List[Rule]) -> bool:
        """
        Resolve anomalies between two rules r and s
        """
        if rule.issubset(subset_rule) and subset_rule.issubset(rule):
            if not rule.actions == subset_rule.actions:
                subset_rule.actions = 'DENY'
            else:
                self.resolver_logger.info('Remove rule %s' % (str(rule),))
            return True
        if rule.issubset(subset_rule):
            self.resolver_logger.info('Reodering %s before %s' % \
                                      (str(rule), str(subset_rule)))
            new_rules_list.insert(0, rule)
            return True
        if subset_rule.issubset(rule):
            return False
        if subset_rule in new_rules_list:
            new_rules_list.remove(subset_rule)
        attribute_set: Set[str] = rule.find_attribute_set(subset_rule)

        for attribute in attribute_set:
            self.split(rule, subset_rule, attribute, new_rules_list)
        if not rule.actions == subset_rule.actions:
            subset_rule.actions = 'DENY'
        self.insert(subset_rule, new_rules_list)
        return True

    def split(self, rule: Rule, subset_rule: Rule, attribute: str, new_rules_list: List[Rule]) -> None:
        """
        Split overlapping rules r and s based on attribute a
        """
        self.resolver_logger.info('Overlapping rule %s, %s' % (str(rule), str(subset_rule)))
        rule_range = rule.get_attribute_range(attribute)
        rule_start = rule_range[0]
        rule_end = rule_range[-1]
        subset_rule_range = subset_rule.get_attribute_range(attribute)
        subset_rule_start = subset_rule_range[0]
        subset_rule_end = subset_rule_range[-1]

        left = min(rule_start, subset_rule_start)
        right = max(rule_end, subset_rule_end)
        common_start = max(rule_start, subset_rule_start)
        common_end = min(rule_end, subset_rule_end)

        if rule_start > subset_rule_start:
            copy_rule = Rule()
            copy_rule.set_fields(subset_rule)
            copy_rule.set_attribute_range(attribute, left, common_start, -1)
            self.insert(copy_rule, new_rules_list)
        elif rule_start < subset_rule_start:
            copy_rule = Rule()
            copy_rule.set_fields(rule)
            copy_rule.set_attribute_range(attribute, left, common_start, -1)
            self.insert(copy_rule, new_rules_list)
        if rule_end > subset_rule_end:
            copy_rule = Rule()
            copy_rule.set_fields(rule)
            copy_rule.set_attribute_range(attribute, common_end, right, 1)
            self.insert(copy_rule, new_rules_list)
        elif rule_end < subset_rule_end:
            copy_rule = Rule()
            copy_rule.set_fields(subset_rule)
            copy_rule.set_attribute_range(attribute, common_end, right, 1)
            self.insert(copy_rule, new_rules_list)
        rule.set_attribute_range(attribute, common_start, common_end, 0)
        subset_rule.set_attribute_range(attribute, common_start, common_end, 0)

    def merge_contiguous_rules(self, rule_list: List[Rule]) -> None:
        self.construct_rule_tree(rule_list)
        self.merge(self.get_rule_tree_root())
        self.plot_firewall_rule_tree(file_name='../img/merged_tree.png')

    def construct_rule_tree(self, rule_list: List[Rule], plot: bool = True) -> None:
        """
        """
        self.tree = nx.DiGraph()
        attr = self.attr_list[0]
        self.attr_dict[attr] = self.attr_dict[attr] + 1
        root_node = str(self.attr_dict[attr]) + '. ' + attr
        self.tree.add_node(root_node, attr=attr)
        for rule in rule_list:
            self.tree_insert(root_node, rule)
        if plot:
            self.plot_firewall_rule_tree()
        print('Nodes', self.tree.nodes())
        print('Edges', self.tree.edges())

    def get_rule_tree_root(self) -> Optional[str]:
        attr_list = self.attr_list
        if self.tree:
            return '1. ' + attr_list[0]
        return None

    def plot_firewall_rule_tree(self, file_name: str = 'img/firewall_rule_tree.png') -> None:
        plt.figure(figsize=(16, 16))
        tree = self.tree
        pos = hierarchy_pos(tree)
        nx.draw(tree, pos, with_labels=True)
        nx.draw_networkx_edge_labels(tree,
                                     pos,
                                     rotate=False,
                                     edge_labels=nx.get_edge_attributes(tree, 'range'))
        plt.savefig(file_name)

    def tree_insert(self, node: str, rule: Rule) -> None:
        """
        Inserts rule r into the node n of the rule tree
        """
        tree: DiGraph = self.tree
        attr_list = self.attr_list
        attr_dict = self.attr_dict
        attr = nx.get_node_attributes(tree, 'attr')[node]
        for snode in tree.successors(node):
            edge_range = nx.get_edge_attributes(tree, 'range')[(node, snode)]
            if rule.get_attribute_range(attr, format='string') == edge_range:
                self.tree_insert(snode, rule)
                return
        idx = attr_list.index(attr) + 1
        if idx >= len(attr_list):
            return
        else:
            next_attr = attr_list[idx]
            attr_dict[next_attr] = attr_dict[next_attr] + 1
            next_node = str(attr_dict[next_attr]) + ('. ' + next_attr if next_attr != 'None' else '')
        tree.add_node(next_node, attr=next_attr)
        tree.add_edge(node, next_node, range=rule.get_attribute_range(attr, format='string'))
        if next_attr == 'None':
            return
        self.tree_insert(next_node, rule)

    def merge(self, node: str) -> None:
        """
        Merges edges of node n representing a continuous range
        for all edge e in n.edges:
            merge(e.node)
        for all edge e in n.edges:
            for all edge e' != e in n.edges:
                if e and e' range are contiguous and Subtree(e)=Subtree(e'):
                    Merge e.range and e'.range into e.range
                    Remove e' from n.edges
        """
        tree: DiGraph = self.tree
        edges = tree.edges()
        for e in tree.edges([node]):
            self.merge(e[1])
        combination_list = list(itertools.combinations(tree.edges([node]), 2))
        self.removing_edges = []
        self.removing_nodes = []
        for edge_tuple in combination_list:
            edge_1 = edge_tuple[0]
            edge_2 = edge_tuple[1]
            range_1 = edges[edge_1]['range']
            range_2 = edges[edge_2]['range']
            if Rule.contiguous(range_1, range_2) \
                    and self.subtree_equal(edge_1, edge_2):
                result = Rule.combine_range(range_1, range_2)
                nx.set_edge_attributes(tree, {edge_1: result}, 'range')
                self.cut_edge(edge_2)
            tree.remove_edges_from(self.removing_edges)
            tree.remove_nodes_from(self.removing_nodes)
            self.removing_edges = []
            self.removing_nodes = []

    def cut_edge(self, edge: Tuple[str]) -> None:
        """
        """
        tree = self.tree
        self.removing_edges.append((edge[0], edge[1]))
        for e in tree.edges([edge[1]]):
            self.cut_edge(e)
        self.removing_nodes.append(edge[1])

    def subtree_equal(self, e_1: Tuple[str], e_2: Tuple[str]) -> bool:
        """
        """
        tree: DiGraph = self.tree
        edges = tree.edges()
        edges_1 = tree.edges([e_1[1]])
        edges_2 = tree.edges([e_2[1]])
        if len(edges_1) != len(edges_2):
            return False
        sign = True
        for edge_1, edge_2 in zip(edges_1, edges_2):
            if edges[edge_1]['range'] != edges[edge_2]['range'] or not sign:
                return False
            sign = self.subtree_equal(edge_1, edge_2)
        return sign
