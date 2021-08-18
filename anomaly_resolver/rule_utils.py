import ctypes
from typing import List, Optional, Set, Union, Any

from netaddr import IPSet, IPRange, IPNetwork, IPGlob, IPAddress  # type: ignore
from netaddr import valid_ipv4, valid_glob, glob_to_cidrs

STRING_TYPE = ctypes.c_wchar_p


class RuleParser:

    def __init__(self) -> None:
        self.rules: List["Rule"] = []

    def parse_file(self, file_name: str) -> None:
        pass


class SimpleRuleParser(RuleParser):

    def __init__(self, file_name: str) -> None:
        super(SimpleRuleParser, self).__init__()
        self.parse_file(file_name)

    def parse_file(self, file_name: str) -> None:
        with open(file_name, 'r') as f:
            for line in f:
                priority = int(line[:line.find('.')])
                rule_start = line.find('<')
                rule_end = line.find('>')
                rule_string = line[rule_start + 1:rule_end]
                rule_string = rule_string.replace(' ', '')
                fields = rule_string.split(',')
                rule = Rule(
                    priority=priority,
                    direction=fields[0],
                    nw_proto=fields[1],
                    nw_src=fields[2],
                    nw_dst=fields[4],
                    tp_src=fields[3],
                    tp_dst=fields[5],
                    actions=fields[6],
                )
                self.rules.append(rule)


class Rule(ctypes.Structure):
    # https://osrg.github.io/ryu-book/en/html/rest_firewall.html#id10
    # https://www.opennetworking.org/wp-content/uploads/2014/10/openflow-spec-v1.3.0.pdf
    _fields_ = [
        ('switch', STRING_TYPE),
        # REST_SWITCHID, [ 'all' | Switch ID ]
        ('vlan', STRING_TYPE),
        # REST_VLANID, [ 'all' | VLAN ID ]
        ('priority', ctypes.c_int),
        # REST_PRIORITY, [ 0 - 65535 ]
        ('in_port', STRING_TYPE),
        # REST_IN_PORT, [ 0 - 65535 ]
        ('dl_src', STRING_TYPE),
        # REST_SRC_MAC, '<xx:xx:xx:xx:xx:xx>'
        ('dl_dst', STRING_TYPE),
        # REST_DST_MAC, '<xx:xx:xx:xx:xx:xx>'
        ('dl_type', STRING_TYPE),
        # REST_DL_TYPE, [ 'ARP' | 'IPv4' | 'IPv6' ]
        ('nw_src', STRING_TYPE),
        # REST_SRC_IP, '<xxx.xxx.xxx.xxx/xx>'
        ('nw_dst', STRING_TYPE),
        # REST_DST_IP, '<xxx.xxx.xxx.xxx/xx>'
        ('ipv6_src', STRING_TYPE),
        # REST_SRC_IPV6, '<xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx/xx>'
        ('ipv6_dst', STRING_TYPE),
        # REST_DST_IPV6, '<xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx/xx>'
        ('nw_proto', STRING_TYPE),
        # REST_NW_PROTO, [ 'TCP' | 'UDP' | 'ICMP' | 'ICMPv6' ]
        ('tp_src', STRING_TYPE),
        # REST_TP_SRC, [ 0 - 65535 ]
        ('tp_dst', STRING_TYPE),
        # REST_TP_DST, [ 0 - 65535 ]
        ('direction', STRING_TYPE),
        # [ 'IN' | 'OUT' ]
        ('actions', STRING_TYPE),
        # REST_ACTION, [ 'ALLOW' | 'DENY' ]
    ]

    def __init__(
            self,
            switch='all',
            vlan='all',
            priority=0,
            in_port='*',
            dl_src='*',
            dl_dst='*',
            dl_type='IPv4',
            nw_src='*',
            nw_dst='*',
            ipv6_src='*',
            ipv6_dst='*',
            nw_proto='TCP',
            tp_src='0-65535',
            tp_dst='*',
            direction='IN',
            actions='DENY',
    ) -> None:

        priority = Rule._sanity_check(priority, field='priority')
        in_port = Rule._sanity_check(in_port, field='port')
        nw_src = Rule._sanity_check(nw_src, field='ipv4')
        nw_dst = Rule._sanity_check(nw_dst, field='ipv4')
        tp_src = Rule._sanity_check(tp_src, field='port')
        tp_dst = Rule._sanity_check(tp_dst, field='port')
        direction = Rule._sanity_check(direction, field='direction')
        actions = Rule._sanity_check(actions, field='action')

        super(Rule, self).__init__(
            switch,
            vlan,
            priority,
            in_port,
            dl_src,
            dl_dst,
            dl_type,
            nw_src,
            nw_dst,
            ipv6_src,
            ipv6_dst,
            nw_proto,
            tp_src,
            tp_dst,
            direction,
            actions,
        )

    @staticmethod
    def _sanity_check(value: Union[int, str], field: str) -> Optional[Union[int, str]]:
        if field == 'priority':
            try:
                if isinstance(value, int) and 0 <= value < 65536:
                    return value
            except:
                return value
        if isinstance(value, str):
            if field == 'port':
                if value.isdigit():
                    return value
                elif value.find('-') > -1 and value != '0-65535':
                    first, second = value.split('-')
                    if first.isdigit() and second.isdigit():
                        return value
                return '*'  # 'ANY' or '*' or '0-65535':

            elif field == 'dl_type':
                if value.upper() in ['ARP', 'IPv4', 'IPv6']:
                    return value.upper()
                return 'IPv4'

            elif field == 'ipv4':
                if '-' in value:
                    first, second = value.split('-')
                    if second.isdigit():
                        second = first[:first.rindex('.') + 1] + second
                    if valid_ipv4(first) and valid_ipv4(second):
                        return first + '-' + second
                if valid_glob(value):
                    return str(glob_to_cidrs(value)[0]).replace('/32', '')
                if valid_ipv4(value) or \
                        ('/' in value and valid_ipv4(value[:value.find('/')])):
                    return value.replace('/32', '')
                return '*'  # 'ANY'

            if field == 'nw_proto':
                if value.upper() in ['TCP', 'UDP', 'ICMP', 'ICMPv6']:
                    return value.upper()
                return 'TCP'

            if field == 'direction':
                if value.upper() in ['IN']:
                    return 'IN'
                if value.upper() in ['OUT']:
                    return 'OUT'
                return 'IN'

            if field == 'action':
                if value.upper() in ['DENY', 'REJECT']:
                    return 'DENY'
                if value.upper() in ['ALLOW', 'ACCEPT']:
                    return 'ALLOW'
                return 'DENY'
        else:
            raise Exception('illegal value format')
        return None

    def __repr__(self, format: str = 'basic') -> str:
        if format == 'detail':
            return '<switch:{}, vlan:{}, priority:{:d}, in_port:{}, dl_src:{}, dl_dst:{},' \
                   ' dl_type:{}, nw_src:{}, nw_dst:{}, ipv6_src:{}, ipv6_dst:{},' \
                   ' nw_proto:{}, tp_src:{}, tp_dst:{}, actions:{}>'\
                .format(
                    self.switch, self.vlan, self.priority, self.in_port,
                    self.dl_src, self.dl_dst, self.dl_type, self.nw_src, self.nw_dst,
                    self.ipv6_src, self.ipv6_dst, self.nw_proto, self.tp_src,
                    self.tp_dst, self.direction, self.actions,
                )
        if format == 'no description':
            return '<{}, {}, {:d}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}>'\
                .format(
                    self.switch, self.vlan, self.priority, self.in_port, self.dl_src,
                    self.dl_dst, self.dl_type, self.nw_src, self.nw_dst, self.ipv6_src,
                    self.ipv6_dst, self.nw_proto, self.tp_src, self.tp_dst, self.actions,
                )
        return '<{}, {}, {}, {}, {}, {}, {}>'.format(
            self.direction, self.nw_proto, self.nw_src, self.tp_src, self.nw_dst, self.tp_dst, self.actions,
        )

    def __eq__(self, rhs: "Rule") -> bool:
        return self.issubset(rhs) and self.issubset(rhs)

    def disjoint(self, subset_rule: "Rule") -> bool:
        # TODO support for
        # dl_src, dl_dst, dl_type, ipv6_src, ipv6_dst, multiple protocol
        if not self.switch == subset_rule.switch or \
                not self.vlan == subset_rule.vlan or \
                Rule.portdisjoint(self.in_port, subset_rule.in_port) or \
                Rule.ipdisjoint(self.nw_src, subset_rule.nw_src) or \
                Rule.ipdisjoint(self.nw_dst, subset_rule.nw_dst) or \
                not self.nw_proto == subset_rule.nw_proto or \
                Rule.portdisjoint(self.tp_src, subset_rule.tp_src) or \
                Rule.portdisjoint(self.tp_dst, subset_rule.tp_dst) or \
                not self.direction == subset_rule.direction:
            return True
        return False

    def issubset(self, subset_rule: "Rule") -> bool:
        # TODO support for
        # dl_src, dl_dst, dl_type, ipv6_src, ipv6_dst, multiple protocol
        if self.switch == subset_rule.switch and self.vlan == subset_rule.vlan and \
                Rule.portinrange(self.in_port, subset_rule.in_port) and \
                Rule.ipinrange(self.nw_src, subset_rule.nw_src) and \
                Rule.ipinrange(self.nw_dst, subset_rule.nw_dst) and \
                self.nw_proto == subset_rule.nw_proto and \
                Rule.portinrange(self.tp_src, subset_rule.tp_src) and \
                Rule.portinrange(self.tp_dst, subset_rule.tp_dst) and \
                self.direction == subset_rule.direction:
            return True
        return False

    @staticmethod
    def portinrange(first: str, second: str) -> bool:
        first_set = set(Rule.portstr2range(first))
        second_set = set(Rule.portstr2range(second))
        return first_set.issubset(second_set)

    @staticmethod
    def portstr2range(x: str) -> List[int]:
        res: List[int] = list()
        if x == '*':
            x = '0-65535'
        if '-' in x:
            first, second = x.split('-')
            res.extend(range(int(first), int(second) + 1))
        else:
            num = int(x)
            res.append(num)
        return res

    @staticmethod
    def portrange2str(x: List[Any]) -> str:
        if len(x) > 1:
            return '%d-%d' % (x[0], x[-1])
        return str(x[0])

    @staticmethod
    def ipinrange(first: str, second: str) -> bool:
        first_set = Rule.ipstr2range(first, format='set')
        second_set = Rule.ipstr2range(second, format='set')
        return first_set.issubset(second_set)

    @staticmethod
    def portdisjoint(first: str, second: str) -> bool:
        if first == '0-65535' or second == '0-65535':
            return False
        first_set = set(Rule.portstr2range(first))
        second_set = set(Rule.portstr2range(second))
        return not first_set.intersection(second_set)

    @staticmethod
    def ipdisjoint(first: str, second: str) -> bool:
        first_set = Rule.ipstr2range(first, format='set')
        second_set = Rule.ipstr2range(second, format='set')
        return not first_set.intersection(second_set)

    def find_attribute_set(self, subset_rule: "Rule") -> Set[str]:
        attribute_set = set()
        for field in self._fields_:
            if not getattr(self, field[0]) == getattr(subset_rule, field[0]) and \
                    (field[0] == 'in_port' or field[0] == 'nw_src' or
                     field[0] == 'nw_dst' or field[0] == 'tp_src' or field[0] == 'tp_dst'):
                attribute_set.add(field[0])
        return attribute_set

    def get_attribute_range(self, attribute: str, format: str = 'range') -> IPRange:
        if attribute == 'in_port' or attribute == 'tp_src' or attribute == 'tp_dst':
            if format == 'string':
                return getattr(self, attribute)
            return Rule.portstr2range(getattr(self, attribute))
        elif attribute == 'nw_src' or attribute == 'nw_dst':
            if format == 'string':
                return getattr(self, attribute)
            return Rule.ipstr2range(getattr(self, attribute))
        else:
            return eval('self.' + attribute)

    def set_attribute_range(self, attribute: str, start: IPAddress, end: IPAddress, offset: int) -> None:
        if attribute == 'in_port' or attribute == 'tp_src' or attribute == 'tp_dst':
            if offset == -1:
                new_range = range(start, end)
            elif offset == 1:
                new_range = range(start + 1, end + 1)
            else:
                new_range = range(start, end + 1)
            if len(new_range) > 1:
                new_str = '%d-%d' % (new_range[0], new_range[-1])
            else:
                new_str = '%d' % (new_range[0],)
            setattr(self, attribute, new_str)
        else:
            if offset == -1:
                new_range = IPRange(start, end - 1)
            elif offset == 1:
                new_range = IPRange(start + 1, end)
            else:
                new_range = IPRange(start, end)
            setattr(self, attribute, Rule.iprange2str(new_range))

    @staticmethod
    def iprange2str(ip_range: IPRange) -> str:
        if len(ip_range) > 1:
            end = str(ip_range[-1])
            return '%s-%s' % (str(ip_range[0]), end)  # end[end.rindex('.') + 1:]
        else:
            return str(ip_range[0])

    @staticmethod
    def ipstr2range(ip_str: str, format: str = 'range') -> IPSet:
        init = IPRange if format == 'range' else IPSet
        if ip_str == '*':
            ip_str = '0.0.0.0/0'
        if '*' in ip_str:
            ipglob = IPGlob(ip_str)
            iprange = IPRange(ipglob[0], ipglob[-1])
            return iprange if format == 'range' else init(iprange)
        if '-' in ip_str:
            start, end = ip_str.split('-')
            iprange = IPRange(start, end)  # start[:start.rindex('.') + 1] +
            return iprange if format == 'range' else init(iprange)
        else:
            if format == 'range':
                network = IPNetwork(ip_str)
                return init(network[0], network[-1])
            return init([ip_str])

    def set_fields(self, other: "Rule") -> None:
        for field in other._fields_:
            setattr(self, field[0], getattr(other, field[0]))

    @staticmethod
    def contiguous(r_1: str, r_2: str) -> bool:
        range_value = False
        range_1: IPRange = IPRange
        range_2: IPRange = IPRange
        if '.' in r_1 or '*' == r_1:
            range_1 = Rule.ipstr2range(r_1)
            range_2 = Rule.ipstr2range(r_2)
            range_value = True
        elif r_1.isdigit() or '-' in r_1:
            range_1 = Rule.portstr2range(r_1)
            range_2 = Rule.portstr2range(r_2)
            range_value = True
        if (range_1[-1] + 1 == range_2[0] or range_1[0] == range_2[-1] + 1) and range_value:
            return True
        return False

    @staticmethod
    def combine_range(r_1: str, r_2: str) -> Optional[str]:
        range_1: IPRange = IPRange
        range_2: IPRange = IPRange
        if '.' in r_1 or '*' == r_1:
            range_1 = Rule.ipstr2range(r_1)
            range_2 = Rule.ipstr2range(r_2)
            return Rule.iprange2str(IPRange(range_1[0], range_2[-1]))
        else:
            range_1 = Rule.portstr2range(r_1)
            range_2 = Rule.portstr2range(r_2)
            return Rule.portrange2str(range(range_1[0], range_2[-1] + 1))
