import grequests
from netmiko import ConnectHandler
from pprint import pprint
import re


class ASA(object):
    def __init__(self, method='http'):
        """
        Collects ASA outputs
        :param method: str > 'http' or 'ssh
        """
        self.method = method
        self.credentials = {"username": '',
                            'password': '',
                            "device_type": 'cisco_ios',
                            "ip": '',
                            "port": '22'}
        self.commands = {"config": "show run",
                         "xlate": "show xlate",
                         "object": "show running-config object",
                         "object-group": "sh running-config object-group",
                         "aaa": "sh running-config aaa",
                         "aaa-server": "sh running-config aaa-server",
                         "access-group": "sh running-config access-group",
                         "access-list": "sh running-config access-list",
                         "domain-name": "sh running-config domain-name",
                         "interface": "sh running-config interface",
                         "ipsec": "sh running-config ipsec",
                         "map": "sh running-config map",
                         "tunnel-group": "sh running-config tunnel-group",
                         "nat": "sh running-config nat",
                         "route": "sh running-config route",
                         "router_ospf": "sh running-config router ospf",
                         "router_eigrp": "sh running-config router eigrp",
                         "ikev1_sa": "show crypto ikev1 sa detail",
                         "ipsec_sa": "show crypto ipsec sa entry detail",
                         "vpn-sessiondb": "sh vpn-sessiondb l2l",
                         }
        self.config = {}

    def connect_ssh(self):
        return ConnectHandler(**self.credentials)

    def get_ssh_data(self, command='show run\n'):
        """
        Returns the Running Config
        """
        self.device = self.connect_ssh()
        config = self.device.send_command(command).split("\n")

        if not config[-1]:
            config.pop()

        return config

    def get_http_data(self):
        keys = self.commands.keys()
        urls = ["https://{}/exec/{}".format(self.credentials['ip'], "%20".join(command.split())) for command in self.commands.values()]
        commands = grequests.map(
            (grequests.get(command, auth=('lramos', 'Secure@2314!'), verify=False) for command in urls), size=20)
        self.config["config"] = dict(zip(keys, [i.content.decode("utf-8") for i in commands]))

    def get_config(self):
        if self.method == "http":
            self.get_http_data()
        elif self.method == "ssh":
            self.get_ssh_data()
        else:
            print("Method not supported")

    def config_parser(self):
        self.get_config()
        self.get_objects()
        self.get_object_groups()
        self.get_aaa()
        self.get_acl()
        self.get_domain()
        self.get_interfaces()
        self.get_ipsec()
        self.get_crypto_maps()
        self.get_tunnel_groups()
        self.get_crypto_ikev1_sa()
        self.get_crypto_ipsec_sa_entries()
        self.get_vpn_sessiondb_l2l()

    def xlate(self):
        output = self.config["config"]["xlate"]

        usage = output[0]

        total = output[3:]
        xlate = {'NAT': [],
                 'TCP': [],
                 'UDP': [],
                 'ICMP': []}
        flags = {'D': 'DNS',
                 'e': 'extended',
                 'I': 'identity',
                 'i': 'dynamic',
                 'r': 'portmap',
                 's': 'static',
                 'T': 'twice',
                 'N': 'net-to-net'}

        def local_parser(buffer):
            buffer = buffer.replace(', ', ',')
            sub_lines = buffer.split()

            if sub_lines[0] == 'NAT':
                return {'protocol': sub_lines[0],
                        'nat_from': [i for i in sub_lines[2].replace(':', ' ').replace('/', ' ').split()],
                        'nat_to': [i for i in sub_lines[4].replace(':', ' ').replace('/', ' ').split()],
                        'nat_flags': [flags[flag] for flag in sub_lines[6]],
                        'nat_idle': sub_lines[8],
                        'nat_timeout': sub_lines[10]
                        }
            else:
                return {'protocol': sub_lines[0],
                        'nat_type': sub_lines[1],
                        'nat_from': [i for i in sub_lines[3].replace(':', ' ').replace('/', ' ').split()],
                        'nat_to': [i for i in sub_lines[5].replace(':', ' ').replace('/', ' ').split()],
                        'nat_flags': [flags[flag] for flag in sub_lines[7]],
                        'nat_idle': sub_lines[9],
                        'nat_timeout': sub_lines[11]
                        }
        counter = 0
        for line in total:
            if line.split()[0] == 'NAT':
                new_counter = counter
                new_line = total[new_counter + 1]

                while new_line.startswith('    '):
                    if new_line.startswith('    flags'):
                        line += ' ' + new_line.strip()
                    else:
                        line += new_line.strip()
                    new_counter += 1
                    new_line = total[new_counter + 1]

                xlate['NAT'].append(local_parser(line))

            if line.split()[0] == 'TCP':
                xlate['TCP'].append(local_parser(line))
            if line.split()[0] == 'UDP':
                xlate['UDP'].append(local_parser(line))
            if line.split()[0] == 'ICMP':
                xlate['ICMP'].append(local_parser(line))

            counter += 1

        return {'xlate': xlate, 'usage': usage}

    def get_objects_inline(self):
        objects = self.get_ssh_data('sh running-config object in-line\n')

        self.config['object'] = {}

        for obj in objects:
            if obj:
                # Get full config
                obj_config = obj
                # Make config a List
                obj = obj.split()
                # Discard first element
                obj.pop(0)
                # Store Type: Network or Service and Name
                obj_type = obj.pop(0)
                obj_name = obj.pop(0)
                # Save Instance
                self.config['object'].update({obj_name: {"type": obj_type, "config": obj_config}})

                working_sub_type = "default"
                while obj:
                    new_pop = obj.pop(0)
                    if new_pop in ["description", "fqdn", "host", "range", "subnet", "service"]:
                        working_sub_type = new_pop
                        self.config['object'][obj_name][working_sub_type] = ""
                    else:
                        if self.config['object'][obj_name][working_sub_type]:
                            self.config['object'][obj_name][working_sub_type] += " "
                        self.config['object'][obj_name][working_sub_type] += new_pop

    def get_objects(self):
        objects = self.config["config"].get("object").splitlines()

        self.config['object'] = {}

        obj_type, obj_name = "", ""
        for line in objects:
            if line:
                if not line.startswith(" "):
                    _, obj_type, obj_name = line.split()
                    self.config['object'].update({obj_name: {"type": obj_type, "config": line}})
                else:
                    self.config['object'][obj_name][line.split()[0]] = " ".join(line.split()[1:])
                    self.config['object'][obj_name]["config"] += "\n" + line

    def get_object_groups(self):
        object_groups = self.config["config"].get("object-group").splitlines()

        self.config['object-groups'] = {'network': {},
                                        'service': {}}

        pack = {}
        while object_groups:
            working_line = object_groups.pop(0)

            if working_line.startswith('object-group'):
                obj_sub = working_line.split()[1]
                obj_name = working_line.split()[2]
                self.config['object-groups'][obj_sub][obj_name] = {"config": working_line + "\n"}
                pack = self.config['object-groups'][obj_sub][obj_name]

                if obj_sub == 'service':
                    obj_proto = 'ip'
                    if len(working_line) == 4:
                        obj_proto = working_line.split()[-1]
                    pack['protocol'] = obj_proto

            if working_line.startswith(' '):
                obj_type = working_line.split()[0]
                obj_value = " ".join(working_line.split()[1:])

                if not pack.get(obj_type):
                    pack[obj_type] = [obj_value]
                else:
                    pack[obj_type].append(obj_value)

                pack["config"] += working_line + "\n"

    def get_aaa(self):
        aaa = self.config["config"].get("aaa").splitlines()
        servers = self.config["config"].get("aaa-server").splitlines()

        self.config['aaa'] = {}
        self.config['aaa-server'] = {}

        while aaa:
            working_line = aaa.pop(0)

            if working_line:
                aaa_type = working_line.split()[1]
                aaa_value = " ".join(working_line.split()[1:])

                if not self.config['aaa'].get(aaa_type):
                    self.config['aaa'][aaa_type] = [aaa_value]
                else:
                    self.config['aaa'][aaa_type].append(aaa_value)

        working_host = ""
        working_name = ""
        working_type = ""
        while servers:
            working_line = servers.pop(0)

            if working_line:
                if working_line.startswith('aaa-server'):
                    aaa_name = working_name = working_line.split()[1]
                    aaa_type = working_type = working_line.split()[2]
                    aaa_value = " ".join(working_line.split()[3:])

                    if not self.config['aaa-server'].get(aaa_name):
                        self.config['aaa-server'][aaa_name] = {}

                    if not self.config['aaa-server'][aaa_name].get('host'):
                        self.config['aaa-server'][aaa_name]['host'] = {}

                    if aaa_type == 'protocol' or aaa_type == 'max-failed-attempts' or aaa_type == 'deadtime':
                        self.config['aaa-server'][aaa_name][aaa_type] = aaa_value

                    if aaa_type == 'host':
                        working_host = working_line.split()[3]

                        if not self.config['aaa-server'][aaa_name]['host'].get(working_host):
                            self.config['aaa-server'][aaa_name]['host'][working_host] = {'interface': 'default'}

                        if len(working_line.split()) > 4:
                            extra = working_line.split()[4]

                            if extra == 'timeout':
                                self.config['aaa-server'][aaa_name]['host'] = {'timeout': working_line.split()[-1]}
                            else:
                                self.config['aaa-server'][aaa_name]['host'] = {'encryption_key': extra}

                                if len(working_line.split()) > 5:
                                    self.config['aaa-server'][aaa_name]['host'] = {
                                        'timeout': working_line.split()[-1]}

                    if aaa_type.startswith('('):
                        aaa_interface = aaa_type.replace("(", "").replace(")", "")
                        working_host = working_line.split()[4]

                        if not self.config['aaa-server'][aaa_name]['host'].get(working_host):
                            self.config['aaa-server'][aaa_name]['host'][working_host] = {'interface': aaa_interface}
                        else:
                            self.config['aaa-server'][aaa_name]['host'][working_host]['interface'] = aaa_interface

                        if len(working_line.split()) > 5:
                            extra = working_line.split()[5]

                            if extra == 'timeout':
                                self.config['aaa-server'][aaa_name]['host'] = {'timeout': working_line.split()[-1]}
                            else:
                                self.config['aaa-server'][aaa_name]['host'] = {'encryption_key': extra}

                                if len(working_line.split()) > 6:
                                    self.config['aaa-server'][aaa_name]['host'] = {
                                        'timeout': working_line.split()[-1]}

                if working_line.startswith(' '):
                    aaa_attrib = working_line.strip().split()[0]
                    aaa_value = " ".join(working_line.strip().split()[1:])

                    if working_type == 'protocol':
                        if not self.config['aaa-server'][working_name]['host'].get('protocol_attrib'):
                            self.config['aaa-server'][working_name]['host']['protocol_attrib'] = {aaa_attrib: aaa_value}
                        else:
                            self.config['aaa-server'][working_name]['host']['protocol_attrib'].update(
                                                                                                {aaa_attrib: aaa_value})
                    else:
                        self.config['aaa-server'][working_name]['host'][working_host].update({aaa_attrib: aaa_value})

    def get_acl(self):
        access_groups = self.config["config"].get("access-group").splitlines()
        access_lists = self.config["config"].get("access-list").splitlines()

        self.config['access_groups'] = {}
        self.config['access_lists'] = {}

        while access_groups:
            working_line = access_groups.pop(0)

            if working_line:
                access_group_name = working_line.split()[1]
                access_group_direction = working_line.split()[2]
                access_group_interface = 'global'

                if access_group_direction in ['in', 'out']:
                    access_group_interface = working_line.split()[-1]

                self.config['access_groups'][access_group_name] = {"direction": access_group_direction,
                                                                   "interface": access_group_interface,
                                                                   "config": working_line}

        while access_lists:
            working_line = access_lists.pop(0)

            if working_line:
                acl_name = working_line.split()[1]

                if not self.config['access_lists'].get(acl_name):
                    self.config['access_lists'][acl_name] = [working_line]
                else:
                    self.config['access_lists'][acl_name].append(working_line)

    def get_domain(self):
        domain = self.config["config"].get("domain-name").splitlines()
        self.config['domain_name'] = domain

    def get_interfaces(self):
        interfaces = self.config["config"].get("interface").splitlines()

        self.config['interface'] = {}

        working_int = "default"
        while interfaces:
            working_line = interfaces.pop(0)

            if working_line:
                if working_line.startswith("interface"):
                    int_name = working_int = working_line.split()[-1]
                    self.config['interface'][int_name] = []

                if working_line.startswith(" "):
                    self.config['interface'][working_int].append(working_line.strip())

    def get_ipsec(self):
        ipsec = self.config["config"].get("ipsec").splitlines()

        self.config['crypto_ipsec'] = {'ikev1': [],
                                       'ikev2': {}}

        version = "default"
        ipsec_proposal = "default"
        while ipsec:
            working_line = ipsec.pop(0)

            if working_line:
                if working_line.startswith("crypto ipsec ikev1"):

                    version = "ikev1"
                    transform_set = " ".join(working_line.split()[4:])

                    self.config['crypto_ipsec'][version].append(transform_set)

                if working_line.startswith("crypto ipsec ikev2"):
                    version = "ikev2"
                    ipsec_proposal = working_line.split()[-1]

                    if ipsec_proposal == 'sa-strength-enforcement':
                        self.config['crypto_ipsec'][version]['sa-strength-enforcement'] = True

                    self.config['crypto_ipsec'][version][ipsec_proposal] = []

                if working_line.startswith(" "):
                    self.config['crypto_ipsec'][version][ipsec_proposal].append(working_line.strip())

                if working_line.startswith("crypto ipsec df-bit"):
                    version = "df-bit"
                    action = working_line.split()[3]
                    interface = working_line.split()[-1]

                    if not self.config['crypto_ipsec'].get(version):
                        self.config['crypto_ipsec'][version] = []
                    else:
                        self.config['crypto_ipsec'][version].append(action, interface)

                if working_line.startswith("crypto ipsec security-association"):
                    version = "security-association"
                    action = " ".join(working_line.split()[3:])

                    if not self.config['crypto_ipsec'].get(version):
                        self.config['crypto_ipsec'][version] = [action]
                    else:
                        self.config['crypto_ipsec'][version].append(action)

    def get_crypto_maps(self):
        maps = self.config["config"].get("map").splitlines()

        self.config['crypto_maps'] = {}
        pack = self.config['crypto_maps']
        for line in maps:
            if line:
                crypto_name = line.split()[2]
                crypto_id = line.split()[3]
                crypto_command = line.split()[4]

                if not crypto_id == 'interface':
                    crypto_subcommand = line.split()[5]
                    crypto_val = " ".join(line.split()[6:])

                    if crypto_name not in pack:
                        pack[crypto_name] = {}

                    if crypto_id not in pack[crypto_name]:
                        pack[crypto_name][crypto_id] = {}
                        pack[crypto_name][crypto_id]["crypto_id"] = {"config": ""}

                    if crypto_command not in pack[crypto_name][crypto_id]["crypto_id"]:
                        pack[crypto_name][crypto_id]["crypto_id"][crypto_command] = {crypto_subcommand: crypto_val}
                    else:
                        if pack[crypto_name][crypto_id]["crypto_id"][crypto_command].get(crypto_subcommand):
                            old_value = pack[crypto_name][crypto_id]["crypto_id"][crypto_command][crypto_subcommand]
                            pack[crypto_name][crypto_id]["crypto_id"][crypto_command][crypto_subcommand] = [old_value,
                                                                                                            crypto_val]
                        else:
                            pack[crypto_name][crypto_id]["crypto_id"][crypto_command].update(
                                {crypto_subcommand: crypto_val})

                    if pack[crypto_name][crypto_id]["crypto_id"]["config"]:
                        pack[crypto_name][crypto_id]["crypto_id"]["config"] += "\n"

                    pack[crypto_name][crypto_id]["crypto_id"]["config"] += line

                else:
                    pack[crypto_name][crypto_id] = crypto_command

    def get_tunnel_groups(self):
        tunnels = self.config["config"].get("tunnel-group").splitlines()

        self.config['tunnel_group'] = {}

        working_tunnel = "default"
        working_sub = "general-attributes"
        while tunnels:
            working_line = tunnels.pop(0)

            if working_line:
                if working_line.startswith("tunnel-group"):
                    working_tunnel = working_line.split()[1]
                    action = working_line.split()[2]

                    if working_tunnel.startswith("\""):
                        working_tunnel = working_line.split("\"")[1].split("\"")[0]
                        action = working_line.split("\"")[-1].split()[0]

                    if action == 'type':
                        tunnel_type = working_line.split()[-1]
                        self.config['tunnel_group'][working_tunnel] = {action: tunnel_type}
                    else:
                        working_sub = action

                        if not self.config['tunnel_group'].get(working_tunnel):
                            self.config['tunnel_group'][working_tunnel] = {}

                        self.config['tunnel_group'][working_tunnel][working_sub] = []

                if working_line.startswith(" "):
                    self.config['tunnel_group'][working_tunnel][working_sub].append(working_line.strip())

    def get_nats(self):
        nats = self.config["config"].get("nat").splitlines()

    def get_route_static(self):
        static = self.config["config"].get("route").splitlines()

    def get_route_ospf(self):
        ospf = self.config["config"].get("router_ospf").splitlines()

    def get_route_eigrp(self):
        eigrp = self.config["config"].get("router_eigrp").splitlines()

    def get_group_policy(self):
        pass

    def get_crypto_ikev1_sa(self):
        details = self.config["config"].get("ikev1_sa").splitlines()

        self.config['crypto_ikev1'] = {}

        headers = details[:7]
        details = details[7:]

        working_peer = "default"
        while details:
            working_line = details.pop(0)

            if working_line:
                if "IKE" in working_line:
                    ike = working_line.split()[0]
                    working_peer = working_line.split()[-1]

                    self.config['crypto_ikev1'][working_peer] = {}

                else:
                    ike_keys = [_.replace(":", "").strip() for _ in re.findall(r"    [\w\s]*:", working_line)]
                    ike_vals = [_.replace(":", "").strip() for _ in re.findall(r": [\w]*", working_line)]
                    self.config['crypto_ikev1'][working_peer].update(dict(zip(ike_keys, ike_vals)))

    def get_crypto_ipsec_sa_entries(self):
        entries = self.config["config"].get("ipsec_sa").splitlines()

        self.config['crypto_ipsec_sa'] = {}

        working_peer = "default"
        while entries:
            working_line = entries.pop(0)

            if working_line:
                if working_line.startswith("peer address: "):
                    working_peer = working_line.split()[-1]

                    self.config['crypto_ipsec_sa'][working_peer] = {}

                else:
                    working_line = working_line.strip()
                    current_stats = {}

                    if "seq num" in working_line:
                        current_stats.update({'seq_num': working_line.split("seq num: ")[1].split()[0]})

                    if working_line.startswith('current '):
                        direction = working_line.split()[1] + "_spi"
                        value = working_line.split()[-1]
                        current_stats.update({direction: value})

                    current_stats.update(dict(re.findall(r"#([\D]*): (\d*)", working_line)))

                    self.config['crypto_ipsec_sa'][working_peer].update(current_stats)

    def get_vpn_sessiondb_l2l(self):
        vpn_sessiondb = self.config["config"].get("vpn-sessiondb").splitlines()
        vpn_sessiondb = vpn_sessiondb[3:]

        self.config['vpn_sessiondb'] = {}

        working_peer = "default"
        while vpn_sessiondb:
            working_line = vpn_sessiondb.pop(0)

            if working_line:
                if working_line.startswith("Connection"):
                    working_peer = working_line.split()[-1]
                    self.config['vpn_sessiondb'][working_peer] = {}

                if working_line.startswith("Index"):
                    self.config['vpn_sessiondb'][working_peer].update({"index": working_line.split(":")[1].split()[0]})
                    self.config['vpn_sessiondb'][working_peer].update({"ip": working_line.split(":")[-1].strip()})

                if working_line.startswith("Protocol"):
                    self.config['vpn_sessiondb'][working_peer].update({"protocol": working_line.split(":")[-1]})

                if working_line.startswith("Encryption"):
                    self.config['vpn_sessiondb'][working_peer].update(
                        {"encryption": ":".join(working_line.split(":")[1:])})

                if working_line.startswith("Hashing"):
                    self.config['vpn_sessiondb'][working_peer].update(
                        {"hashing": ":".join(working_line.split(":")[1:])})

                if working_line.startswith("Bytes"):
                    vpn_bytes = dict(zip(['bytes_tx', 'bytes_rx'], re.findall(r": ([\d]*)", working_line)))
                    self.config['vpn_sessiondb'][working_peer].update(vpn_bytes)

                if working_line.startswith("Login Time"):
                    login_time = ":".join(working_line.split(":")[1:]).strip()
                    self.config['vpn_sessiondb'][working_peer].update({"login_time": login_time})

                if working_line.startswith("Duration"):
                    duration = ":".join(working_line.split(":")[1:]).strip()
                    self.config['vpn_sessiondb'][working_peer].update({"duration": duration})

    def close(self):
        self.device.disconnect()

    def tunnels(self):
        # Get Objects
        print("Gathering Information")
        print("Objects")
        self.get_objects()

        # Get Object Groups
        print("Object Groups")
        self.get_object_groups()

        # Get ACL
        print("Access Lists")
        self.get_acl()

        # Get Crypto Maps
        print("Crypto Maps")
        self.get_crypto_maps()

        # Get Tunnel Groups
        print("Tunnel Groups")
        self.get_tunnel_groups()

        # Get IKE SA
        print("Active Phase1")
        self.get_crypto_ikev1_sa()

        # Get IPSEC SA
        print("Active Phase2")
        self.get_crypto_ipsec_sa_entries()

        # Get L2L VPN session
        print("L2L information")
        self.get_vpn_sessiondb_l2l()

        tunnels = {}
        for peer, val in self.config['tunnel_group'].items():
            if val.get('type') == 'ipsec-l2l':
                tunnels[peer] = {'tunnel_group': self.config['tunnel_group'][peer]}
                tunnels[peer]['crypto_map'] = self.config['crypto_maps']['outside_map0'].get(peer)
                for _id, attribs in self.config['crypto_maps']['outside_map0'].items():
                    if type(attribs) == dict and attribs.get('set'):
                        for k, v in attribs.get('set'):
                            if k == 'peer':
                                tunnels[peer]['crypto_map'] = self.config['crypto_maps']['outside_map0'].get(_id)
                tunnels[peer]['crypto_ikev1'] = self.config['crypto_ikev1'].get(peer)
                tunnels[peer]['crypto_ipsec_sa'] = self.config['crypto_ipsec_sa'].get(peer)
                tunnels[peer]['vpn_sessiondb'] = self.config['vpn_sessiondb'].get(peer)
        return tunnels

a = ASA()
a.config_parser()
