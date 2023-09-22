import ipaddress
import logging
import urllib.request
import yaml
import os
import time


class app:
    settings = {}
    settings_path = "settings.yaml"
    temporary_folders = ['tmp/asns', 'tmp/asn_lists', 'tmp/ip_lists']
    ipv4_allow_list = []
    ipv4_deny_list = []
    ipv6_allow_list = []
    ipv6_deny_list = []
    comment_for_deny_rule = 'blocked by ufw-asn-blocklist'.encode(
        'utf-8').hex()
    comment_for_allow_rule = 'allowed by ufw-asn-blocklist'.encode(
        'utf-8').hex()

    def __init__(self):
        self._configure_logging()
        self._print_welcome()
        # initialize
        self._create_folder()
        self._load_settings()
        # check asn block and allow lists
        self.update_asn_lists()
        # collapse ip addresses to save space
        self._collapse_ipv4_addresses()
        # create ufw user rules
        self.create_ipv4_ufw_user_rules()
        self.create_ipv6_ufw_user_rules()
        # update ufw if enabled
        if self.settings['update_ufw']:
            self.update_ufw_ipv4()
            self.update_ufw_ipv6()

    def update_asn_lists(self):
        logging.info('updating asn lists')
        # update deny lists
        for item in self.settings['asn_deny_lists']:
            logging.info('updating %s', item['name'])
            # download deny list
            self._download_file_to_dir(
                item['url'],
                'tmp/asn_lists',
                item['name']
            )
            # parse deny list type csv
            if item['type'] == 'csv':
                logging.info('parsing %s', item['name'])
                with open('tmp/asn_lists/{}'.format(item['name']), 'r') as file:
                    for line in file:
                        try:
                            asn = line.strip().split(',')[item['column']]
                        except:
                            logging.error('could not parse line: %s', line)
                        # download asn
                        self._get_asn([asn])
                        # get ips from asn
                        ips = self._get_ips_from_asn(asn)
                        # add ips to deny list specific to ipv4 or ipv6
                        self._add_ips_to_deny_list(ips)
        # update allow lists
        for item in self.settings['asn_allow_lists']:
            logging.info('updating %s', item['name'])
            # download allow list
            self._download_file_to_dir(
                item['url'],
                'tmp/asn_lists',
                item['name']
            )
            # parse allow list type csv
            if item['type'] == 'csv':
                logging.info('parsing %s', item['name'])
                with open('tmp/asn_lists/{}'.format(item['name']), 'r') as file:
                    for line in file:
                        try:
                            asn = line.strip().split(',')[item['column']]
                        except:
                            logging.error('could not parse line: %s', line)
                        # download asn
                        self._get_asn([asn])
                        # get ips from asn
                        ips = self._get_ips_from_asn(asn)
                        # add ips to allow list specific to ipv4 or ipv6
                        self._add_ips_to_allow_list(ips)

    def create_ipv4_ufw_user_rules(self):
        logging.info('creating ipv4 ufw user rules')
        # create or overwrite file user.rules
        with open('user.rules', 'w') as file:
            # create deny rules
            for ip in self.ipv4_deny_list:
                file.write('### tuple ### deny any any 0.0.0.0/0 any {} in comment={}\n'.format(
                    ip,
                    self.comment_for_deny_rule
                ))
                file.write('-A ufw-user-input -s {} -j DROP\n'.format(ip))
            # create allow rules
            for ip in self.ipv4_allow_list:
                file.write('### tuple ### allow any any 0.0.0.0/0 any {} in comment={}\n'.format(
                    ip,
                    self.comment_for_allow_rule
                ))
                file.write('-A ufw-user-input -s {} -j ACCEPT\n'.format(ip))

    def create_ipv6_ufw_user_rules(self):
        logging.info('creating ipv6 ufw user rules')
        # create or overwrite file user.rules
        with open('user6.rules', 'w') as file:
            # create deny rules
            for ip in self.ipv6_deny_list:
                file.write('### tuple ### deny any any ::/0 any {} in comment={}\n'.format(
                    ip,
                    self.comment_for_deny_rule
                ))
                file.write('-A ufw6-user-input -s {} -j DROP\n'.format(ip))
            # create allow rules
            for ip in self.ipv6_allow_list:
                file.write('### tuple ### allow any any ::/0 any {} in comment={}\n'.format(
                    ip,
                    self.comment_for_allow_rule
                ))
                file.write('-A ufw6-user-input -s {} -j ACCEPT\n'.format(ip))

    def update_ufw_ipv4(self):
        ignore_next_line = False
        last_line_was_empty = False
        new_file = []
        # update ipv4 ufw rules
        logging.info('updating ipv4 ufw rules')
        # remove old rules
        logging.info('removing old ipv4 ufw rules')
        with open(self.settings['path_to_ufw_ipv4_user_config'], 'r') as file:
            for line in file:
                line = line.strip()
                # find old rules and remove this line and the next line
                if self.comment_for_deny_rule in line or self.comment_for_allow_rule in line:
                    ignore_next_line = True
                    continue
                # ignore next line
                if ignore_next_line:
                    ignore_next_line = False
                    continue
                # ignore multiple empty lines
                if not line and not last_line_was_empty:
                    last_line_was_empty = True
                elif not line and last_line_was_empty:
                    continue
                else:
                    last_line_was_empty = False
                new_file.append(line)
        # write new rules
        logging.info('writing new ipv4 ufw rules')
        with open(self.settings['path_to_ufw_ipv4_user_config'], 'w') as file:
            for line in new_file:
                file.write(line + '\n')
                # check if rules section has begun and add our user.rules file content
                if '### RULES ###' in line:
                    with open('user.rules', 'r') as user_file:
                        for user_line in user_file:
                            file.write(user_line)

    def update_ufw_ipv6(self):
        ignore_next_line = False
        last_line_was_empty = False
        new_file = []
        # update ipv6 ufw rules
        logging.info('updating ipv6 ufw rules')
        # remove old rules
        logging.info('removing old ipv6 ufw rules')
        with open(self.settings['path_to_ufw_ipv6_user_config'], 'r') as file:
            for line in file:
                line = line.strip()
                # find old rules and remove this line and the next line
                if self.comment_for_deny_rule in line or self.comment_for_allow_rule in line:
                    ignore_next_line = True
                    continue
                # ignore next line
                if ignore_next_line:
                    ignore_next_line = False
                    continue
                # ignore multiple empty lines
                if not line and not last_line_was_empty:
                    last_line_was_empty = True
                elif not line and last_line_was_empty:
                    continue
                else:
                    last_line_was_empty = False
                new_file.append(line)
        # write new rules
        logging.info('writing new ipv6 ufw rules')
        with open(self.settings['path_to_ufw_ipv6_user_config'], 'w') as file:
            for line in new_file:
                file.write(line + '\n')
                # check if rules section has begun and add our user.rules file content
                if '### RULES ###' in line:
                    with open('user6.rules', 'r') as user_file:
                        for user_line in user_file:
                            file.write(user_line)

    def _print_welcome(self):
        logging.info('')
        logging.info('==== Welcome to the UFW ASN Blocklist ====')
        logging.info('')
        logging.info('            .-"""-.')
        logging.info('           \'       \'')
        logging.info('          |,.  ,-.  |')
        logging.info('          |()L( ()| |')
        logging.info('          |,\'  `".| |')
        logging.info('          |.___.\',| `')
        logging.info('         .j `--"\' `  `.')
        logging.info('        / \'        \'   \'')
        logging.info('       / /          `   `.')
        logging.info('      / /            `    .')
        logging.info('     / /              l   |')
        logging.info('    . ,               |   |')
        logging.info('    ,"`.             .|   |')
        logging.info(' _.\'   ``.          | `..-\'l')
        logging.info('|       `.`,        |      `.')
        logging.info('|         `.    __.j         )')
        logging.info('|__        |--""___|      ,-\'')
        logging.info('   `"--...,+""""   `._,.-\' mh')
        logging.info('')

    def _configure_logging(self):
        logging.basicConfig(
            format='%(asctime)s %(levelname)s: %(message)s',
            level=logging.INFO,
            datefmt='%Y-%m-%d %H:%M:%S'
        )

    def _load_settings(self):
        try:
            logging.info('loading settings from %s', self.settings_path)
            with open("settings.yaml", "r") as stream:
                self.settings = yaml.safe_load(stream)
        except Exception as exc:
            logging.error('could not load settings: %s', exc)
            quit()

    def _create_folder(self):
        for folder in self.temporary_folders:
            if not os.path.exists(folder):
                os.makedirs(folder)
                logging.info('created folder: %s', folder)

    def _download_file_to_dir(self, url, dir, filename):
        if os.path.isfile(dir + '/' + filename):
            if os.path.getmtime(dir + '/' + filename) > (time.time() - int(self.settings['file_cache_time'] * 60 * 60)):
                logging.info(
                    'using cached version of %s',
                    dir + '/' + filename
                )
                return True
        logging.info('downloading %s', url)
        try:
            opener = urllib.request.build_opener()
            opener.addheaders = [('User-Agent', 'Mozilla/5.0')]
            urllib.request.install_opener(opener)
            urllib.request.urlretrieve(url, dir + '/' + filename)
            return True
        except Exception as e:
            logging.error('could not download file: %s', e)
            return False

    def _get_asn(self, asns):
        for asn in asns:
            self._download_file_to_dir(
                self.settings['asn_fetch_url'].format(asn),
                'tmp/asns',
                '{}.txt'.format(asn)
            )

    def _get_ips_from_asn(self, asn):
        logging.info('parsing %s', '{}.txt'.format(asn))
        ips = []
        with open('tmp/asns/{}.txt'.format(asn), 'r') as file:
            for line in file:
                try:
                    ips.append(line.strip().split(' ')[0])
                except:
                    logging.error('could not parse line: %s', line)
        return ips

    def _add_ips_to_allow_list(self, ips):
        for ip in ips:
            if ':' in ip:
                self.ipv6_allow_list.append(ip)
            else:
                self.ipv4_allow_list.append(ip)

    def _add_ips_to_deny_list(self, ips):
        for ip in ips:
            if ':' in ip:
                self.ipv6_deny_list.append(ip)
            else:
                self.ipv4_deny_list.append(ip)

    def _collapse_ipv4_addresses(self):
        # collapse ipv4 addresses
        logging.info('collapsing ipv4 addresses')
        logging.info('size ipv4 allow list before: %s',
                     len(self.ipv4_allow_list))
        self.ipv4_allow_list[:] = list(map(
            lambda t: t.exploded,
            ipaddress.collapse_addresses(
                map(ipaddress.IPv4Network, self.ipv4_allow_list)),
        ))
        logging.info('size ipv4 allow list after: %s',
                     len(self.ipv4_allow_list))
        logging.info('size ipv4 deny list before: %s',
                     len(self.ipv4_deny_list))
        self.ipv4_deny_list[:] = list(map(
            lambda t: t.exploded,
            ipaddress.collapse_addresses(
                map(ipaddress.IPv4Network, self.ipv4_deny_list)),
        ))
        logging.info('size ipv4 deny list after: %s', len(self.ipv4_deny_list))
        # collapse ipv6 addresses
        logging.info('collapsing ipv6 addresses')
        logging.info('size ipv6 allow list before: %s',
                     len(self.ipv6_allow_list))
        self.ipv6_allow_list[:] = list(map(
            lambda t: t.compressed,
            ipaddress.collapse_addresses(
                map(ipaddress.IPv6Network, self.ipv6_allow_list)),
        ))
        logging.info('size ipv6 allow list after: %s',
                     len(self.ipv6_allow_list))
        logging.info('size ipv6 deny list before: %s',
                     len(self.ipv6_deny_list))
        self.ipv6_deny_list[:] = list(map(
            lambda t: t.compressed,
            ipaddress.collapse_addresses(
                map(ipaddress.IPv6Network, self.ipv6_deny_list)),
        ))
        logging.info('size ipv6 deny list after: %s', len(self.ipv6_deny_list))


if __name__ == "__main__":
    app()
