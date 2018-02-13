#!/usr/bin/python

'''
# to create my key using gpg v1:

gpg --gen-key
...
gpg: /home/gtest/.gnupg/trustdb.gpg: trustdb created
gpg: key EBB94674 marked as ultimately trusted
public and secret key created and signed.
...
gpg -a --export EBB94674 >> /home/gtest/.gnupg/keyfile.asc
gpg -a --export-secret-keys EBB94674 >> /home/gtest/.gnupg/keyfile.asc

'''

import sys
import time
import gnupg
import sqlite3
from getpass import getpass
from pprint import pprint


class GPW(object):

    def __init__(self, args):
        for arg in [
            'home', 'gpgid', 'gpgkey', 'keyfile', 'pf', 'pwdb',
            'sql', 'c'
        ]:
            if arg in args:
                setattr(self, arg, args[arg])
            else:
                setattr(self, arg, None)

    def get_passphrase(self):
        self.pf = getpass('Enter your GPG passphrase: ')

    def load_key(self):
        self.gpgkey = gnupg.GPG(gnupghome=self.home)
        self.gpgkey.import_keys(
            open('%s/%s' % (self.home, self.keyfile)).read()
        )

    def init_db(self):
        sql = '''BEGIN TRANSACTION;
        CREATE TABLE targets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name VARCHAR(50), url VARCHAR(250), has_attr INTEGER
        );
        CREATE UNIQUE INDEX name ON targets(name);
        CREATE TABLE pw (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tid INTEGER,
            user VARCHAR(200), pw VARCHAR(200),
            date INTEGER, note VARCHAR(200)
        );
        CREATE INDEX tid ON pw(tid);
        CREATE INDEX date ON pw(date);
        CREATE TABLE pw_attr (
            pwid INTEGER, attr VARCHAR(200), attr_val VARCHAR(200)
        );
        CREATE INDEX pwid ON pw_attr(pwid);
        CREATE UNIQUE INDEX id_attr ON pw_attr(pwid, attr);
        COMMIT;
        '''
        self.sql = sqlite3.connect(':memory:')
        self.c = self.sql.cursor()
        self.c.executescript(sql)
        self.sql.commit()

    def load_encrypted_db(self):
        data = ''
        with open('%s/%s' % (self.home, self.pwdb), 'r') as f:
            data = f.read()

        decrypted_data = str(self.gpgkey.decrypt(data, passphrase=self.pf))
        if len(decrypted_data) == 0:
            print("No data... wrong passphrase?")
            sys.exit()

        self.sql = sqlite3.connect(':memory:')
        self.c = self.sql.cursor()
        self.c.executescript(decrypted_data)
        self.sql.commit()
        print decrypted_data

    def save_encrypted_db(self):
        dump = ''
        for line in self.sql.iterdump():
            dump += ('%s\n' % line)

        print(dump)
        encrypted_data = self.gpgkey.encrypt(dump, self.gpgid)

        with open('%s/%s' % (self.home, self.pwdb), 'w') as f:
            f.write(str(encrypted_data))

    def add_new_pw(self, args):
        has_attr = 0
        if 'attr' in args:
            has_attr = 1
        self.c.execute(
            'INSERT INTO targets (name,url,has_attr) VALUES(?,?,?)',
            (args['name'], args['url'], has_attr)
        )
        tid = self.c.lastrowid

        self.c.execute(
            'INSERT INTO pw (tid,user,pw,note,date) '
            'VALUES(?,?,?,?,?)',
            (tid, args['user'], args['pw'], args['note'], time.time())
        )
        pwid = self.c.lastrowid

        if has_attr:
            for k, v in args['attr'].items():
                self.c.execute(
                    'INSERT INTO pw_attr (pwid,attr,attr_val) '
                    'VALUES(?,?,?)',
                    (pwid, k, v)
                )

        self.sql.commit()

    def dict_factory(self, row):
        d = {}
        for idx, col in enumerate(self.c.description):
            d[col[0]] = row[idx]
        return d

    def add_pw(self, args):
        if 'note' not in args:
            args['note'] = ''

        tid = 0
        if 'id' in args:
            tid = args['id']
        else:
            tid = self.get_pwid_by_name(args['name'])

        if 'user' not in args:
            self.c.execute(
                'SELECT user FROM pw WHERE tid = ? '
                'ORDER BY date DESC LIMIT 1',
                (tid)
            )
            args['user'] = self.c.fetchone()[0]

        self.c.execute(
            'INSERT INTO pw (tid,user,pw,note,date) '
            'VALUES(?,?,?,?,?)',
            (tid, args['user'], args['pw'], args['note'], time.time())
        )
        pwid = self.c.lastrowid

        if 'attr' in args:
            for k, v in args['attr'].items():
                self.c.execute(
                    'INSERT INTO pw_attr (pwid,attr,attr_val) '
                    'VALUES(?,?,?)',
                    (pwid, k, v)
                )

        self.sql.commit()

    def get_pwid_by_name(self, name):
        self.c.execute(
            'SELECT id FROM targets WHERE name = ?', (name)
        )
        return(str(self.c.fetchone()[0]))

    def get_pw(self, name=None, tid=None):
        if tid is None:
            tid = self.get_pwid_by_name(args['name'])
        if tid is None:
            print("No password found")
            return

        # print(help(self.c))
        # self.sql.row_factory = sqlite3.Row
        self.c.execute(
            'SELECT * FROM targets '
            'JOIN pw ON(targets.id = pw.tid) '
            'WHERE tid = ? ORDER BY date DESC LIMIT 1', (str(tid))
        )
        # self.sql.row_factory = self.dict_factory
        pwr = self.c.fetchone()
        pw = self.dict_factory(pwr)
        pprint(self.c.description)
        pprint(pw)

        self.c.execute(
            'SELECT * FROM pw_attr WHERE pwid = ?', (str(pw['tid']))
        )
        attr = self.c.fetchall()
        pw = (pw, attr)
        return pw


g = GPW({
    'home': '/home/gtest/.gnupg',
    'gpgid': 'test@test.com',
    'keyfile': 'keyfile.asc',
    'pf': 'yourpass',   # Remove later when done testing
    'pwdb': 'pw2.db.gpg',
})

g.load_key()

# to start
g.init_db()
g.add_new_pw({
    'name': 'Test4', 'url': 'http://blah4.com',
    'user': 'test4', 'pw': 'Gann=Of1Du7glog-', 'note': '',
    'attr': {'remember1': 'one', 'remember2': 'two', 'remember3': 'three'},
})
g.add_pw({
    'name': 'Test4', 'pw': 'tect7Ov#Eenn#oj8',
    'attr': {'remember1': 'www', 'remember2': 'yyy', 'remember3': 'zzz'},
})

g.save_encrypted_db()

# later on
g.load_encrypted_db()

print(g.get_pw(tid=4))
