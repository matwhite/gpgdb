#!/usr/bin/python

'''
# To create a key using GPG v1:

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
from sqlalchemy import inspect, create_engine
from sqlalchemy import Column, Integer, String, Table, MetaData
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.sql import select
from getpass import getpass
from pprint import pprint

Base = declarative_base()


class Targets(Base):
    __tablename__ = 'targets'

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String, unique=True)
    url = Column(String)
    has_attr = Column(Integer)

    def t(self):
        return(self.__table__)

    def __repr__(self):
        return (
            "<Target(id='%s', name='%s', url='%s', has_attr='%s')>"
            % (self.id, self.name, self.url, self.has_attr)
        )


class PW(Base):
    __tablename__ = 'pw'

    id = Column(Integer, primary_key=True, autoincrement=True)
    tid = Column(Integer)
    user = Column(String)
    pw = Column(String)
    date = Column(Integer)
    note = Column(String)

    def t(self):
        return(self.__table__)


class PW_Attr(Base):
    __tablename__ = 'pw_attr'

    pwid = Column(Integer, primary_key=True)
    attr = Column(String, primary_key=True)
    attr_val = Column(String)

    def t(self):
        return(self.__table__)


class GPW(object):

    def __init__(self, args):
        for arg in [
            'home', 'gpgid', 'gpgkey', 'keyfile', 'pf', 'pwdb', 'sql',
            'c', 'al'
        ]:
            if arg in args:
                setattr(self, arg, args[arg])
            else:
                setattr(self, arg, None)
        self.al = create_engine('sqlite://', echo=True)
        self.sql = self.al.raw_connection()
        self.c = self.sql.cursor()

    def get_passphrase(self):
        self.pf = getpass('Enter your GPG passphrase: ')

    def load_key(self):
        self.gpgkey = gnupg.GPG(gnupghome=self.home)
        self.gpgkey.import_keys(
            open('%s/%s' % (self.home, self.keyfile)).read()
        )

    def init_db(self):
        Base.metadata.create_all(self.al)

    def load_encrypted_db(self):
        data = ''
        with open('%s/%s' % (self.home, self.pwdb), 'r') as f:
            data = f.read()

        decrypted_data = str(self.gpgkey.decrypt(data, passphrase=self.pf))
        if len(decrypted_data) == 0:
            print("No data... wrong passphrase?")
            sys.exit()

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

    # Add a new target
    def add_new_target(self, args):
        # Default for "note" is blank
        if 'note' not in args:
            args['note'] = ''

        # Set "has_attr" boolean
        has_attr = 0
        if 'attr' in args:
            has_attr = 1

        # Insert into Targets
        ins = Targets.__table__.insert().values(
            name=args['name'], url=args['url'], has_attr=has_attr
        )
        tid = str(self.al.execute(ins).inserted_primary_key[0])

        # Insert into PW
        ins = PW.__table__.insert().values(
            tid=tid, user=args['user'], pw=args['pw'], note=args['note'],
            date=time.time()
        )
        pwid = str(self.al.execute(ins).inserted_primary_key[0])

        # Insert Into PW_Attr
        if has_attr:
            for k, v in args['attr'].items():
                ins = PW_Attr.__table__.insert().values(
                    pwid=pwid, attr=k, attr_val=v
                )
                self.al.execute(ins)

    # Add a password to an existing target
    def add_pw(self, args):
        # Default for "note" is blank
        if 'note' not in args:
            args['note'] = ''

        # Find tid by tid or by target name
        tid = 0
        if 'id' in args:
            tid = args['id']
        else:
            tid = self.get_pwid_by_name(args['name'])

        if 'user' not in args:
            args['user'] = self.al.execute(
                select(
                    [PW.__table__.c.user]
                ).where(PW.__table__.c.tid == tid)
            ).fetchone()[0]

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
            'SELECT id FROM targets WHERE name = ?', (name, )
        )
        return(str(self.c.fetchone()[0]))

    def get_pw(self, name=None, tid=None):
        if tid is None:
            tid = self.get_pwid_by_name(args['name'])
        if tid is None:
            print("No password found")
            return

        tab = Table('targets', Targets)
        print type(tab)
        args['user'] = self.al.execute(
            select(
                [tab, PW]
            ).where(tab.c.id == PW.c.tid)
            .where(Targets.t.c.id == tid)
        ).fetchone()[0]
        # self.c.execute(
        #     'SELECT * FROM targets '
        #     'JOIN pw ON(targets.id = pw.tid) '
        #     'WHERE tid = ? ORDER BY date DESC LIMIT 1', (str(tid))
        # )
        pw = dict(self.c.fetchone())

        self.c.execute(
            'SELECT * FROM pw_attr WHERE pwid = ?', (str(pw[4]))
        )
        attr = self.c.fetchall()
        # pw = (pw, attr)
        pw['attr'] = attr
        return pw


g = GPW({
    'home': '/home/gtest/.gnupg',
    'gpgid': 'test@test.com',
    'keyfile': 'keyfile.asc',
    'pf': 'yourpass',   # change later, when done testing
    'pwdb': 'pw2.db.gpg',
})

g.load_key()

# to start

g.init_db()
g.add_new_target({
    'name': 'Test7', 'url': 'http://blah7.com',
    'user': 'test7', 'pw': 'pw7', 'note': '',
    'attr': {'remember': 'one', 'remember0': 'two'},
})
g.add_pw({
    'name': 'Test4', 'pw': 'Il#Drus5orOdec5',
    'attr': {'remember1': '1ww', 'remember2': '1yy', 'remember3': '1zz'},
})

g.save_encrypted_db()

# later, after db is created

g.load_encrypted_db()
print(g.get_pw(tid=4))
