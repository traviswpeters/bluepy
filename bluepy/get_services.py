#!/usr/bin/python

"""
Scrape the Bluetooth website to gather the most up-to-date information on BLE.

https://www.bluetooth.com

NOTE: The website was recently updated and all of the previous links that this script used broke.
"""

import requests
import os
import tempfile
import errno
import json
import argparse
from bs4 import BeautifulSoup

DEBUG = False

def DBG(*args):
    if DEBUG:
        msg = " ".join([str(a) for a in args])
        print(msg)

def _get_html(url, local_filename):

    cachedir = os.path.join(tempfile.gettempdir(), 'bluepy')
    try:
        os.mkdir(cachedir)
    except OSError as error:
        if error.errno != errno.EEXIST:
            raise

    cachefilename = os.path.join(cachedir, local_filename)

    DBG(f'DEBUG: {url} -> {cachefilename}')

    try:
        # try to read cached HTML file...
        with open(cachefilename, 'r') as f:
            html = f.read().decode('utf-8')
    except:
        # ...if it doesn't exist, write a cached file and return the HTML
        headers = {'User-Agent': 'BluePy'}
        html = requests.get(url, headers=headers).content
        with open(cachefilename, 'wb') as f:
            f.write(html)

    return html


def _get_table_rows(html=None):
    if html is None:
        html = _get_html()

    soup = BeautifulSoup(html, 'html.parser')

    tables = soup.find_all("table")

    biggest_table = max(tables, key=len)

    #service_table=soup.find("table", attrs={"summary":"Documents This library contains Services."})

    assert(biggest_table)

    for row in biggest_table.find_all('tr'):
        cols = row.find_all('td')
        cols = [ele.text.strip() for ele in cols]
        outrow = [ele for ele in cols if ele]  # Get rid of empty values
        if outrow:
            yield outrow


def get_table(url, local_filename, table_defs):
    """
    Grabs the (largest) table from `url` or cached `local_filename`.

    `table_defs` is a list of tuples: (column name, interpretation function).
    """
    html = _get_html(url, local_filename)
    for row in _get_table_rows(html):
        assert(len(row) == len(table_defs))

        ret = {}
        for col, (name, func) in zip(row, table_defs):
            try:
                if func is None:
                    def func(x):
                        return x
                ret[name] = func(col)
            except:
                print(name)
                print(col)
                print(row)
                raise
        yield ret


# TODO: Level => Specification

def get_service_names():
    for row in get_table('https://www.bluetooth.com/specifications/gatt/services/', 'services.html',
                         (('Name', None),
                          ('Type', None),
                          ('Number', lambda x: int(x, 16)),
                          ('Level', None))):
        row['cname'] = row['Type'].split('.')[-1]
        yield row


def get_descriptors():
    for row in get_table('https://www.bluetooth.com/specifications/gatt/descriptors/', 'descriptors.html',
                         (('Name', None),
                          ('Type', None),
                          ('Number', lambda x: int(x, 16)),
                          ('Level', None))):
        row['cname'] = row['Type'].split('.')[-1]
        yield row


def get_characteristics():
    for row in get_table('https://www.bluetooth.com/specifications/gatt/characteristics/', 'characteristics.html',
                         (('Name', None),
                          ('Type', None),
                          ('Number', lambda x: int(x, 16)),
                          ('Level', None))):
        row['cname'] = row['Type'].split('.')[-1]
        yield row


def get_units():
    for row in get_table('https://www.bluetooth.com/specifications/assigned-numbers/units/', 'units.html',
                         (('Number', lambda x: int(x, 16)),
                          ('Name', None),
                          ('Type', None))):
        row['cname'] = row['Type'].split('.')[-1]
        yield row


# def get_formats():
#     for row in get_table('https://www.bluetooth.com/specifications/assigned-numbers/format-types/', 'formats.html',
#                          (('Number', None), #lambda x: int(x, 16)),
#                           ('Name', None),
#                           ('Type', None),
#                           ('ExpValue', None))):
#         row['cname'] = row['Name']
#         yield row


def get_declarations():
    for row in get_table('https://www.bluetooth.com/specifications/gatt/declarations/', 'declarations.html',
                         (('Name', None),
                          ('Type', None),
                          ('Number', lambda x: int(x, 16)),
                          ('Level', None))):
        row['cname'] = row['Type'].split('.')[-1]
        yield row


class Definitions(object):

    def __init__(self):
        self._characteristics = None
        self._units = None
        self._services = None
        self._descriptors = None
        # self._formats = None
        self._declarations = None

    @property
    def characteristics(self):
        if not self._characteristics:
            self._characteristics = list(get_characteristics())
        return self._characteristics

    @property
    def units(self):
        if not self._units:
            self._units = list(get_units())
        return self._units

    @property
    def services(self):
        if not self._services:
            self._services = list(get_service_names())
        return self._services

    @property
    def descriptors(self):
        if not self._descriptors:
            self._descriptors = list(get_descriptors())
        return self._descriptors

    # @property
    # def formats(self):
    #     if not self._formats:
    #         self._formats = list(get_formats())
    #     return self._formats

    @property
    def declarations(self):
        if not self._declarations:
            self._declarations = list(get_declarations())
        return self._declarations

    def data(self):
        """
        Makes tables like this:
        number, name, common name.
        """
        return {
                'characteristic_UUIDs':
                [(row['Number'],
                  row['cname'],
                  row['Name']) for row in self.characteristics],

                'service_UUIDs':
                [(row['Number'],
                  row['cname'],
                  row['Name']) for row in self.services],

                'descriptor_UUIDs':
                [(row['Number'],
                  row['cname'],
                  row['Name']) for row in self.descriptors],

                'units_UUIDs':
                [(row['Number'],
                  row['cname'],
                  row['Name']) for row in self.units],

                # 'formats':
                # [(row['Number'],
                #   row['cname'],
                #   row['Name']) for row in self.formats],

                'declaration_UUIDs':
                [(row['Number'],
                  row['cname'],
                  row['Name']) for row in self.declarations],
        }

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Fetch an updated set of UUIDs from <https://www.bluetooth.com>.')
    parser.add_argument('--debug', '-d', action='count', default=0, help='show debug output')
    args = parser.parse_args()

    if args.debug > 0:
        DEBUG = True

    d = Definitions()
    s = json.dumps(d.data(),
                   indent=4,
                   ensure_ascii=False,
                   sort_keys=True)
    print(s)
