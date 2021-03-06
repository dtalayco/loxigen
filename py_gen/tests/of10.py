#!/usr/bin/env python
# Copyright 2013, Big Switch Networks, Inc.
#
# LoxiGen is licensed under the Eclipse Public License, version 1.0 (EPL), with
# the following special exception:
#
# LOXI Exception
#
# As a special exception to the terms of the EPL, you may distribute libraries
# generated by LoxiGen (LoxiGen Libraries) under the terms of your choice, provided
# that copyright and licensing notices generated by LoxiGen are not altered or removed
# from the LoxiGen Libraries and the notice provided below is (i) included in
# the LoxiGen Libraries, if distributed in source code form and (ii) included in any
# documentation for the LoxiGen Libraries, if distributed in binary form.
#
# Notice: "Copyright 2013, Big Switch Networks, Inc. This library was generated by the LoxiGen Compiler."
#
# You may not use this file except in compliance with the EPL or LOXI Exception. You may obtain
# a copy of the EPL at:
#
# http://www.eclipse.org/legal/epl-v10.html
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# EPL for the specific language governing permissions and limitations
# under the EPL.
import unittest
import test_data
from testutil import add_datafiles_tests

try:
    import loxi.of10 as ofp
    from loxi.generic_util import OFReader
except ImportError:
    exit("loxi package not found. Try setting PYTHONPATH.")

class TestImports(unittest.TestCase):
    def test_toplevel(self):
        import loxi
        self.assertTrue(hasattr(loxi, "ProtocolError"))
        self.assertEquals(loxi.version_names[1], "1.0")
        ofp = loxi.protocol(1)
        self.assertEquals(ofp.OFP_VERSION, 1)
        self.assertTrue(hasattr(ofp, "action"))
        self.assertTrue(hasattr(ofp, "common"))
        self.assertTrue(hasattr(ofp, "const"))
        self.assertTrue(hasattr(ofp, "message"))

    def test_version(self):
        import loxi
        self.assertTrue(hasattr(loxi.of10, "ProtocolError"))
        self.assertTrue(hasattr(loxi.of10, "OFP_VERSION"))
        self.assertEquals(loxi.of10.OFP_VERSION, 1)
        self.assertTrue(hasattr(loxi.of10, "action"))
        self.assertTrue(hasattr(loxi.of10, "common"))
        self.assertTrue(hasattr(loxi.of10, "const"))
        self.assertTrue(hasattr(loxi.of10, "message"))

class TestActions(unittest.TestCase):
    def test_output_equality(self):
        action = ofp.action.output(port=1, max_len=0x1234)
        action2 = ofp.action.output(port=1, max_len=0x1234)
        self.assertEquals(action, action2)

        action2.port = 2
        self.assertNotEquals(action, action2)
        action2.port = 1

        action2.max_len = 0xffff
        self.assertNotEquals(action, action2)
        action2.max_len = 0x1234

# Assumes action serialization/deserialization works
class TestActionList(unittest.TestCase):
    def test_normal(self):
        expected = []
        bufs = []

        def add(action):
            expected.append(action)
            bufs.append(action.pack())

        add(ofp.action.output(port=1, max_len=0xffff))
        add(ofp.action.output(port=2, max_len=0xffff))
        add(ofp.action.output(port=ofp.OFPP_IN_PORT, max_len=0xffff))
        add(ofp.action.bsn_set_tunnel_dst(dst=0x12345678))
        add(ofp.action.nicira_dec_ttl())

        actions = ofp.action.unpack_list(OFReader(''.join(bufs)))
        self.assertEquals(actions, expected)

    def test_empty_list(self):
        self.assertEquals(ofp.action.unpack_list(OFReader('')), [])

    def test_invalid_list_length(self):
        buf = '\x00' * 9
        with self.assertRaisesRegexp(ofp.ProtocolError, 'Buffer too short'):
            ofp.action.unpack_list(OFReader(buf))

    def test_invalid_action_length(self):
        buf = '\x00' * 8
        with self.assertRaisesRegexp(ofp.ProtocolError, 'Buffer too short'):
            ofp.action.unpack_list(OFReader(buf))

        buf = '\x00\x00\x00\x04'
        with self.assertRaisesRegexp(ofp.ProtocolError, 'Buffer too short'):
            ofp.action.unpack_list(OFReader(buf))

        buf = '\x00\x00\x00\x10\x00\x00\x00\x00'
        with self.assertRaisesRegexp(ofp.ProtocolError, 'Buffer too short'):
            ofp.action.unpack_list(OFReader(buf))

    def test_invalid_action_type(self):
        buf = '\xff\xfe\x00\x08\x00\x00\x00\x00'
        with self.assertRaisesRegexp(ofp.ProtocolError, 'unknown action type'):
            ofp.action.unpack_list(OFReader(buf))

class TestConstants(unittest.TestCase):
    def test_ports(self):
        self.assertEquals(0xffff, ofp.OFPP_NONE)

    def test_wildcards(self):
        self.assertEquals(0xfc000, ofp.OFPFW_NW_DST_MASK)

class TestCommon(unittest.TestCase):
    def test_match(self):
        match = ofp.match()
        self.assertEquals(match.wildcards, ofp.OFPFW_ALL)
        self.assertEquals(match.tcp_src, 0)
        buf = match.pack()
        match2 = ofp.match.unpack(buf)
        self.assertEquals(match, match2)

class TestMessages(unittest.TestCase):
    def test_hello_construction(self):
        msg = ofp.message.hello()
        self.assertEquals(msg.version, ofp.OFP_VERSION)
        self.assertEquals(msg.type, ofp.OFPT_HELLO)
        self.assertEquals(msg.xid, None)

        msg = ofp.message.hello(xid=123)
        self.assertEquals(msg.xid, 123)

        # 0 is a valid xid distinct from None
        msg = ofp.message.hello(xid=0)
        self.assertEquals(msg.xid, 0)

    def test_echo_request_construction(self):
        msg = ofp.message.echo_request(data="abc")
        self.assertEquals(msg.data, "abc")

    def test_echo_request_invalid_length(self):
        buf = "\x01\x02\x00\x07\x12\x34\x56"
        with self.assertRaisesRegexp(ofp.ProtocolError, "buffer too short"):
            ofp.message.echo_request.unpack(buf)

    def test_echo_request_equality(self):
        msg = ofp.message.echo_request(xid=0x12345678, data="abc")
        msg2 = ofp.message.echo_request(xid=0x12345678, data="abc")
        self.assertEquals(msg, msg2)

        msg2.xid = 1
        self.assertNotEquals(msg, msg2)
        msg2.xid = msg.xid

        msg2.data = "a"
        self.assertNotEquals(msg, msg2)
        msg2.data = msg.data

# The majority of the serialization tests are created here using the files in
# the test_data directory.
class TestDataFiles(unittest.TestCase):
    pass
add_datafiles_tests(TestDataFiles, 'of10/', ofp)

class TestParse(unittest.TestCase):
    def test_parse_header(self):
        import loxi

        msg_ver, msg_type, msg_len, msg_xid = ofp.message.parse_header("\x01\x04\xAF\xE8\x12\x34\x56\x78")
        self.assertEquals(1, msg_ver)
        self.assertEquals(4, msg_type)
        self.assertEquals(45032, msg_len)
        self.assertEquals(0x12345678, msg_xid)

        with self.assertRaisesRegexp(loxi.ProtocolError, "too short"):
            ofp.message.parse_header("\x01\x04\xAF\xE8\x12\x34\x56")

    def test_parse_message(self):
        import loxi
        import loxi.of10 as ofp

        buf = "\x01\x00\x00\x08\x12\x34\x56\x78"
        msg = ofp.message.parse_message(buf)
        assert(msg.xid == 0x12345678)

        # Get a list of all message classes
        test_klasses = [x for x in ofp.message.__dict__.values()
                        if type(x) == type
                           and issubclass(x, ofp.message.Message)
                           and x != ofp.message.Message]

        for klass in test_klasses:
            self.assertIsInstance(ofp.message.parse_message(klass(xid=1).pack()), klass)

class TestUtils(unittest.TestCase):
    def test_pretty_wildcards(self):
        self.assertEquals("OFPFW_ALL", ofp.util.pretty_wildcards(ofp.OFPFW_ALL))
        self.assertEquals("0", ofp.util.pretty_wildcards(0))
        self.assertEquals("OFPFW_DL_SRC|OFPFW_DL_DST",
                          ofp.util.pretty_wildcards(ofp.OFPFW_DL_SRC|ofp.OFPFW_DL_DST))
        self.assertEquals("OFPFW_NW_SRC_MASK&0x2000",
                          ofp.util.pretty_wildcards(ofp.OFPFW_NW_SRC_ALL))
        self.assertEquals("OFPFW_NW_SRC_MASK&0x1a00",
                          ofp.util.pretty_wildcards(0x00001a00))
        self.assertEquals("OFPFW_IN_PORT|0x80000000",
                          ofp.util.pretty_wildcards(ofp.OFPFW_IN_PORT|0x80000000))

class TestAll(unittest.TestCase):
    """
    Round-trips every class through serialization/deserialization.
    Not a replacement for handcoded tests because it only uses the
    default member values.
    """

    def setUp(self):
        mods = [ofp.action,ofp.message,ofp.common]
        self.klasses = [klass for mod in mods
                              for klass in mod.__dict__.values()
                              if hasattr(klass, 'show')]
        self.klasses.sort(key=lambda x: str(x))

    def test_serialization(self):
        expected_failures = []
        for klass in self.klasses:
            def fn():
                obj = klass()
                if hasattr(obj, "xid"): obj.xid = 42
                buf = obj.pack()
                obj2 = klass.unpack(buf)
                self.assertEquals(obj, obj2)
            if klass in expected_failures:
                self.assertRaises(Exception, fn)
            else:
                fn()

    def test_parse_message(self):
        expected_failures = []
        for klass in self.klasses:
            if not issubclass(klass, ofp.message.Message):
                continue
            def fn():
                obj = klass(xid=42)
                buf = obj.pack()
                obj2 = ofp.message.parse_message(buf)
                self.assertEquals(obj, obj2)
            if klass in expected_failures:
                self.assertRaises(Exception, fn)
            else:
                fn()

    def test_show(self):
        expected_failures = []
        for klass in self.klasses:
            def fn():
                obj = klass()
                if hasattr(obj, "xid"): obj.xid = 42
                obj.show()
            if klass in expected_failures:
                self.assertRaises(Exception, fn)
            else:
                fn()

if __name__ == '__main__':
    unittest.main()
