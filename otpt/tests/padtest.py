import otpt
import unittest
import tempfile
import os
from textwrap import dedent


class PadTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._keyfile = cls._create_keyfile()
        
    @classmethod
    def _create_keyfile(cls):
        keyfile = tempfile.mkstemp()[1]
        with open(keyfile, 'wb') as keypool:
            keypool.write(dedent("""1) jt~c!e3b5&7r4h@l:g5hp1o]kmzhookuvs0rm*
                */iftovt}k0fz@0o0xfoau?4rzrm&gociqg+|/s7(tx;g=wq]4d!t7>3lozu|)
                >~6!l=b!gr|cqf+lek5|~q8-[y(q*hryji(cj(~}g]-_wnv$ve2il=rr#^/ne9
                trcq}k*6]la^?|~}xw6}~c]z8/yu5])dosgsion2gualjpqf()2^,-d+l2$kk1
                e^<l+rqxw#o[5e13*j.,1-.g1||t7*n~q!8y52<j8h&[p[x6a<ex$dlfdk({hu
                c:wasg&bu,,luf?=>ixtbc$nb;jh*8e>${m]c]bijfi(l+ewtgk^zg;4vr]rt}
                :0g9lf9*joqoy02>+|6eoz:x%bp=u<;x[3luldngj9qaml%+am0ju|]~j*xfq:
                szpvx|3jndgxu$o>farnm*h<#;qn^isicw?l>kt<c6i.}e[[(_ag.=1sml9q$j
                0<s7f6q~swul3.i_0,%8_66d#s]ng*.0j,ej_1hmjq)kz%qli-=hxw%f?=<.b[
                $&=_fe:i0!h@4q@.)=szj34i4fn2gml;4a3*v0hzpm;1^)*u2u@0/4.zr3[obh
                gj3do|$@1wb@{jmj3y1[l~q4hg4-_yiq*za**(m/kvdhy5/&n1w?v/-f#iz#8w
                =h~z-z|!zm#_rx~f[1@71vom7co}7:-3=]7_uw5fxo#a^eizj4,?rldt(kg~<$
                yunz+kux,b~ma^yhq3aeg77@_w(tskcgvlux(y#qo~om=s&,b^wnyqtf5^ak-$
                k)t#oa!wyx0)6if8g)q+#l!|;en~(}jtupa5i7m!z]#3!drauaulg(~q6}9vsu
                %qtzte0y|r{udyttc|%j1z[qngsjkod8%xh6tpk8ea<-;=q-[~?l2bn)]]z,uz
                f0;qxhjyxmeb;p$q8v7ulau%i,ss<3xvw>3p/osgz:lmc.yc>,oc$i!.342qd.
                $0gv_+ywcmm:y#2:[gzt1qnrmkjahwbd[]d.at0uzm|)g9qiewp]&jo/"""))
        return keyfile
        
    @classmethod
    def tearDownClass(cls):
        os.remove(cls._keyfile)

    def setUp(self):
        self.plaintexts = [
            '',
            ' ',
            'abc',
            'ABC',
            'AaBbCc',
            'aAbBcC',
            '123',
            '321',
            'hello world',
            'hello world!',
            """`~!@#$%^&*()-=_+[]{};':",./<>?"""
        ]
        self.block_sizes = [0, 1, 2, 7, 10, 64, 100, 128]
        self.pad = otpt.Pad(self._keyfile)
        
    def test_inverse_equality(self):
        for text in self.plaintexts:
            self.assertEqual(text, self.pad.decode(self.pad.encode(text)))
            
    def test_nonexistent_keyfile(self):
        with self.assertRaises(IOError):
            pad = otpt.Pad('doesnotexist.fakefile')
        
    def test_encode_block_size(self):
        for bs in self.block_sizes:
            block = self.pad.fetch_encode_block(bs)
            self.assertEqual(bs, len(block))
        
    def test_decode_block_size(self):
        for bs in self.block_sizes:
            block = self.pad.fetch_decode_block(0, bs)
            self.assertEqual(bs, len(block))
            

if __name__ == '__main__':
    unittest.main()