# -*- coding: utf-8 -*-

import binascii
import exercise
import time
import unittest

class GeneratorTestSuite(unittest.TestCase):
    def test_double_sha(self):
        # Example from bitcoin specification

        self.assertEqual(
            exercise.double_sha(b'hello'),
            binascii.unhexlify('9595c9df90075148eb06860365df33584b75bff782a510c6cd4883a419833d50')
        )

    def test_init(self):
        g = exercise.Generator()

        self.assertEqual(g._counter, 0)
        self.assertEqual(
            g._key,
            binascii.unhexlify('0000000000000000000000000000000000000000000000000000000000000000')
        )

    def test_reseed(self):
        # `reseed` increments the counter to mark the generator as seeded, and computes the new key by
        # hashing the old key together with the seed.

        g = exercise.Generator()

        g.reseed(binascii.unhexlify('1234'))

        self.assertEqual(g._counter, 1)
        self.assertEqual(
            g._key,
            exercise.double_sha(binascii.unhexlify('00000000000000000000000000000000000000000000000000000000000000001234'))
        )

    def test_generate_blocks_from_unseeded(self):
        g = exercise.Generator()

        self.assertRaises(Exception, g._generate_blocks, 1)

    def test_generate_one_block(self):
        g = exercise.Generator()
        g.reseed(b'hello')

        self.assertEqual(g._generate_blocks(1), binascii.unhexlify('178b0a056e064d1eb07238ea7402fcf5'))
        self.assertEqual(g._generate_blocks(1), binascii.unhexlify('83d8d7e8a9a073b5f1d93f601fdaca40'))

    def test_generate_blocks(self):
        g = exercise.Generator()
        g.reseed(b'hello')

        # Because the generator is deterministic, the first two blocks are the same as in `test_generate_one_block`
        self.assertEqual(
            g._generate_blocks(3),
            binascii.unhexlify('178b0a056e064d1eb07238ea7402fcf583d8d7e8a9a073b5f1d93f601fdaca40cce9cac929606fd6506ff1f9b082702d')
        )

    def test_generate_data(self):
        g = exercise.Generator()
        g.reseed(b'hello')

        # The (beginning of) the first block, as seen in `test_generate_one_block`
        self.assertEqual(g.generate_data(13), binascii.unhexlify('178b0a056e064d1eb07238ea74'))

        # After each call to `_generate_data`, a new key is generated, making this data different
        # from the one from the second block in `test_generate_one_block`
        self.assertEqual(g.generate_data(8), binascii.unhexlify('8d6aa6fe3aeda893'))

    def test_generate_data_with_invalid_size(self):
        g = exercise.Generator()
        g.reseed(b'hello')

        self.assertRaises(Exception, g.generate_data, -1)
        self.assertRaises(Exception, g.generate_data, 16_777_216)

class EntropyPoolTestSuite(unittest.TestCase):
    def test_init(self):
        p = exercise.EntropyPool()

        self.assertEqual(len(p._pools), 32)
        self.assertLess(p._last_reseed, time.time() - 0.1)
        self.assertEqual(p.get_reseed_count(), 0)

    def test_add_event(self):
        p = exercise.EntropyPool()
        p.add_event(17, 9, b'hello')

        # 1 byte for source id + 1 byte for length + 5 bytes of random data
        self.assertEqual(p._pools[9].length, 7)

        p.add_event(2, 9, b' world')

        # previous size + 1 byte for source id + 1 byte for length + 6 bytes of random data
        self.assertEquals(p._pools[9].length, 15)

    def test_flush(self):
        p = exercise.EntropyPool()
        p.add_event(17, 9, b'hello')
        p.add_event(2, 9, b' world')

        seed = p._pools[9].flush()

        self.assertEquals(seed, exercise.double_sha(b'\x11\x05hello\x02\x06 world'))
        self.assertEquals(p._pools[9].length, 0)

    def test_no_seed_if_pool_too_small(self):
        p = exercise.EntropyPool()
        p.add_event(1, 0, b'just a bit of data')

        self.assertEquals(p.maybe_seed(), None)

    def rate_limit_seeds(self):
        p = exercise.EntropyPool()
        p.add_event(1, 0, b'abcdefghijklmnopqrstuvwxyz')
        p.add_event(2, 0, b'ABCDEFGHIJKLMNOPQRSTUVWXYZ')
        p.add_event(3, 0, b'0123456789')
        p.maybe_seed()
        p.add_event(4, 0, b'abcdefghijklmnopqrstuvwxyz')
        p.add_event(5, 0, b'ABCDEFGHIJKLMNOPQRSTUVWXYZ')
        p.add_event(6, 0, b'0123456789')

        # Should not reseed because less than 100 ms elapsed since last reseeding
        self.assertEquals(p.maybe_seed(), None)

    def test_return_just_the_first_pool_on_first_reseed(self):
        p = exercise.EntropyPool()
        p.add_event(1, 0, b'abcdefghijklmnopqrstuvwxyz')
        p.add_event(2, 0, b'ABCDEFGHIJKLMNOPQRSTUVWXYZ')
        p.add_event(3, 0, b'0123456789')

        p.add_event(1, 1, b'will not get used')
        p.add_event(1, 2, b'will not get used 2')
        p.add_event(1, 3, b'will not get used 3')

        self.assertEquals(p.maybe_seed(), exercise.double_sha(b'\x01\x1aabcdefghijklmnopqrstuvwxyz\x02\x1aABCDEFGHIJKLMNOPQRSTUVWXYZ\x03\x0a0123456789'))

    def test_return_from_two_pools_second_reseed(self):
        p = exercise.EntropyPool()
        p.add_event(1, 0, b'abcdefghijklmnopqrstuvwxyz')
        p.add_event(2, 0, b'ABCDEFGHIJKLMNOPQRSTUVWXYZ')
        p.add_event(3, 0, b'0123456789')

        p.add_event(1, 1, b'will get used')

        p.add_event(1, 2, b'will not get used')
        p.add_event(1, 3, b'will not get used 2')

        p._reseed_count = 1

        self.assertEquals(
            p.maybe_seed(),
            exercise.double_sha(b'\x01\x1aabcdefghijklmnopqrstuvwxyz\x02\x1aABCDEFGHIJKLMNOPQRSTUVWXYZ\x03\x0a0123456789')
            + exercise.double_sha(b'\x01\x0dwill get used')
        )

    def test_return_from_three_pools_fourth_reseed(self):
        p = exercise.EntropyPool()
        p.add_event(1, 0, b'abcdefghijklmnopqrstuvwxyz')
        p.add_event(2, 0, b'ABCDEFGHIJKLMNOPQRSTUVWXYZ')
        p.add_event(3, 0, b'0123456789')

        p.add_event(1, 1, b'will get used')
        p.add_event(1, 2, b'will get used 2')

        p.add_event(1, 3, b'will not get used')

        p._reseed_count = 3

        self.assertEquals(
            p.maybe_seed(),
            exercise.double_sha(b'\x01\x1aabcdefghijklmnopqrstuvwxyz\x02\x1aABCDEFGHIJKLMNOPQRSTUVWXYZ\x03\x0a0123456789')
            + exercise.double_sha(b'\x01\x0dwill get used')
            + exercise.double_sha(b'\x01\x0fwill get used 2')
        )

if __name__ == '__main__':
    unittest.main()
