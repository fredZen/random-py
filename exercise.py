from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

import hashlib
import sys
import time

def double_sha(bytes):
    """Two rounds of SHA-256. Unlike a single round, this is immune to extension attacks."""
    return hashlib.sha256(hashlib.sha256(bytes).digest()).digest()

class Generator:
    def __init__(self):
        # Set counter to zero to indicate that the generator has not been seeded yet.
        self._counter = 0

        # The key is a always 128 bit pad. Start off with a clean one.
        self._key = (0).to_bytes(32, byteorder='little')

    def _counter_block(self):
        """The internal counter, formatted as a 16 byte block suitable for consumption by the cipher"""
        return self._counter.to_bytes(16, byteorder='little')

    def reseed(self, seed):
        self._key = double_sha(self._key + seed)
        self._counter += 1

    def _generate_blocks(self, block_count):
        """Internal function, generates a number of blocks of random output."""
        if self._counter <= 0:
            raise Exception('Trying to read values from unseeded generator')

        # ECB is generally a terrible choice. Here, we’re using it as a building block
        # to essentially make CTR, while retaining control over the counter.
        cipher = Cipher(algorithms.AES(self._key), modes.ECB(), backend=default_backend())

        result = b''

        for i in range(0, block_count):
            encryptor = cipher.encryptor()
            result += encryptor.update(self._counter_block()) + encryptor.finalize()
            self._counter += 1

        return result

    MAX_OUTPUT_SIZE = 2 ** 20

    def generate_data(self, byte_count):
        """Generates up to MAX_OUTPUT_SIZE bytes of random data.
        The limitation to one megabyte of random data per call is there to decrease
        statistical deviation from pure randomness (the cipher never repeats itself
        during one run, while true random data can). It should not be raised."""
        if byte_count < 0 or byte_count > self.MAX_OUTPUT_SIZE:
            raise Exception('Invalid byte count requested {}'.format(byte_count))

        result = self._generate_blocks((byte_count + 15) // 16)[0:byte_count]

        # Switch to a new key to avoid later compromise of this output
        self._key = self._generate_blocks(2)

        return result


class EntropyPool:
    """Pools randomness from external entropy sources"""

    class SubPool:
        def __init__(self):
            self.length = 0
            self._hash = hashlib.sha256()

        def add_event(self, data):
            self._hash.update(data)
            self.length += len(data)

        def flush(self):
            digest = self._hash.digest()
            self._hash = hashlib.sha256()
            self.length = 0
            return hashlib.sha256(digest).digest()

    def __init__(self):
        self._pools = [self.SubPool() for i in range(0, 32)]
        self._reseed_count = 0
        self._last_reseed = time.time() - 1

    def get_reseed_count(self):
        return self._reseed_count

    def add_event(self, source_number, pool_number, data):
        """Randomness sources call this method when they have a random event.
        They are supposed to distribute their events over the pools in a cyclical
        fashion; see Ferguson, Schneier and Kohno for the reason why this is
        not enforced by `add_event`."""

        if source_number < 0 or source_number > 255:
            raise Exception('Source number must be between 0 and 255')

        if pool_number < 0 or pool_number > 31:
            raise Exception('Pool number must be between 0 and 31')

        length = len(data)

        if length < 1 or length > 32:
            raise Exception('Data should be between 1 and 32 bytes long')

        formatted_event = (
            source_number.to_bytes(1, byteorder='little')
            + length.to_bytes(1, byteorder='little')
            + data
        )
        self._pools[pool_number].add_event(formatted_event)

    MIN_POOL_SIZE = 64

    def maybe_seed(self):
        if self._pools[0].length < self.MIN_POOL_SIZE or time.time() - self._last_reseed <= 0.1:
            return

        self._reseed_count += 1
        seed = b''

        for i in range(0, 32):
            seed += self._pools[i].flush()
            if self._reseed_count & (1 << i):
                break

        return seed


class PoolingGenerator:
    def __init__(self, entropy_pool):
        self._entropy_pool = entropy_pool
        self._generator = Generator()

    def generate_data(self, byte_count):
        seed = self._entropy_pool.maybe_seed()

        if seed is not None:
            self._generator.reseed(seed)

        if self._entropy_pool.get_reseed_count() == 0:
            raise Exception('Random number generator not seeded yet')

        return self._generator.generate_data(byte_count)


def raw_generator(seed):
    generator = Generator()
    generator.reseed(time32.to_bytes(4, byteorder='little'))
    return generator

def pooling_generator(seed):
    pool = EntropyPool()

    pool.add_event(0, 0, time32.to_bytes(4, byteorder='little'))

    # Add fake entropy to take the pool over its minimum size
    pool.add_event(1, 0, (0).to_bytes(30, byteorder='little'))
    pool.add_event(2, 0, (0).to_bytes(30, byteorder='little'))

    generator = PoolingGenerator(pool)
    return generator

if __name__ == '__main__':

    # Hilariously poor seed, but for demonstration purposes it will have to do
    # In reality, there only are no more than a few bits of entropy in the
    # startup time of the script; the rough time can be assumed to be known to the attacker.
    time32 = int(time.time()) & 0xffffffff

    # generator = pooling_generator(time32)
    generator = raw_generator(time32)

    while True:
        sys.stdout.buffer.write(generator.generate_data(1024))
