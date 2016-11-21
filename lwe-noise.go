package frodo_post_quantum_key_exchange_golang

import _ "crypto/cipher"


var (
	CDF_LENGTH_D1 = 4;
	CDF_D1 = [4]uint8{43, 104, 124, 127};
	CDF_LENGTH_D2 = 5;
	CDF_D2 = [5]uint16{784, 1774, 2022, 2046, 2047}; // out of [0, 2047]

/* Approximation to the rounded Gaussian with sigma^2 = 1.75. The Renyi
 * divergence of order 100 between the two is 1.000301.
 * The range of the distribution is [0..5]. Requires 11 bits (plus 1 for the
 * sign).
 */
CDF_LENGTH_D3 = 6;
CDF_D3 =  [6]uint16{602, 1521, 1927, 2031, 2046, 2047}; // out of [0, 2047]

/* Approximation to the rounded Gaussian with sigma^2 = 1.75. The Renyi
 * divergence of order 500 between the two is ~1.0000146.
 * The range of the distribution is [0..6]. Requires 15 bits (plus 1 for the
 * sign).
 */
CDF_LENGTH_D4 = 7;
CDF_D4 = [7]uint16{9651, 24351, 30841, 32500, 32745, 32766, 32767}; // out of [0, 32767]

//#if (LWE_CDF_TABLE & 0x0F) != 0
//#error "Static constants are not aligned. A potential cache-timing attack."
//#endif
)

func count_bits8(x uint64) {
	// Count bits set in each byte of x using the "SWAR" algorithm.
	x -= (x >> 1) & 0x5555555555555555;
	x = (x & 0x3333333333333333) + ((x >> 2) & 0x3333333333333333);
	x = (x + (x >> 4)) & 0x0f0f0f0f0f0f0f0f;
	return x;
}

func count_bits32(x uint32) {
	/* Count bits set to 1 using the "SWAR" algorithm.
	 * Can be replaced with __builtin_popcount(x) that resolves either to a
	 * a hardware instruction or a library implementation.
	 */
	x -= (x >> 1) & 0x55555555;
	x = (x & 0x33333333) + ((x >> 2) & 0x33333333);
	x = (x + (x >> 4)) & 0x0f0f0f0f;
	x += x >> 8;
	x += x >> 16;
	return x & 0x3F;  // Returned answer is <= 32 which is at most 6 bits long.
}

