/*
 * -----------------------------------------------------------------------
 * (c) Thomas Pornin 2014. This software is provided 'as-is', without
 * any express or implied warranty. In no event will the author be held
 * liable for any damages arising from the use of this software.
 *
 * Permission is granted to anyone to use this software for any purpose,
 * including commercial applications, and to alter it and redistribute it
 * freely, subject to no restriction.
 *
 * Technical remarks and questions can be addressed to:
 * <pornin@bolet.org>
 * -----------------------------------------------------------------------
 */

package makwa;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

/**
 * <p>A {@code MakwaPrivateKey} instance encapsulates a Makwa private
 * key, i.e. the two prime factors whose product is the Makwa
 * modulus.</p>
 * 
 * <p>A new private key can be generated with {@link #generate}. The
 * target modulus size (in bits) is provided; it must be at least
 * 1273 bits (the normal modulus size is 2048 bits).</p>
 *
 * <p>Private and public keys can be encoded into array of bytes; the
 * {@link #exportPrivate} and {@link #exportPublic} methods implement
 * this serialization. Decoding can be done in several ways:</p>
 * <ul>
 * <li>A new {@code MakwaPrivateKey} instance can be created over an
 * encoded private key used as parameter for the constructor.</li>
 * <li>A public key is actually the modulus; encoding and decoding
 * can be performed with the static {@link #encodePublic} and
 * {@link #decodePublic} methods.</li>
 * <li>The {@link Makwa} class can be instantiated with an encoded
 * public or private key as first parameter.</li>
 * </ul>
 *
 * <p>The encoded format for a modulus consists in the concatenation,
 * in that order, of the following:</p>
 * <ul>
 * <li>a four-byte header: 55 41 4D 30, or 55 41 4D 70;</li>
 * <li>the modulus as a multi-precision integer (MPI):
 *    <ul>
 *    <li>an integer value "{@code len}" encoded in unsigned big-endian
 *    convention over exactly two bytes;</li>
 *    <li>exactly {@code len} bytes which encode the modulus in unsigned
 *    big-endian convention;</li>
 *    </ul>
 * When a MPI is encoded, the minimal length encoding should be used
 * (no leading byte of value 0x00);</li>
 * <li>if the header used the second form (ending with 70), then another
 * MPI follows, encoding a generator of invertible quadratic residues.</li>
 * </ul>
 *
 * <p>The encoded format for a private consists in the concatenation,
 * in that order, of the following:</p>
 * <ul>
 * <li>a four-byte header: 55 41 4D 31 or 55 41 4D 71</li>
 * <li>the first prime factor, as a MPI;</li>
 * <li>the second prime factor, as a MPI;</li>
 * <li>(only if the header ended with 71) a generator of invertible
 * quadratic residues.</li>
 * </ul>
 *
 * <p>When encoding a private key, the greater of the two prime factors
 * is supposed to come first.</p>
 *
 * <p>Instances of {@code MakwaPrivateKey} are immutable and
 * thread-safe.</p>
 *
 * @version   $Revision$
 * @author    Thomas Pornin <pornin@bolet.org>
 */

public class MakwaPrivateKey {

	private BigInteger p;
	private BigInteger q;
	private BigInteger modulus;
	private BigInteger invQ;
	private BigInteger QRGen;

	/**
	 * Create a new instance by decoding a private key. This method
	 * makes some sanity checks but does not verify that the two
	 * prime integers are indeed prime.
	 *
	 * @param encoded   the encoded private key
	 * @throws MakwaException  on error
	 */
	public MakwaPrivateKey(byte[] encoded)
	{
		try {
			InputStream in = new ByteArrayInputStream(encoded);
			int magic = MakwaIO.read32(in);
			boolean withGen = false;
			switch (magic) {
			case MakwaIO.MAGIC_PRIVKEY:
				break;
			case MakwaIO.MAGIC_PRIVKEY_WITHGEN:
				withGen = true;
				break;
			default:
				throw new MakwaException(
					"not an encoded Makwa private key");
			}
			BigInteger p = MakwaIO.readMPI(in);
			BigInteger q = MakwaIO.readMPI(in);
			if (withGen) {
				QRGen = MakwaIO.readMPI(in);
			}
			if (in.read() >= 0) {
				throw new MakwaException("invalid Makwa"
					+ " private key (trailing garbage)");
			}
			init(p, q, QRGen);
		} catch (IOException ioe) {
			throw new MakwaException(
				"invalid Makwa private key (truncated)");
		}
	}

	/**
	 * Create a new instance with two specific primes. This method
	 * makes some sanity checks but does not verify that the two
	 * prime integers are indeed prime.
	 *
	 * @param p   the first prime factor
	 * @param q   the second prime factor
	 */
	public MakwaPrivateKey(BigInteger p, BigInteger q)
	{
		init(p, q, null);
	}

	/**
	 * Create a new instance with two specific primes and a quadratic
	 * residue generator. This method makes some sanity checks but
	 * does not verify that the two prime integers are indeed prime,
	 * or that the generator really generates all the invertible
	 * quadratic residues.
	 *
	 * @param p     the first prime factor
	 * @param q     the second prime factor
	 * @param gen   the quadratic residue generator
	 */
	public MakwaPrivateKey(BigInteger p, BigInteger q, BigInteger gen)
	{
		init(p, q, gen);
	}

	private void init(BigInteger p, BigInteger q, BigInteger gen)
	{
		if (p.signum() <= 0 || q.signum() <= 0
			|| (p.intValue() & 3) != 3
			|| (q.intValue() & 3) != 3
			|| p.equals(q))
		{
			throw new MakwaException("invalid Makwa private key");
		}
		if (p.compareTo(q) < 0) {
			// We normally want the first prime to be the
			// largest of the two. This can help some
			// implementations of the CRT.
			BigInteger t = p;
			p = q;
			q = t;
		}
		this.p = p;
		this.q = q;
		this.QRGen = gen;
		modulus = p.multiply(q);
		if (modulus.bitLength() < 1273) {
			throw new MakwaException("invalid Makwa private key");
		}
		if (gen != null && (gen.compareTo(BigInteger.ONE) <= 0
			|| gen.compareTo(modulus) >= 0))
		{
			throw new MakwaException("invalid Makwa private key");
		}
		try {
			invQ = q.modInverse(p);
		} catch (ArithmeticException ae) {
			// This cannot happen if p and q are distinct
			// and both prime, as they should.
			throw new MakwaException(ae);
		}
	}

	/**
	 * Get the modulus (public key).
	 *
	 * @return  the Makwa modulus
	 */
	public BigInteger getModulus()
	{
		return modulus;
	}

	/**
	 * Get the invertible quadratic residue generator, if defined
	 * in this key. {@code null} is returned if no such generator
	 * is known.
	 *
	 * @return  the intertible quadratic residue generator, or {@code null}
	 */
	public BigInteger getQRGen()
	{
		return QRGen;
	}

	/**
	 * Generate a new private key. A secure PRNG is used to produce
	 * the new private key. The target modulus size (in bits) is
	 * provided as parameter; it must be no smaller than 1273 bits,
	 * and no greater than 32768 bits. The normal and recommended
	 * modulus size is 2048 bits.
	 *
	 * @param size   the target modulus size
	 * @return  the new private key
	 * @throws MakwaException  on error
	 */
	public static MakwaPrivateKey generate(int size)
	{
		if (size < 1273 || size > 32768) {
			throw new MakwaException(
				"invalid modulus size: " + size);
		}

		/*
		 * We generate p and q such that:
		 * -- p = 2*p1*p2 + 1
		 * -- q = 2*q1*q2 + 1
		 * -- p1, p2, q1 and q2 are distinct random primes of the
		 *    same size.
		 * -- p*q has the required size
		 * -- '4' has multiplicative order p1*p2 modulo p
		 *    (i.e. 4^p1 != 1 mod p and 4^p2 != 1 mod p)
		 * -- '4' has multiplicative order q1*q2 modulo q
		 *    (i.e. 4^q1 != 1 mod q and 4^q2 != 1 mod q)
		 *
		 * These rules imply that p = 3 mod 4 and q = 3 mod 4.
		 *
		 * To obtain the right size, we generate all small
		 * primes (p1, p2, q1 and q2) as x*2^k+y for a fixed
		 * 4-bit pattern x, a fixed k, and a y < 2^k. The
		 * following values for x guarantee the size of n:
		 *
		 *    x   size of n
		 *    7   14+4*k
		 *    8   15+4*k
		 *   10   16+4*k
		 *   12   17+4*k
		 */
		int k = (size - 14) >> 2;
		int x;
		switch ((size - 14) & 3) {
		case 0:
			x = 7;
			break;
		case 1:
			x = 8;
			break;
		case 2:
			x = 10;
			break;
		default:
			x = 12;
			break;
		}

		/*
		 * We accumulate generated small primes in a list; a new
		 * small prime is accepted only if it is distinct from
		 * all previously generated primes (it is extremely
		 * improbable that the same prime is generated twice,
		 * but the check has negligible cost). For every new
		 * prime p_j, we compute the combinations 2*p_i*p_j+1
		 * and check that value for primality. We must take care
		 * not to reuse the same small prime for p and q.
		 *
		 * 'sp' contains the list of generated small primes.
		 * 'used' marks the "used primes".
		 * 'bp' contains the list of found big primes.
		 *
		 * Algorithm stops when the size of bp reaches 2.
		 */
		List<BigInteger> sp = new ArrayList<BigInteger>();
		List<Boolean> used = new ArrayList<Boolean>();
		List<BigInteger> bp = new ArrayList<BigInteger>();
		int len = (k + 12) >>> 3;
		byte[] buf = new byte[len];
		int mz16 = 0xFFFF >>> (8 * len - k);
		int mo16 = x << (k + 16 - 8 * len);
		BigInteger FOUR = BigInteger.valueOf(4);

		/*
		 * Number of needed Miller-Rabin rounds depends on the
		 * target prime size. We follow table 4.4 from the
		 * Handbook of Applied Cryptography. Note that since
		 * the target modulus size is at least 1273, we know
		 * that k is necessarily above 300.
		 *
		 * (Size of small primes is not k but k+3 or k+4, but
		 * we conservatively use k here.)
		 */
		int numMR = computeNumMR(k);
		int numMR2 = computeNumMR(k << 1);

		loop: for (;;) {
			prng(buf);
			buf[0] &= (byte)(mz16 >>> 8);
			buf[1] &= (byte)mz16;
			buf[0] |= (byte)(mo16 >>> 8);
			buf[1] |= (byte)mo16;
			buf[len - 1] |= (byte)0x01;
			BigInteger pj = new BigInteger(buf);

			/*
			 * Check that the new pj is indeed prime.
			 */
			if (isMultipleSmallPrime(pj)) {
				continue;
			}
			if (!passesMR(pj, numMR)) {
				continue;
			}

			/*
			 * Check if we already have that prime.
			 */
			for (BigInteger z : sp) {
				if (z.equals(pj)) {
					continue loop;
				}
			}

			/*
			 * Try combinations.
			 */
			for (int i = sp.size() - 1; i >= 0; i --) {
				if (used.get(i)) {
					continue;
				}
				BigInteger pi = sp.get(i);
				BigInteger p = pi.multiply(pj)
					.shiftLeft(1).add(BigInteger.ONE);
				if (!passesMR(p, numMR2)) {
					continue;
				}
				if (FOUR.modPow(pi, p).equals(BigInteger.ONE)) {
					continue;
				}
				if (FOUR.modPow(pj, p).equals(BigInteger.ONE)) {
					continue;
				}

				/*
				 * Found a big prime.
				 */
				bp.add(p);
				if (bp.size() == 2) {
					break loop;
				}
				sp.add(pj);
				used.add(true);
				used.set(i, true);
				continue loop;
			}

			/*
			 * No combinations yet with that prime.
			 */
			sp.add(pj);
			used.add(false);
		}

		BigInteger p = bp.get(0);
		BigInteger q = bp.get(1);
		if (p.compareTo(q) < 0) {
			BigInteger t = p;
			p = q;
			q = t;
		}
		MakwaPrivateKey mk = new MakwaPrivateKey(p, q, FOUR);
		if (mk.getModulus().bitLength() != size) {
			throw new MakwaException("key generation error");
		}
		return mk;
	}

	/**
	 * Encode the private key into bytes.
	 *
	 * @return  the encoded private key
	 */
	public byte[] exportPrivate()
	{
		try {
			ByteArrayOutputStream out = new ByteArrayOutputStream();
			MakwaIO.write32(out, QRGen == null
				? MakwaIO.MAGIC_PRIVKEY
				: MakwaIO.MAGIC_PRIVKEY_WITHGEN);
			MakwaIO.writeMPI(out, p);
			MakwaIO.writeMPI(out, q);
			if (QRGen != null) {
				MakwaIO.writeMPI(out, QRGen);
			}
			return out.toByteArray();
		} catch (IOException ioe) {
			// Cannot actually happen.
			throw new MakwaException(ioe);
		}
	}

	/**
	 * Encode the public key (modulus and optional generator) into
	 * bytes.
	 *
	 * @return  the encoded modulus
	 */
	public byte[] exportPublic()
	{
		return encodePublic(modulus, QRGen);
	}

	/**
	 * Encode a modulus into bytes.
	 *
	 * @param modulus   the modulus
	 * @return  the encoded modulus
	 */
	public static byte[] encodePublic(BigInteger modulus)
	{
		return encodePublic(modulus, null);
	}

	/**
	 * Encode a modulus and, optionally, a generator, into bytes.
	 *
	 * @param modulus   the modulus
	 * @param qrgen     generator of invertible quadratic residues
	 *                  (or {@code null})
	 * @return  the encoded modulus and generator
	 */
	public static byte[] encodePublic(BigInteger modulus, BigInteger qrgen)
	{
		try {
			ByteArrayOutputStream out = new ByteArrayOutputStream();
			MakwaIO.write32(out, qrgen == null
				? MakwaIO.MAGIC_PUBKEY
				: MakwaIO.MAGIC_PUBKEY_WITHGEN);
			MakwaIO.writeMPI(out, modulus);
			if (qrgen != null) {
				MakwaIO.writeMPI(out, qrgen);
			}
			return out.toByteArray();
		} catch (IOException ioe) {
			// Cannot actually happen.
			throw new MakwaException(ioe);
		}
	}

	/**
	 * Decode a modulus from its encoded representation.
	 *
	 * @param encoded   the encoded modulus
	 * @return  the modulus
	 * @throws MakwaException  on error
	 */
	public static BigInteger decodePublic(byte[] encoded)
	{
		try {
			InputStream in = new ByteArrayInputStream(encoded);
			int magic = MakwaIO.read32(in);
			boolean withGen = false;
			switch (magic) {
			case MakwaIO.MAGIC_PUBKEY:
				break;
			case MakwaIO.MAGIC_PUBKEY_WITHGEN:
				withGen = true;
				break;
			default:
				throw new MakwaException(
					"not an encoded Makwa modulus");
			}
			BigInteger mod = MakwaIO.readMPI(in);
			if (withGen) {
				MakwaIO.readMPI(in);
			}
			if (in.read() >= 0) {
				throw new MakwaException("invalid Makwa"
					+ " modulus (trailing garbage)");
			}
			return mod;
		} catch (IOException ioe) {
			throw new MakwaException(
				"invalid Makwa private key (truncated)");
		}
	}

	BigInteger getP()
	{
		return p;
	}

	BigInteger getQ()
	{
		return q;
	}

	BigInteger getInvQ()
	{
		return invQ;
	}

	private static SecureRandom RNG;

	static synchronized void prng(byte[] buf)
	{
		if (RNG == null) {
			RNG = new SecureRandom();
		}
		RNG.nextBytes(buf);
	}

	/*
	 * Generate a random integer in the 0..m-1 range (inclusive).
	 */
	static BigInteger makeRandInt(BigInteger m)
	{
		if (m.signum() <= 0) {
			throw new MakwaException("invalid modulus (negative)");
		}
		if (m.equals(BigInteger.ONE)) {
			return BigInteger.ZERO;
		}
		int blen = m.bitLength();
		int len = (blen + 7) >>> 3;
		int mask = 0xFF >>> (8 * len - blen);
		byte[] buf = new byte[len];
		for (;;) {
			prng(buf);
			buf[0] &= (byte)mask;
			BigInteger z = new BigInteger(1, buf);
			if (z.compareTo(m) < 0) {
				return z;
			}
		}
	}

	/*
	 * Make a random integer in the 1..m-1 range (inclusive).
	 */
	static BigInteger makeRandNonZero(BigInteger m)
	{
		if (m.compareTo(BigInteger.ONE) <= 0) {
			throw new MakwaException(
				"invalid modulus (less than 2)");
		}
		for (;;) {
			BigInteger z = makeRandInt(m);
			if (z.signum() != 0) {
				return z;
			}
		}
	}

	/*
	 * Product of all primes from 3 to 47.
	 */
	private static final long PSP = 307444891294245705L;
	private static final BigInteger PSPB = BigInteger.valueOf(PSP);

	/*
	 * Returns true if the provided integer is a multiple of a prime
	 * integer in the 2 to 47 range. Note that it returns true if
	 * x is equal to one of these small primes.
	 */
	private static boolean isMultipleSmallPrime(BigInteger x)
	{
		if (x.signum() < 0) {
			x = x.negate();
		}
		if (x.signum() == 0) {
			return true;
		}
		if (!x.testBit(0)) {
			return true;
		}
		long a = PSP;
		long b = x.mod(PSPB).longValue();
		while (b != 0) {
			long t = a % b;
			a = b;
			b = t;
		}
		return a != 1;
	}

	/**
	 * Test n for non-primality with some rounds of Miller-Rabin.
	 * Returned value is false if n is composite, true if n was
	 * not detected as composite.
	 *
	 * Number of rounds should be adjusted so that the probability
	 * of a composite integer not to be detected is sufficiently
	 * low. IF the candidate value is a random odd integer (as is
	 * the case here, and as opposed to a potentially specially
	 * crafted integer), then the number of rounds can be quite low.
	 * The Handbook of Applied Cryptography, section 4.4.1,
	 * discusses these issues; in particular, for RANDOM odd
	 * integers of at least 300 bits, 9 rounds are sufficient to
	 * get probability of failure below 2^-80.
	 *
	 * @param n    the integer to test
	 * @param cc   the count of rounds
	 * @return  {@code false} for a composite integer, {@code true}
	 *          if the value was not detected as composite
	 */
	private static boolean passesMR(BigInteger n, int cc)
	{
		/*
		 * Normalize n and handle very small values and even
		 * integers.
		 */
		if (n.signum() < 0) {
			n = n.negate();
		}
		if (n.signum() == 0) {
			return true;
		}
		if (n.bitLength() <= 3) {
			switch (n.intValue()) {
			case 2: case 3: case 5: case 7:
				return false;
			default:
				return true;
			}
		}
		if (!n.testBit(0)) {
			return true;
		}

		/*
		 * Miller-Rabin algorithm:
		 *
		 * Set n-1 = r * 2^s  for an odd integer r and an integer s.
		 * For each round:
		 *  1. Choose a random a in the 2..n-2 range (inclusive)
		 *  2. Compute y = a^r mod n
		 *  3. If y != 1 and y != n-1, do:
		 *     a. j <- 1
		 *     b. while j < s and y != n-1:
		 *          y <- y^2 mod n
		 *          if y = 1 return false
		 *          j <- j+1
		 *     c. if y != n-1 return false
		 *
		 * If we do all the rounds without detecting a composite,
		 * return true.
		 */
		BigInteger nm1 = n.subtract(BigInteger.ONE);
		BigInteger nm2 = nm1.subtract(BigInteger.ONE);
		BigInteger r = nm1;
		int s = 0;
		while (!r.testBit(0)) {
			s ++;
			r = r.shiftRight(1);
		}
		while (cc -- > 0) {
			BigInteger a = makeRandNonZero(nm2).add(BigInteger.ONE);
			BigInteger y = a.modPow(r, n);
			if (!y.equals(BigInteger.ONE) && !y.equals(nm1)) {
				for (int j = 1; j < s; j ++) {
					if (y.equals(nm1)) {
						break;
					}
					y = y.multiply(y).mod(n);
					if (y.equals(BigInteger.ONE)) {
						return false;
					}
				}
				if (!y.equals(nm1)) {
					return false;
				}
			}
		}
		return true;
	}

	/**
	 * Return the number of Miller-Rabin rounds recommended to detect
	 * composite integers of size 'k' bits with a probability of
	 * failure below 2^-80. We follow here the table 4.4 from the
	 * Handbook of Applied Cryptography.
	 * <strong>WARNING:</strong> this value is good only under the
	 * assumption that the input is a random odd integer. If the
	 * input is specially crafted, it may evade detection with higher
	 * probability.
	 *
	 * @param k   the input integer size
	 * @return  the number of Miller-Rabin rounds
	 */
	private static int computeNumMR(int k)
	{
		if (k < 400) {
			if (k < 250) {
				if (k < 100) {
					return 40;
				} else if (k < 150) {
					return 27;
				} else if (k < 200) {
					return 18;
				} else {
					return 15;
				}
			} else {
				if (k < 300) {
					return 12;
				} else if (k < 350) {
					return 9;
				} else {
					return 8;
				}
			}
		} else {
			if (k < 650) {
				if (k < 450) {
					return 7;
				} else if (k < 550) {
					return 6;
				} else {
					return 5;
				}
			} else {
				if (k < 850) {
					return 4;
				} else if (k < 1300) {
					return 3;
				} else {
					return 2;
				}
			}
		}
	}
}
