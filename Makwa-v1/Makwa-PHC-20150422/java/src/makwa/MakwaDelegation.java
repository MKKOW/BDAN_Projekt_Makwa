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

/**
 * <p>A {@code MakwaDelegation} instance contains the parameters needed
 * to perform work delegation to an external system (the "delegation
 * server"). Such a set of parameters is specific to a given modulus
 * and work factor. Under normal conditions, it is expected that sets
 * of parameters are created once, then saved in encoded format
 * (as returned by {@link #export}), and decoded again at application
 * start-up.</p>
 *
 * <p>A new set of parameters (for a newly created modulus, or an hitherto
 * unused work factor) can be obtained with {@link #generate}. The modulus
 * is provided as either an encoded modulus, or an encoded Makwa private
 * key. Since generating a set of parameters has a cost similar to computing
 * Makwa 300 times, it is recommended to use a Makwa private key, which
 * enables the "fast path".</p>
 *
 * <p>Instances are immutable and thread-safe.</p>
 *
 * @version   $Revision$
 * @author    Thomas Pornin <pornin@bolet.org>
 */

public class MakwaDelegation {

	private static final int DEFAULT_NUM_MASKS = 300;

	private BigInteger modulus;
	private int workFactor;
	private BigInteger[] alpha;
	private BigInteger[] beta;
	private boolean withGen;

	private MakwaDelegation(BigInteger modulus, int workFactor,
		BigInteger[] alpha, BigInteger[] beta, boolean withGen)
	{
		init(modulus, workFactor, alpha, beta, withGen);
	}

	/**
	 * Create an instance by decoding a set of delegation parameters.
	 *
	 * @param params   the encoded parameters
	 * @throws MakwaException  on decoding error
	 */
	public MakwaDelegation(byte[] params)
	{
		try {
			InputStream in = new ByteArrayInputStream(params);
			int magic = MakwaIO.read32(in);
			BigInteger mod;
			int wf;
			BigInteger[] alpha, beta;
			boolean withGen = false;
			switch (magic) {

			/*
			 * For "normal" parameters (explicit masking pairs),
			 * we just decode all of them. We require that there
			 * are at least 80 pairs, though the recommended
			 * number is 300.
			 */
			case MakwaIO.MAGIC_DELEG_PARAM_GEN:
				withGen = true;
				/* fall through */
			case MakwaIO.MAGIC_DELEG_PARAM:
				mod = MakwaIO.readMPI(in);
				wf = MakwaIO.read32(in);
				int num = MakwaIO.read16(in);
				if (num < 80 && (num != 1 || !withGen)) {
					throw new MakwaException(
						"too few mask pairs");
				}
				alpha = new BigInteger[num];
				beta = new BigInteger[num];
				for (int i = 0; i < num; i ++) {
					alpha[i] = MakwaIO.readMPI(in);
					beta[i] = MakwaIO.readMPI(in);
				}
				checkEOF(in);
				init(mod, wf, alpha, beta, withGen);
				break;

			default:
				throw new MakwaException("unknown Makwa"
					+ " delegation parameter type");
			}
		} catch (IOException ioe) {
			throw new MakwaException("invalid Makwa"
				+ " delegation parameter (truncated)");
		}
	}

	private static void checkEOF(InputStream in)
		throws IOException
	{
		if (in.read() >= 0) {
			throw new MakwaException("invalid Makwa"
				+ " delegation parameter (trailing garbage)");
		}
	}

	private void init(BigInteger modulus, int workFactor,
		BigInteger[] alpha, BigInteger[] beta, boolean withGen)
	{
		if (modulus.signum() <= 0 || modulus.bitLength() < 1273
			|| (modulus.intValue() & 3) != 1)
		{
			throw new MakwaException("invalid modulus");
		}
		if (workFactor < 0) {
			throw new MakwaException("invalid work factor");
		}
		int n = alpha.length;
		if (n > 65535) {
			throw new MakwaException("too many mask pairs");
		}
		if (n < 80 && n != 1) {
			throw new MakwaException("too few mask pairs");
		}
		if (n != beta.length) {
			throw new MakwaException("invalid mask pairs");
		}
		for (int i = 0; i < n; i ++) {
			BigInteger a = alpha[i];
			BigInteger b = beta[i];
			if (a.signum() <= 0 || a.compareTo(modulus) >= 0) {
				throw new MakwaException("invalid mask value");
			}
			if (b.signum() <= 0 || b.compareTo(modulus) >= 0) {
				throw new MakwaException("invalid mask value");
			}
		}
		this.modulus = modulus;
		this.workFactor = workFactor;
		this.alpha = alpha;
		this.beta = beta;
		this.withGen = withGen;
	}

	/**
	 * Encode this set of parameters.
	 *
	 * @return  the encoded parameters
	 */
	public byte[] export()
	{
		try {
			ByteArrayOutputStream baos =
				new ByteArrayOutputStream();
			int num = alpha.length;
			int magic = withGen
				? MakwaIO.MAGIC_DELEG_PARAM_GEN
				: MakwaIO.MAGIC_DELEG_PARAM;
			MakwaIO.write32(baos, magic);
			MakwaIO.writeMPI(baos, modulus);
			MakwaIO.write32(baos, workFactor);
			MakwaIO.write16(baos, num);
			for (int i = 0; i < num; i ++) {
				MakwaIO.writeMPI(baos, alpha[i]);
				MakwaIO.writeMPI(baos, beta[i]);
			}
			return baos.toByteArray();
		} catch (IOException ioe) {
			// This cannot actually happen.
			throw new MakwaException(ioe);
		}
	}

	/**
	 * Get the modulus used by this set of delegation parameters.
	 *
	 * @return  the modulus
	 */
	public BigInteger getModulus()
	{
		return modulus;
	}

	/**
	 * Get the work factor for which this set of parameters was created.
	 *
	 * @return  the work factor
	 */
	public int getWorkFactor()
	{
		return workFactor;
	}

	/**
	 * Symbolic identifier for "classic" delegation parameters (300
	 * random mask pairs).
	 */
	public static final int RANDOM_PAIRS = 1;

	/**
	 * Symbolic identifier for delegation parameters computed from
	 * a generator of invertible quadratic residues. For a modulus
	 * of size n bits, n+64 mask pairs are precomputed.
	 */
	public static final int GENERATOR_EXPAND = 2;

	/**
	 * Symbolic identifier for delegation parameters computed from
	 * a generator of invertible quadratic residues. Only one mask
	 * pair is precomputed. This type leads to the shortest encoded
	 * parameters, but also the largest CPU overhead upon usage.
	 */
	public static final int GENERATOR_ONLY = 3;

	/**
	 * Generate a new set of delegation parameters. The {@code mparam}
	 * argument must contains an encoded Makwa modulus, or an
	 * encoded Makwa private key (the latter is recommended; otherwise,
	 * the generation can be computationally expensive). This method
	 * produces "classic" parameters (300 random mask pairs).
	 *
	 * @param mparam       the Makwa modulus or private key
	 * @param workFactor   the work factor
	 * @throws MakwaException  on error
	 */
	public static MakwaDelegation generate(byte[] mparam, int workFactor)
	{
		return generate(mparam, workFactor, RANDOM_PAIRS);
	}

	/**
	 * <p>Generate a new set of delegation parameters. The {@code
	 * mparam} argument must contains an encoded Makwa modulus, or
	 * an encoded Makwa private key (the latter is recommended;
	 * otherwise, the generation can be computationally
	 * expensive).</p>
	 *
	 * <p>The kind of generated parameters is specified with the
	 * {@code paramType} argument. If the provided modulus or
	 * private key does not include a generator of invertible
	 * quadratic residues, then only {@link #RANDOM_PAIRS} can
	 * be used.<p>
	 * <ul>
	 * <li>{@link #RANDOM_PAIRS}: 300 random mask pairs are
	 * produced.</li>
	 * <li>{@link #GENERATOR_EXPAND}: n+64 mask pairs are
	 * precomputed, for a modulus of n bits.</li>
	 * <li>{@link #GENERATOR_ONLY}: only one mask pair is
	 * precomputed, using the generator of invertible quadratic
	 * residues.</li>
	 * </ul>
	 *
	 * @param mparam       the Makwa modulus or private key
	 * @param workFactor   the work factor
	 * @param paramType    the kind of generated parameters
	 * @throws MakwaException  on error
	 */
	public static MakwaDelegation generate(byte[] mparam,
		int workFactor, int paramType)
	{
		try {
			Makwa mkw = new Makwa(mparam, 0, false, 0, 0);
			BigInteger mod = mkw.getModulus();
			int num;
			switch (paramType) {
			case RANDOM_PAIRS:
				return generateRandomPairs(mkw, workFactor);
			case GENERATOR_EXPAND:
				num = mod.bitLength() + 64;
				break;
			case GENERATOR_ONLY:
				num = 1;
				break;
			default:
				throw new MakwaException("unknown kind"
					+ " of delegation parameters");
			}
			BigInteger qrgen = mkw.getQRGen();
			if (qrgen == null) {
				throw new MakwaException("missing generator of"
					+ " invertible quadratic residues");
			}
			BigInteger[] alpha = new BigInteger[num];
			BigInteger[] beta = new BigInteger[num];
			alpha[0] = qrgen;
			beta[0] = mkw.multiSquare(qrgen, workFactor)
				.modInverse(mod);
			for (int i = 1; i < num; i ++) {
				alpha[i] = modSquare(alpha[i - 1], mod);
				beta[i] = modSquare(beta[i - 1], mod);
			}
			return new MakwaDelegation(
				mod, workFactor, alpha, beta, true);
		} catch (ArithmeticException ae) {
			// This never happens if the modulus has the
			// correct format.
			throw new MakwaException(ae);
		}
	}

	private static MakwaDelegation generateRandomPairs(
		Makwa mkw, int workFactor)
	{
		BigInteger mod = mkw.getModulus();
		int num = DEFAULT_NUM_MASKS;
		BigInteger[] alpha = new BigInteger[num];
		BigInteger[] beta = new BigInteger[num];
		for (int i = 0; i < num; i ++) {
			BigInteger r = MakwaPrivateKey.makeRandNonZero(mod);
			alpha[i] = r.multiply(r).mod(mod);
			beta[i] = mkw.multiSquare(
				alpha[i], workFactor).modInverse(mod);
		}
		return new MakwaDelegation(
			mod, workFactor, alpha, beta, false);
	}

	private static BigInteger modSquare(BigInteger x, BigInteger m)
	{
		return x.multiply(x).mod(m);
	}

	BigInteger[] createMaskPair()
	{
		int num = alpha.length;
		BigInteger v1, v2;
		if (withGen && num == 1) {
			/*
			 * We only have one pair, assumed to use a generator.
			 * We use a random exponent, sufficiently large to
			 * allow all invertible quadratic residues to be
			 * selected with almost uniform probability.
			 */
			int n = modulus.bitLength() + 64;
			byte[] bits = new byte[(n + 8) >>> 3];
			MakwaPrivateKey.prng(bits);
			bits[0] &= (byte)(0xFF >> ((bits.length << 3) - n));
			BigInteger e = new BigInteger(bits);
			v1 = alpha[0].modPow(e, modulus);
			v2 = beta[0].modPow(e, modulus);
		} else {
			/*
			 * We have many pairs; we multiply together a random
			 * selection of these pairs.
			 */
			byte[] bits = new byte[(num + 7) >>> 3];
			MakwaPrivateKey.prng(bits);
			v1 = BigInteger.ONE;
			v2 = BigInteger.ONE;
			for (int i = 0; i < num; i ++) {
				if ((bits[i >>> 3] & (1 << (i & 7))) != 0) {
					v1 = v1.multiply(alpha[i]).mod(modulus);
					v2 = v2.multiply(beta[i]).mod(modulus);
				}
			}
		}
		return new BigInteger[] { v1, v2 };
	}
}
