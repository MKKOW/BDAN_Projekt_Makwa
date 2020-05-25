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

package makwa.tools;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;

import makwa.MakwaDelegation;

/**
 * <p>This command-line tools generates sets of parameters for Makwa
 * delegation. Usage:</p>
 * <pre>
 *    DelegGen [ -it ] inParam workFactor outFile
 * </pre>
 *
 * <p>The {@code inParam} parameter is the name of a file containing an
 * encoded Makwa modulus, or an encoded Makwa private key. Processing
 * is (much) faster if a private key is used; but the obtained set is
 * equally valid otherwise.</p>
 *
 * <p>The {@code workFactor} parameter is the work factor for which the
 * set of parameters is created. Each set of parameters is specific to a
 * single work factor.</p>
 *
 * <p>The resulting set of parameters is finally encoded into the
 * file whose name is provided as {@code outFile}.</p>
 *
 * <p>If either the "{@code -genX}" or "{@code -gen1}" option is used,
 * then the parameters will be created using the generator of invertible
 * quadratic residues included in the provided public or private key.
 * If that provided key does not include such a generator, then the
 * process fails and an error is reported.</p>
 * <ul>
 * <li>If {@code -genX} is used, then the generated parameters will
 * include {@code n+64} precomputed mask pairs, for a modulus of
 * {@code n} bits; the resulting parameter file may be quite large
 * (a bit more than 1 megabyte for a 2048-bit modulus).</li>
 * <li>If {@code -gen1} is used, then the generated parameters will
 * include only a single mask pair, and thus will be very compact
 * (less than 1 kilobyte for a 2048-bit modulus). However, this
 * method implies a larger computation overhead upon usage.</li>
 * </ul>
 *
 * <p>Using the generator means that the delegation process is
 * information theoretic secure, i.e. the delegation server learns
 * nothing about the password even if it is assumed to have unlimited
 * computing abilities (with the "classic" delegation parameters, such
 * security is achieved "only" through computational infeasibility, i.e.
 * leaking information requires a lot more computing power than is
 * available on Earth today and in the foreseeable future). Since
 * generator-based delegation implies a substantial computational
 * overhead on the client (for a 2048-bit modulus, the overhead is 7x
 * with "-genX", somehwat more with "-gen1"), it is recommended to use
 * it only if it is required by a specific security or marketing
 * model.</p>
 *
 * @version   $Revision$
 * @author    Thomas Pornin
 */

public class DelegGen {

	public static void main(String[] args)
		throws IOException
	{
		int paramType = MakwaDelegation.RANDOM_PAIRS;
		String[] nargs = new String[3];
		int j = 0;
		for (int i = 0; i < args.length; i ++) {
			if (args[i].equalsIgnoreCase("-genx")) {
				if (paramType != MakwaDelegation.RANDOM_PAIRS) {
					usage();
				}
				paramType = MakwaDelegation.GENERATOR_EXPAND;
			} else if (args[i].equalsIgnoreCase("-gen1")) {
				if (paramType != MakwaDelegation.RANDOM_PAIRS) {
					usage();
				}
				paramType = MakwaDelegation.GENERATOR_ONLY;
			} else {
				if (j >= nargs.length) {
					usage();
				}
				nargs[j ++] = args[i];
			}
		}
		if (j != nargs.length) {
			usage();
		}
		byte[] mparam = readAllBytes(nargs[0]);
		int workFactor = Integer.parseInt(nargs[1]);
		MakwaDelegation md = MakwaDelegation.generate(
			mparam, workFactor, paramType);
		FileOutputStream out = new FileOutputStream(nargs[2]);
		try {
			out.write(md.export());
		} finally {
			out.close();
		}
	}

	private static void usage()
	{
		System.err.println(
"usage: DelegGen [ -genX | -gen1 ] inParam workFactor outFile");
		System.exit(1);
	}

	private static byte[] readAllBytes(String name)
		throws IOException
	{
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		byte[] buf = new byte[8192];
		FileInputStream in = new FileInputStream(name);
		try {
			for (;;) {
				int len = in.read(buf);
				if (len < 0) {
					return baos.toByteArray();
				}
				baos.write(buf, 0, len);
			}
		} finally {
			in.close();
		}
	}
}
