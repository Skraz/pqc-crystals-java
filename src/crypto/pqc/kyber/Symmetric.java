package crypto.pqc.kyber;

import org.bouncycastle.crypto.digests.SHAKEDigest;

public class Symmetric
{
    /**
     * Absorb step of the SHAKE128 specialized for the Kyber context.
     * @param seed byte[]: Kyber SymBytes byte array
     * @param a int: Additional byte of input
     * @param b int: Additional byte of input
     * @return SHAKEDigest: Initialised SHAKE-128 Object
     */
    public static SHAKEDigest KyberXOF(byte[] seed, int a, int b)
    {
        SHAKEDigest xof = new SHAKEDigest(128);
        byte[] buf = new byte[seed.length + 2];
        System.arraycopy(seed, 0, buf, 0, seed.length);
        buf[seed.length] = (byte)a;
        buf[seed.length + 1] = (byte)b;

        xof.update(buf, 0, seed.length + 2);


        return xof;
    }

    public final static int SHAKE128_rate = 168;

    /**
     * Usage of SHAKE256 as a PRF, concatenates secret and public input
     * @param seed byte[]: Key Byte Array of Kyber SymBytes
     * @param nonce byte: single-byte nonce (public PRF input)
     * @return SHAKEDigest: Initialised SHAKE-256 Object
     */
    public static SHAKEDigest KyberPRF(byte[] seed, byte nonce)
    {
        SHAKEDigest prf = new SHAKEDigest(256);

        byte[] extSeed = new byte[seed.length + 1];
        System.arraycopy(seed, 0, extSeed, 0, seed.length);
        extSeed[seed.length] = nonce;
        prf.update(extSeed, 0, extSeed.length);
        return prf;
    }
}
