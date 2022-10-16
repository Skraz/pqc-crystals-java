package crypto.pqc.kyber;

public class Reduce
{

    /**
     * Montgomery reduction; given a 32-bit integer a, computes
     * 16-bit integer congruent to a * R^-1 mod q,
     * where R=2^16
     * @param a int: Input integer to be reduced;
     *               has to be in {-q2^15,...,q2^15-1}
     * @return int: integer in {-q+1,...,q-1} congruent to a * R^-1 modulo q.
     */
    public static short montgomeryReduce(int a)
    {
        int t;
        short u;

        u = (short)(a * KyberEngine.KyberQinv);
        t = (int)(u * KyberEngine.KyberQ);
        t = a - t;
        t >>= 16;
        return (short)t;
    }

    /**
     * Plantard Reduction where l = 16, alpha = 3, q = 3329
     * @param a
     * @return (a * -2^(32) mod +- q)
     */
    public static short plantardReduce(int a) 
    {
        int plantardQInv = 1806234369; // q^-1 mod 2^32

        int u = a * plantardQInv;

        short v = (short) (((((short) (u >>> 16)) + 8) * KyberEngine.KyberQ) >>> 16);

        return v;
    }

    /**
     * Barrett reduction; given a 16-bit integer a, computes
     * 16-bit integer congruent to a mod q in {0,...,q}
     * @param a int: input integer to be reduced
     * @return int: integer in {0,...,q} congruent to a modulo q.
     */
    public static short barretReduce(short a)
    {
        short t;
        long shift = (((long)1) << 26);
        short v = (short)((shift + (KyberEngine.KyberQ / 2)) / KyberEngine.KyberQ);
        t = (short)((v * a) >> 26);
        t = (short)(t * KyberEngine.KyberQ);
        return (short)(a - t);
    }

    /**
     * Conditionally Subtract Q
     * @param a int: Input Integer
     * @return int: a - q if a >= q, else a
     */
    public static short conditionalSubQ(short a)
    {
        a -= KyberEngine.KyberQ;
        a += (a >> 15) & KyberEngine.KyberQ;
        return a;
    }

}
