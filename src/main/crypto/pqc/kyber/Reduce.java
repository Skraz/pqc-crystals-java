package crypto.pqc.kyber;

public class Reduce
{

    /**
     * Montgomery Reduction
     * @param a
     * @return
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
     * Barret Reduction
     * @param a
     * @return
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
     * Conditional Subtract Q
     * @param a
     * @return
     */
    public static short conditionalSubQ(short a)
    {
        a -= KyberEngine.KyberQ;
        a += (a >> 15) & KyberEngine.KyberQ;
        return a;
    }

}
