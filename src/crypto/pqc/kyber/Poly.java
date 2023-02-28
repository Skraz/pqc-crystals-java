package crypto.pqc.kyber;

import java.util.Arrays;

import org.bouncycastle.crypto.digests.SHAKEDigest;

public class Poly
{
    private short[] coeffs;
    private KyberEngine engine;
    private int polyCompressedBytes;
    private int eta1;
    private int eta2;

    public Poly(KyberEngine engine)
    {
        this.coeffs = new short[KyberEngine.KyberN];
        this.engine = engine;
        polyCompressedBytes = engine.getKyberPolyCompressedBytes();
        this.eta1 = engine.getKyberEta1();
        this.eta2 = engine.getKyberEta2();
    }

    public short getCoeffIndex(int i)
    {
        return this.coeffs[i];
    }

    public short[] getCoeffs()
    {
        return this.coeffs;
    }

    public void setCoeffIndex(int i, short val)
    {
        this.coeffs[i] = val;
    }

    public void setCoeffs(short[] coeffs)
    {
        this.coeffs = coeffs;
    }


    /**
     * Computes Negacyclic Number-Theoretical Transform (NTT) of
     * a polynomial in place;
     * Input is in normal order, output is in bitreversed order
     */
    public void polyNtt()
    {
        // Make Constant Space Complexity
        this.setCoeffs(Ntt.ntt(this.getCoeffs()));
        // System.out.print("PolyNTT = [");
        // for (int i = 0; i < KyberEngine.KyberN; i++) {
        //     System.out.printf("%d, ", this.getCoeffIndex(i));
        // }
        // System.out.println("]");
        this.reduce();
    }

    /**
     * Computes Inverse of NTT of a polynomial in place;
     * Input is assumed to be in bit-reversed order,
     * output is in normal order
     */
    public void polyInverseNttToMont()
    {
        this.setCoeffs(Ntt.invNtt(this.getCoeffs()));
    }

    /**
     * Applies Barrett reduction to all coefficient of a polynomial
     * Look at Reduce.java for further comments on Barrett Reduction
     */
    public void reduce()
    {
        int i;
        for (i = 0; i < KyberEngine.KyberN; i++)
        {
            this.setCoeffIndex(i, Reduce.barretReduce(this.getCoeffIndex(i)));
        }
    }

    /**
     * Multiplication of two polynomials in NTT domain
     * @param r Poly: Output Polynomial
     * @param a Poly: First input Polynomial
     * @param b Poly: Second input Polynomial
     */
    public static void baseMultMontgomery(Poly r, Poly a, Poly b)
    {
        int i;
        for (i = 0; i < KyberEngine.KyberN / 4; i++)
        {
            Ntt.baseMult(r, 4 * i,
                a.getCoeffIndex(4 * i), a.getCoeffIndex(4 * i + 1),
                b.getCoeffIndex(4 * i), b.getCoeffIndex(4 * i + 1),
                Ntt.nttZetas[64 + i]);
            Ntt.baseMult(r, 4 * i + 2,
                a.getCoeffIndex(4 * i + 2), a.getCoeffIndex(4 * i + 3),
                b.getCoeffIndex(4 * i + 2), b.getCoeffIndex(4 * i + 3),
                (short)(-1 * Ntt.nttZetas[64 + i]));
        }
    }


    /**
     * Add Polynomial b to This Polynomial
     * @param b Poly: Input Polynomial
     */
    public void addCoeffs(Poly b)
    {
        int i;
        for (i = 0; i < KyberEngine.KyberN; i++)
        {
            this.setCoeffIndex(i, (short)(this.getCoeffIndex(i) + b.getCoeffIndex(i)));
        }
    }

    /**
     * Inplace conversion of all coefficients of a polynomial
     * from normal domain to Montgomery domain
     */
    public void convertToMont()
    {
        int i;
        final short f = (short)(((long)1 << 32) % KyberEngine.KyberQ);
        for (i = 0; i < KyberEngine.KyberN; i++)
        {
            // this.setCoeffIndex(i, Reduce.plantardReduce(this.getCoeffIndex(i) * f));
            this.setCoeffIndex(i, Reduce.montgomeryReduce(this.getCoeffIndex(i) * f));
        }
    }

    /**
     * Compression and subsequent serialization of a polynomial
     * @return Byte[]: Compressed Polynomial
     */
    public byte[] compressPoly()
    {
        int i, j;
        byte[] t = new byte[8];
        byte[] r = new byte[polyCompressedBytes];
        int count = 0;
        this.conditionalSubQ();

        // System.out.print("v = [");
        // Helper.printShortArray(this.coeffs);
        // System.out.print("]\n");

        if (polyCompressedBytes == 128)
        {
            for (i = 0; i < KyberEngine.KyberN / 8; i++)
            {
                for (j = 0; j < 8; j++)
                {
                    t[j] =
                        (byte)((((((short)this.getCoeffIndex(8 * i + j)) << 4)
                            +
                            (KyberEngine.KyberQ / 2)
                        ) / KyberEngine.KyberQ)
                            & 15);
                }

                r[count + 0] = (byte)(t[0] | (t[1] << 4));
                r[count + 1] = (byte)(t[2] | (t[3] << 4));
                r[count + 2] = (byte)(t[4] | (t[5] << 4));
                r[count + 3] = (byte)(t[6] | (t[7] << 4));
                count += 4;
            }
        }
        else if (polyCompressedBytes == 160)
        {
            for (i = 0; i < KyberEngine.KyberN / 8; i++)
            {
                for (j = 0; j < 8; j++)
                {
                    t[j] =
                        (byte)(((((this.getCoeffIndex(8 * i + j) << 5))
                            +
                            (KyberEngine.KyberQ / 2)
                        ) / KyberEngine.KyberQ
                        ) & 31
                        );
                }
                r[count + 0] = (byte)((t[0] >> 0) | (t[1] << 5));
                r[count + 1] = (byte)((t[1] >> 3) | (t[2] << 2) | (t[3] << 7));
                r[count + 2] = (byte)((t[3] >> 1) | (t[4] << 4));
                r[count + 3] = (byte)((t[4] >> 4) | (t[5] << 1) | (t[6] << 6));
                r[count + 4] = (byte)((t[6] >> 2) | (t[7] << 3));
                count += 5;
            }
        }
        else
        {
            throw new RuntimeException("PolyCompressedBytes is neither 128 or 160!");
        }

        // System.out.print("r = ");
        // Helper.printByteArray(r);
        // System.out.println();

        return r;
    }

    /**
     * De-serialization and subsequent decompression of a polynomial;
     * Approximate Inverse of compressPoly
     * @param compressedPolyCipherText byte[]: Compressed Poly Byte Array
     */
    public void decompressPoly(byte[] compressedPolyCipherText)
    {
        int i, count = 0;

        if (engine.getKyberPolyCompressedBytes() == 128)
        {
            for (i = 0; i < KyberEngine.KyberN / 2; i++)
            {
                this.setCoeffIndex(2 * i + 0, (short)((((short)((compressedPolyCipherText[count] & 0xFF) & 15) * KyberEngine.KyberQ) + 8) >> 4));
                this.setCoeffIndex(2 * i + 1, (short)((((short)((compressedPolyCipherText[count] & 0xFF) >> 4) * KyberEngine.KyberQ) + 8) >> 4));
                count += 1;
            }
        }
        else if (engine.getKyberPolyCompressedBytes() == 160)
        {
            int j;
            byte[] t = new byte[8];
            for (i = 0; i < KyberEngine.KyberN / 8; i++)
            {
                t[0] = (byte)((compressedPolyCipherText[count + 0] & 0xFF) >> 0);
                t[1] = (byte)(((compressedPolyCipherText[count + 0] & 0xFF) >> 5) | ((compressedPolyCipherText[count + 1] & 0xFF) << 3));
                t[2] = (byte)((compressedPolyCipherText[count + 1] & 0xFF) >> 2);
                t[3] = (byte)(((compressedPolyCipherText[count + 1] & 0xFF) >> 7) | ((compressedPolyCipherText[count + 2] & 0xFF) << 1));
                t[4] = (byte)(((compressedPolyCipherText[count + 2] & 0xFF) >> 4) | ((compressedPolyCipherText[count + 3] & 0xFF) << 4));
                t[5] = (byte)((compressedPolyCipherText[count + 3] & 0xFF) >> 1);
                t[6] = (byte)(((compressedPolyCipherText[count + 3] & 0xFF) >> 6) | ((compressedPolyCipherText[count + 4] & 0xFF) << 2));
                t[7] = (byte)((compressedPolyCipherText[count + 4] & 0xFF) >> 3);
                count += 5;
                for (j = 0; j < 8; j++)
                {
                    this.setCoeffIndex(8 * i + j, (short)(((t[j] & 31) * KyberEngine.KyberQ + 16) >> 5));
                }
            }
        }
        else
        {
            throw new RuntimeException("PolyCompressedBytes is neither 128 or 160!");
        }

    }

    /**
     * Serialisation of Polynomial
     * @return byte[]: Serialised Poly Byte Array
     */
    public byte[] toBytes()
    {
        byte[] r = new byte[KyberEngine.KyberPolyBytes];
        short t0, t1;
        this.conditionalSubQ();
        for (int i = 0; i < KyberEngine.KyberN / 2; i++)
        {
            t0 = this.getCoeffIndex(2 * i);
            t1 = this.getCoeffIndex(2 * i + 1);
            r[3 * i] = (byte)(t0 >> 0);
            r[3 * i + 1] = (byte)((t0 >> 8) | (t1 << 4));
            r[3 * i + 2] = (byte)(t1 >> 4);
        }

        return r;

    }

    /**
     * De-Serialisation of a polynomial;
     * Inverse of toBytes
     * @param inpBytes byte[]: Byte Array to Deserialise
     */
    public void fromBytes(byte[] inpBytes)
    {
        int i;
        for (i = 0; i < KyberEngine.KyberN / 2; i++)
        {
            this.setCoeffIndex(2 * i, (short)(
                (
                    ((inpBytes[3 * i + 0] & 0xFF) >> 0)
                        | ((inpBytes[3 * i + 1] & 0xFF) << 8)
                ) & 0xFFF)
            );
            this.setCoeffIndex(2 * i + 1, (short)(
                (
                    ((inpBytes[3 * i + 1] & 0xFF) >> 4)
                        | (long)((inpBytes[3 * i + 2] & 0xFF) << 4)
                ) & 0xFFF)
            );
        }
    }

    /**
     * Convert polynomial to 32-byte message
     * @return byte[]: Output Message
     */
    public byte[] toMsg()
    {
        byte[] outMsg = new byte[KyberEngine.getKyberIndCpaMsgBytes()];
        int i, j;
        short t;

        this.conditionalSubQ();

        for (i = 0; i < KyberEngine.KyberN / 8; i++)
        {
            outMsg[i] = 0;
            for (j = 0; j < 8; j++)
            {
                t = (short)(((((short)(this.getCoeffIndex(8 * i + j) << 1) + KyberEngine.KyberQ / 2) / KyberEngine.KyberQ) & 1));
                outMsg[i] |= (byte)(t << j);
            }
        }
        return outMsg;
    }

    /**
     * Convert 32-byte message to polynomial
     * @param msg byte[]: Input Message
     */
    public void fromMsg(byte[] msg)
    {
        int i, j;
        short mask;
        if (msg.length != KyberEngine.KyberN / 8)
        {
            throw new RuntimeException("KYBER_INDCPA_MSGBYTES must be equal to KYBER_N/8 bytes!");
        }
        for (i = 0; i < KyberEngine.KyberN / 8; i++)
        {
            for (j = 0; j < 8; j++)
            {
                mask = (short)((-1) * (short)(((msg[i] & 0xFF) >> j) & 1));
                this.setCoeffIndex(8 * i + j, (short)(mask & (short)((KyberEngine.KyberQ + 1) / 2)));
            }
        }
    }

    /**
     * Applies conditional subtraction of q to each coefficient
     * of a polynomial.
     * For further details of Conditional Sub of Q see Reduce.java
     */
    public void conditionalSubQ()
    {
        int i;
        for (i = 0; i < KyberEngine.KyberN; i++)
        {
            this.setCoeffIndex(i, Reduce.conditionalSubQ(this.getCoeffIndex(i)));
        }
    }

    /**
     * Sample a polynomial deterministically from a seed and a nonce,
     * with output polynomial close to centered binomial distribution
     * with parameter Kyber Eta1
     * @param seed byte[]: Seed Byte Array
     * @param nonce byte: Nonce Byte
     */
    public void getEta1Noise(byte[] seed, byte nonce)
    {
        byte[] buf = new byte[KyberEngine.KyberN * eta1 / 4];
        SHAKEDigest prf = Symmetric.KyberPRF(seed, nonce);
        prf.doFinal(buf, 0, buf.length);
        CBD.kyberCBD(this, buf, eta1);
    }

    /**
     * Sample a polynomial deterministically from a seed and a nonce,
     * with output polynomial close to centered binomial distribution
     * with parameter Kyber Eta2
     * @param seed byte[]: Seed Byte Array
     * @param nonce byte: Nonce Byte
     */
    public void getEta2Noise(byte[] seed, byte nonce)
    {
        byte[] buf = new byte[KyberEngine.KyberN * eta2 / 4];
        SHAKEDigest prf = Symmetric.KyberPRF(seed, nonce);
        prf.doFinal(buf, 0, buf.length);
        CBD.kyberCBD(this, buf, eta2);
    }

    /**
     * Subtract This Polynomial from b Poly. (b Poly - This Poly)
     * @param b Poly: Polynomial to Subtract from
     */
    public void polySubtract(Poly b)
    {
        int i;
        for (i = 0; i < KyberEngine.KyberN; i++)
        {
            this.setCoeffIndex(i, (short)(b.getCoeffIndex(i) - this.getCoeffIndex(i)));
        }
    }

    /**
     * Convert Polynomial to String
     * @return String: Coeffs listed in String
     */
    public String toString()
    {
        return Arrays.toString(coeffs);
    }
}
