package crypto.pqc.kyber;

import java.util.Arrays;

public class PolyVec
{
    Poly[] vec;
    private KyberEngine engine;
    private int kyberK;
    private int polyVecBytes;

    public PolyVec(KyberEngine engine)
    {
        this.engine = engine;
        this.kyberK = engine.getKyberK();
        this.polyVecBytes = engine.getKyberPolyVecBytes();

        this.vec = new Poly[kyberK];
        for (int i = 0; i < kyberK; i++)
        {
            vec[i] = new Poly(engine);
        }
    }

    public PolyVec()
        throws Exception
    {
        throw new Exception("Requires Parameter");
    }

    public Poly getVectorIndex(int i)
    {
        return vec[i];
    }

    /**
     * Apply forward NTT to all elements of a vector of polynomials
     */
    public void polyVecNtt()
    {
        int i;
        for (i = 0; i < kyberK; i++)
        {
            this.getVectorIndex(i).polyNtt();
        }
    }

    /**
     * Apply inverse NTT to all elements of a vector of polynomials
     * and multiply by Montgomery factor 2^16
     */
    public void polyVecInverseNttToMont()
    {
        for (int i = 0; i < kyberK; i++)
        {
            this.getVectorIndex(i).polyInverseNttToMont();
        }
    }

    /**
     * Compress and serialize vector of polynomials
     * @return byte[]: Compressed PolyVec Bytes
     */
    public byte[] compressPolyVec()
    {
        int i, j, k;
        // System.out.print("bp before sub q = [");
        // for (i = 0; i < kyberK; i++) {
        //     Helper.printShortArray(this.getVectorIndex(i).getCoeffs());
        //     System.out.print("], \n");
        // }
        // System.out.println("]"); 

        this.conditionalSubQ();

        // System.out.print("bp sub q = [");
        // for (i = 0; i < kyberK; i++) {
        //     Helper.printShortArray(this.getVectorIndex(i).getCoeffs());
        //     System.out.print("], \n");
        // }
        // System.out.println("]"); 
        short[] t;
        byte[] r = new byte[engine.getKyberPolyVecCompressedBytes()];
        int count = 0;
        if (engine.getKyberPolyVecCompressedBytes() == kyberK * 320)
        {
            t = new short[4];
            for (i = 0; i < kyberK; i++)
            {
                for (j = 0; j < KyberEngine.KyberN / 4; j++)
                {
                    for (k = 0; k < 4; k++)
                    {
                        t[k] = (short)
                            (
                                (
                                    ((this.getVectorIndex(i).getCoeffIndex(4 * j + k) << 10)
                                        + (KyberEngine.KyberQ / 2))
                                        / KyberEngine.KyberQ)
                                    & 0x3ff);
                    }
                    r[count + 0] = (byte)(t[0] >> 0);
                    r[count + 1] = (byte)((t[0] >> 8) | (t[1] << 2));
                    r[count + 2] = (byte)((t[1] >> 6) | (t[2] << 4));
                    r[count + 3] = (byte)((t[2] >> 4) | (t[3] << 6));
                    r[count + 4] = (byte)((t[3] >> 2));
                    count += 5;
                }
            }
        }
        else if (engine.getKyberPolyVecCompressedBytes() == kyberK * 352)
        {
            t = new short[8];
            for (i = 0; i < kyberK; i++)
            {
                for (j = 0; j < KyberEngine.KyberN / 8; j++)
                {
                    for (k = 0; k < 8; k++)
                    {
                        t[k] = (short)
                            (
                                (
                                    ((this.getVectorIndex(i).getCoeffIndex(8 * j + k) << 11)
                                        + (KyberEngine.KyberQ / 2))
                                        / KyberEngine.KyberQ)
                                    & 0x7ff);
                    }
                    r[count + 0] = (byte)((t[0] >> 0));
                    r[count + 1] = (byte)((t[0] >> 8) | (t[1] << 3));
                    r[count + 2] = (byte)((t[1] >> 5) | (t[2] << 6));
                    r[count + 3] = (byte)((t[2] >> 2));
                    r[count + 4] = (byte)((t[2] >> 10) | (t[3] << 1));
                    r[count + 5] = (byte)((t[3] >> 7) | (t[4] << 4));
                    r[count + 6] = (byte)((t[4] >> 4) | (t[5] << 7));
                    r[count + 7] = (byte)((t[5] >> 1));
                    r[count + 8] = (byte)((t[5] >> 9) | (t[6] << 2));
                    r[count + 9] = (byte)((t[6] >> 6) | (t[7] << 5));
                    r[count + 10] = (byte)((t[7] >> 3));
                    count += 11;
                }
            }
        }
        else
        {
            throw new RuntimeException("Kyber PolyVecCompressedBytes neither 320 * KyberK or 352 * KyberK!");
        }
        return r;
    }

    /**
     * De-serialize and decompress vector of polynomials;
     * approximate inverse of polyvec_compress
     * @param compressedPolyVecCipherText byte[]: Compressed PolyVec bytes
     */
    public void decompressPolyVec(byte[] compressedPolyVecCipherText)
    {
        int i, j, k, count = 0;

        if (engine.getKyberPolyVecCompressedBytes() == (kyberK * 320))
        {
            short[] t = new short[4];
            for (i = 0; i < kyberK; i++)
            {
                for (j = 0; j < KyberEngine.KyberN / 4; j++)
                {
                    t[0] = (short)(((compressedPolyVecCipherText[count] & 0xFF) >> 0) | (short)((compressedPolyVecCipherText[count + 1] & 0xFF) << 8));
                    t[1] = (short)(((compressedPolyVecCipherText[count + 1] & 0xFF) >> 2) | (short)((compressedPolyVecCipherText[count + 2] & 0xFF) << 6));
                    t[2] = (short)(((compressedPolyVecCipherText[count + 2] & 0xFF) >> 4) | (short)((compressedPolyVecCipherText[count + 3] & 0xFF) << 4));
                    t[3] = (short)(((compressedPolyVecCipherText[count + 3] & 0xFF) >> 6) | (short)((compressedPolyVecCipherText[count + 4] & 0xFF) << 2));
                    count += 5;
                    for (k = 0; k < 4; k++)
                    {
                        this.vec[i].setCoeffIndex(4 * j + k, (short)(((t[k] & 0x3FF) * KyberEngine.KyberQ + 512) >> 10));
                    }
                }

            }

        }
        else if (engine.getKyberPolyVecCompressedBytes() == (kyberK * 352))
        {
            short[] t = new short[8];
            for (i = 0; i < kyberK; i++)
            {
                for (j = 0; j < KyberEngine.KyberN / 8; j++)
                {
                    t[0] = (short)(((compressedPolyVecCipherText[count] & 0xFF) >> 0) | ((short)(compressedPolyVecCipherText[count + 1] & 0xFF) << 8));
                    t[1] = (short)(((compressedPolyVecCipherText[count + 1] & 0xFF) >> 3) | ((short)(compressedPolyVecCipherText[count + 2] & 0xFF) << 5));
                    t[2] = (short)(((compressedPolyVecCipherText[count + 2] & 0xFF) >> 6) | ((short)(compressedPolyVecCipherText[count + 3] & 0xFF) << 2) | ((short)((compressedPolyVecCipherText[count + 4] & 0xFF) << 10)));
                    t[3] = (short)(((compressedPolyVecCipherText[count + 4] & 0xFF) >> 1) | ((short)(compressedPolyVecCipherText[count + 5] & 0xFF) << 7));
                    t[4] = (short)(((compressedPolyVecCipherText[count + 5] & 0xFF) >> 4) | ((short)(compressedPolyVecCipherText[count + 6] & 0xFF) << 4));
                    t[5] = (short)(((compressedPolyVecCipherText[count + 6] & 0xFF) >> 7) | ((short)(compressedPolyVecCipherText[count + 7] & 0xFF) << 1) | ((short)((compressedPolyVecCipherText[count + 8] & 0xFF) << 9)));
                    t[6] = (short)(((compressedPolyVecCipherText[count + 8] & 0xFF) >> 2) | ((short)(compressedPolyVecCipherText[count + 9] & 0xFF) << 6));
                    t[7] = (short)(((compressedPolyVecCipherText[count + 9] & 0xFF) >> 5) | ((short)(compressedPolyVecCipherText[count + 10] & 0xFF) << 3));
                    count += 11;
                    for (k = 0; k < 8; k++)
                    {
                        this.vec[i].setCoeffIndex(8 * j + k, (short)(((t[k] & 0x7FF) * KyberEngine.KyberQ + 1024) >> 11));
                    }
                }
            }
        }
        else
        {
            throw new RuntimeException("Kyber PolyVecCompressedBytes neither 320 * KyberK or 352 * KyberK!");
        }
    }

    /**
     * Pointwise multiply elements of a and b, accumulate into output Polynomial,
     * and multiply by 2^-16.
     * @param out Poly: Output Polynomial
     * @param inp1 Poly: First input Polynomial
     * @param inp2 Poly: Second input Polynomial
     * @param engine KyberEngine: Kyber Engine holding all constant variables
     */
    public static void pointwiseAccountMontgomery(Poly out, PolyVec inp1, PolyVec inp2, KyberEngine engine)
    {
        int i;
        Poly t = new Poly(engine);

        Poly.baseMultMontgomery(out, inp1.getVectorIndex(0), inp2.getVectorIndex(0));
        for (i = 1; i < engine.getKyberK(); i++)
        {
            Poly.baseMultMontgomery(t, inp1.getVectorIndex(i), inp2.getVectorIndex(i));
            out.addCoeffs(t);
        }
        out.reduce();
    }

    /**
     * Applies Barrett reduction to each coefficient
     * of each element of a vector of polynomials
     * Further details of Barrett Reduction in Reduce.java
     */
    public void reducePoly()
    {
        int i;
        for (i = 0; i < kyberK; i++)
        {
            this.getVectorIndex(i).reduce();
            ;
        }
    }

    /**
     * Add vectors of polynomials
     * @param b PolyVec: Input PolyVec to Add
     */
    public void addPoly(PolyVec b)
    {
        int i;
        for (i = 0; i < kyberK; i++)
        {
            this.getVectorIndex(i).addCoeffs(b.getVectorIndex(i));
        }
    }

    /**
     * Serialize vector of polynomials
     * @return byte[]: PolyVec Converted to Bytes
     */
    public byte[] toBytes()
    {
        byte[] r = new byte[polyVecBytes];
        for (int i = 0; i < kyberK; i++)
        {
            System.arraycopy(this.vec[i].toBytes(), 0, r, i * KyberEngine.KyberPolyBytes, KyberEngine.KyberPolyBytes);
        }

        return r;
    }

    /**
     * De-serialize vector of polynomials;
     * inverse of PolyVec toBytes
     * @param inputBytes byte[]: Bytes which require conversion to PolyVec
     */
    public void fromBytes(byte[] inputBytes)
    {
        for (int i = 0; i < kyberK; i++)
        {
            this.getVectorIndex(i).fromBytes(Arrays.copyOfRange(inputBytes, i * KyberEngine.KyberPolyBytes, (i + 1) * KyberEngine.KyberPolyBytes));
        }
    }

    /**
     * Applies conditional subtraction of q to each coefficient
     * of each element of a vector of polynomials
     * Further details of Conditional Subtraction of Q in Reduce.java
     */
    public void conditionalSubQ()
    {
        for (int i = 0; i < kyberK; i++)
        {
            this.getVectorIndex(i).conditionalSubQ();
        }
    }

    /**
     * Convert PolyVec to String
     * @return String: String format of an Array of Poly.
     */
    public String toString()
    {
        String[] out = new String[engine.getKyberK()];
        for (int i = 0; i < kyberK; i++)
        {
            out[i] = vec[i].toString();
        }
        return Arrays.toString(out);
    }
}