package crypto.pqc.dilithium;

import java.util.Arrays;

import org.bouncycastle.crypto.digests.SHAKEDigest;

class Poly
{
    private int polyUniformNBlocks = (768 + Symmetric.Shake128Rate - 1) / Symmetric.Shake128Rate;
    private int[] coeffs;
    private DilithiumEngine engine;
    private int dilithiumN;


    public Poly(DilithiumEngine engine)
    {
        this.dilithiumN = DilithiumEngine.DilithiumN;
        this.coeffs = new int[dilithiumN];
        this.engine = engine;
    }

    public int getCoeffIndex(int i)
    {
        return this.coeffs[i];
    }

    public int[] getCoeffs()
    {
        return this.coeffs;
    }

    public void setCoeffIndex(int i, int val)
    {
        this.coeffs[i] = val;
    }

    public void setCoeffs(int[] coeffs)
    {
        this.coeffs = coeffs;
    }

    /**
     * Sample polynomial with uniformly random coefficients
     * in [0,Q-1] by performing rejection sampling on the
     * output stream of SHAKE256(seed|nonce) or AES256CTR(seed,nonce).
     * @param seed byte[]: Byte Array of Seed
     * @param nonce 2-byte nonce
     */
    public void uniformBlocks(byte[] seed, short nonce)
    {
        int i, ctr, off,
            buflen = polyUniformNBlocks * Symmetric.Shake128Rate;
        byte[] buf = new byte[buflen + 2];

        SHAKEDigest shake128Digest = new SHAKEDigest(128);

        Symmetric.shakeStreamInit(shake128Digest, seed, nonce);

        shake128Digest.doOutput(buf, 0, buflen + 2);

        // System.out.println("buf = ");
        // Helper.printByteArray(buf);

        // problems with last 2 bytes in buf

        ctr = rejectUniform(this, 0, dilithiumN, buf, buflen);

        // ctr can be less than N

        while (ctr < dilithiumN)
        {
            off = buflen % 3;
            for (i = 0; i < off; ++i)
            {
                buf[i] = buf[buflen - off + i];
            }
            shake128Digest.doOutput(buf, buflen + off, 1);
            buflen = Symmetric.Shake128Rate + off;
            ctr += rejectUniform(this, ctr, dilithiumN, buf, buflen);
        }

    }

    /**
     * Sample uniformly random coefficients in [0, Q-1] by
     * performing rejection sampling on array of random bytes.
     * @param outputPoly Poly: Output Poly
     * @param coeffOff
     * @param len
     * @param inpBuf
     * @param buflen
     * @return
     */
    private static int rejectUniform(Poly outputPoly, int coeffOff, int len, byte[] inpBuf, int buflen)
    {
        int ctr, pos;
        int t;


        ctr = pos = 0;
        while (ctr < len && pos + 3 <= buflen)
        {
            t = (inpBuf[pos++] & 0xFF);
            t |= (inpBuf[pos++] & 0xFF) << 8;
            t |= (inpBuf[pos++] & 0xFF) << 16;
            t &= 0x7FFFFF;

            if (t < DilithiumEngine.DilithiumQ)
            {
                outputPoly.setCoeffIndex(coeffOff + ctr, t);
                ctr++;
            }
        }

        return ctr;

    }

    /**
     * Sample polynomial with uniformly random coefficients
     * in [-ETA,ETA] by performing rejection sampling on the
     * output stream from SHAKE256(seed|nonce)
     * @param seed
     * @param nonce
     */
    public void uniformEta(byte[] seed, short nonce)
    {
        int ctr, polyUniformEtaNBlocks, eta = engine.getDilithiumEta();


        if (engine.getDilithiumEta() == 2)
        {
            polyUniformEtaNBlocks = ((136 + Symmetric.Shake128Rate - 1) / Symmetric.Shake256Rate);
        }
        else if (engine.getDilithiumEta() == 4)
        {
            polyUniformEtaNBlocks = ((227 + Symmetric.Shake128Rate - 1) / Symmetric.Shake256Rate);
        }
        else
        {
            throw new RuntimeException("Wrong Dilithium Eta!");
        }

        int buflen = polyUniformEtaNBlocks * Symmetric.Shake128Rate;

        byte[] buf = new byte[buflen];
        SHAKEDigest shake256Digest = new SHAKEDigest(256);

        Symmetric.shakeStreamInit(shake256Digest, seed, nonce);
        shake256Digest.doOutput(buf, 0, buflen);

        // System.out.println("poly eta buf = ");
        // Helper.printByteArray(buf);

        ctr = rejectEta(this, 0, dilithiumN, buf, buflen, eta);
        // System.out.printf("ctr %d\n", ctr);

        while (ctr < DilithiumEngine.DilithiumN)
        {
            shake256Digest.doOutput(buf, buflen, Symmetric.Shake128Rate);
            ctr += rejectEta(this, ctr, dilithiumN - ctr, buf, Symmetric.Shake128Rate, eta);
        }

    }

    /**
     * Sample uniformly random coefficients in [-ETA, ETA] by
     * performing rejection sampling on array of random bytes.
     * @param outputPoly
     * @param coeffOff
     * @param len
     * @param buf
     * @param buflen
     * @param eta
     * @return
     */
    private static int rejectEta(Poly outputPoly, int coeffOff, int len, byte[] buf, int buflen, int eta)
    {
        int ctr, pos;
        int t0, t1;

        ctr = pos = 0;

        while (ctr < len && pos < buflen)
        {
            t0 = (buf[pos] & 0xFF) & 0x0F;
            t1 = (buf[pos++] & 0xFF) >> 4;
            if (eta == 2)
            {
                if (t0 < 15)
                {
                    t0 = t0 - (205 * t0 >> 10) * 5;
                    outputPoly.setCoeffIndex(coeffOff + ctr, 2 - t0);
                    ctr++;
                }
                if (t1 < 15 && ctr < len)
                {
                    t1 = t1 - (205 * t1 >> 10) * 5;
                    outputPoly.setCoeffIndex(coeffOff + ctr, 2 - t1);
                    ctr++;
                }
            }
            else if (eta == 4)
            {
                if (t0 < 9)
                {
                    outputPoly.setCoeffIndex(coeffOff + ctr, 4 - t0);
                    ctr++;
                }
                if (t1 < 9 && ctr < len)
                {
                    outputPoly.setCoeffIndex(coeffOff + ctr, 4 - t1);
                    ctr++;
                }
                // System.out.printf("ctr %d coeff %d\n", ctr, outputPoly.getCoeffIndex(ctr - 1));
            }
        }
        return ctr;
    }

    /**
     * Inplace forward NTT. Coefficients can grow by
     * 8*Q in absolute value.
     */
    public void polyNtt()
    {
        this.setCoeffs(Ntt.ntt(this.coeffs));
    }

    /**
     * Pointwise multiplication of polynomials in NTT domain
     * representation and multiplication of resulting polynomial
     * by 2^{-32}
     * @param v Poly: First input Polynomial
     * @param w Poly: Second input Polynomial
     */
    public void pointwiseMontgomery(Poly v, Poly w)
    {
        int i;
        for (i = 0; i < dilithiumN; ++i)
        {
            this.setCoeffIndex(i, Reduce.montgomeryReduce((long)((long)v.getCoeffIndex(i) * (long)w.getCoeffIndex(i))));
        }
    }

    public void pointwiseAccountMontgomery(PolyVecL u, PolyVecL v)
    {
        int i;
        Poly t = new Poly(engine);

        this.pointwiseMontgomery(u.getVectorIndex(0), v.getVectorIndex(0));


        for (i = 1; i < engine.getDilithiumL(); ++i)
        {
            t.pointwiseMontgomery(u.getVectorIndex(i), v.getVectorIndex(i));
            this.addPoly(t);
        }
        // System.out.println("temp = ");
        // System.out.println(this.toString());

    }

    /**
     * Add poly a to current polynomial. No modular reduction is performed.
     * @param a Poly: Polynomial to add
     */
    public void addPoly(Poly a)
    {
        int i;
        for (i = 0; i < dilithiumN; i++)
        {
            this.setCoeffIndex(i, this.getCoeffIndex(i) + a.getCoeffIndex(i));
        }
    }


    /**
     * Inplace reduction of all coefficients of polynomial to
     * representative in [-6283009,6283007]
     */
    public void reduce()
    {
        for (int i = 0; i < dilithiumN; ++i)
        {
            this.setCoeffIndex(i, Reduce.reduce32(this.getCoeffIndex(i)));
        }
    }

    /**
     * Inplace inverse NTT and multiplication by 2^{32}.
     * Input coefficients need to be less than Q in absolute
     * value and output coefficients are again bounded by Q.
     */
    public void invNttToMont()
    {
        this.setCoeffs(Ntt.invNttToMont(this.getCoeffs()));
    }

    /**
     * For all coefficients of in/out polynomial add Q if
     * coefficient is negative
     */
    public void conditionalAddQ()
    {
        for (int i = 0; i < dilithiumN; ++i)
        {
            this.setCoeffIndex(i, Reduce.conditionalAddQ(this.getCoeffIndex(i)));
        }
    }

    /**
     * For all coefficients c of the input polynomial,
     * compute this[0], a[1] such that c mod Q = c1*2^D + c0
     * with -2^{D-1} < c0 <= 2^{D-1}. Assumes coefficients to be
     * standard representatives.
     * @param a Poly: Pointer to input
     */
    public void power2Round(Poly a)
    {
        for (int i = 0; i < dilithiumN; ++i)
        {
            int[] p2r = Rounding.power2Round(this.getCoeffIndex(i));
            this.setCoeffIndex(i, p2r[0]);
            a.setCoeffIndex(i, p2r[1]);
        }
    }

    /**
     * Bit-pack polynomial t1 with coefficients fitting in 10 bits.
     * Input coefficients are assumed to be standard representatives.
     * @return
     */
    public byte[] polyt1Pack()
    {
        byte[] out = new byte[DilithiumEngine.DilithiumPolyT1PackedBytes];

        for (int i = 0; i < dilithiumN / 4; ++i)
        {
            out[5 * i + 0] = (byte)(this.coeffs[4 * i + 0] >> 0);
            out[5 * i + 1] = (byte)((this.coeffs[4 * i + 0] >> 8) | (this.coeffs[4 * i + 1] << 2));
            out[5 * i + 2] = (byte)((this.coeffs[4 * i + 1] >> 6) | (this.coeffs[4 * i + 2] << 4));
            out[5 * i + 3] = (byte)((this.coeffs[4 * i + 2] >> 4) | (this.coeffs[4 * i + 3] << 6));
            out[5 * i + 4] = (byte)(this.coeffs[4 * i + 3] >> 2);
        }
        return out;
    }

    /**
     * Unpack polynomial t1 with 10-bit coefficients.
     * Output coefficients are standard representatives.
     * @param a
     */
    public void polyt1Unpack(byte[] a)
    {
        int i;

        for (i = 0; i < dilithiumN / 4; ++i)
        {
            this.setCoeffIndex(4 * i + 0, (((a[5 * i + 0] & 0xFF) >> 0) | ((int)(a[5 * i + 1] & 0xFF) << 8)) & 0x3FF);
            this.setCoeffIndex(4 * i + 1, (((a[5 * i + 1] & 0xFF) >> 2) | ((int)(a[5 * i + 2] & 0xFF) << 6)) & 0x3FF);
            this.setCoeffIndex(4 * i + 2, (((a[5 * i + 2] & 0xFF) >> 4) | ((int)(a[5 * i + 3] & 0xFF) << 4)) & 0x3FF);
            this.setCoeffIndex(4 * i + 3, (((a[5 * i + 3] & 0xFF) >> 6) | ((int)(a[5 * i + 4] & 0xFF) << 2)) & 0x3FF);
        }
    }

    /**
     * Bit-pack polynomial with coefficients in [-ETA,ETA].
     * @return 
     */
    public byte[] polyEtaPack()
    {
        int i;
        byte[] t = new byte[8];
        byte[] out = new byte[engine.getDilithiumPolyEtaPackedBytes()];

        if (engine.getDilithiumEta() == 2)
        {
            for (i = 0; i < dilithiumN / 8; ++i)
            {
                t[0] = (byte)(engine.getDilithiumEta() - this.getCoeffIndex(8 * i + 0));
                t[1] = (byte)(engine.getDilithiumEta() - this.getCoeffIndex(8 * i + 1));
                t[2] = (byte)(engine.getDilithiumEta() - this.getCoeffIndex(8 * i + 2));
                t[3] = (byte)(engine.getDilithiumEta() - this.getCoeffIndex(8 * i + 3));
                t[4] = (byte)(engine.getDilithiumEta() - this.getCoeffIndex(8 * i + 4));
                t[5] = (byte)(engine.getDilithiumEta() - this.getCoeffIndex(8 * i + 5));
                t[6] = (byte)(engine.getDilithiumEta() - this.getCoeffIndex(8 * i + 6));
                t[7] = (byte)(engine.getDilithiumEta() - this.getCoeffIndex(8 * i + 7));

                out[3 * i + 0] = (byte)((t[0] >> 0) | (t[1] << 3) | (t[2] << 6));
                out[3 * i + 1] = (byte)((t[2] >> 2) | (t[3] << 1) | (t[4] << 4) | (t[5] << 7));
                out[3 * i + 2] = (byte)((t[5] >> 1) | (t[6] << 2) | (t[7] << 5));
            }
        }
        else if (engine.getDilithiumEta() == 4)
        {
            for (i = 0; i < dilithiumN / 2; ++i)
            {
                t[0] = (byte)(engine.getDilithiumEta() - this.getCoeffIndex(2 * i + 0));
                t[1] = (byte)(engine.getDilithiumEta() - this.getCoeffIndex(2 * i + 1));
                out[i] = (byte)(t[0] | t[1] << 4);
            }
        }
        else
        {
            throw new RuntimeException("Eta needs to be 2 or 4!");
        }
        return out;
    }

    /**
     * Unpack polynomial with coefficients in [-ETA,ETA].
     * @param a
     * @param off
     */
    public void polyEtaUnpack(byte[] a, int off)
    {
        int i, eta = engine.getDilithiumEta();

        if (engine.getDilithiumEta() == 2)
        {
            for (i = 0; i < dilithiumN / 8; ++i)
            {
                this.setCoeffIndex(8 * i + 0, (((a[off + (3 * i + 0)] & 0xFF) >> 0)) & 7);
                this.setCoeffIndex(8 * i + 1, (((a[off + (3 * i + 0)] & 0xFF) >> 3)) & 7);
                this.setCoeffIndex(8 * i + 2, ((a[off + (3 * i + 0)] & 0xFF) >> 6) | ((a[off + (3 * i + 1)] & 0xFF) << 2) & 7);
                this.setCoeffIndex(8 * i + 3, (((a[off + (3 * i + 1)] & 0xFF) >> 1)) & 7);
                this.setCoeffIndex(8 * i + 4, (((a[off + (3 * i + 1)] & 0xFF) >> 4)) & 7);
                this.setCoeffIndex(8 * i + 5, ((a[off + (3 * i + 1)] & 0xFF) >> 7) | ((a[off + (3 * i + 2)] & 0xFF) << 1) & 7);
                this.setCoeffIndex(8 * i + 6, (((a[off + (3 * i + 2)] & 0xFF) >> 2)) & 7);
                this.setCoeffIndex(8 * i + 7, (((a[off + (3 * i + 2)] & 0xFF) >> 5)) & 7);

                this.setCoeffIndex(8 * i + 0, eta - this.getCoeffIndex(8 * i + 0));
                this.setCoeffIndex(8 * i + 1, eta - this.getCoeffIndex(8 * i + 1));
                this.setCoeffIndex(8 * i + 2, eta - this.getCoeffIndex(8 * i + 2));
                this.setCoeffIndex(8 * i + 3, eta - this.getCoeffIndex(8 * i + 3));
                this.setCoeffIndex(8 * i + 4, eta - this.getCoeffIndex(8 * i + 4));
                this.setCoeffIndex(8 * i + 5, eta - this.getCoeffIndex(8 * i + 5));
                this.setCoeffIndex(8 * i + 6, eta - this.getCoeffIndex(8 * i + 6));
                this.setCoeffIndex(8 * i + 7, eta - this.getCoeffIndex(8 * i + 7));
            }
        }
        else if (engine.getDilithiumEta() == 4)
        {
            for (i = 0; i < dilithiumN / 2; ++i)
            {
                this.setCoeffIndex(2 * i + 0, (a[off + i] & 0xFF) & 0x0F);
                this.setCoeffIndex(2 * i + 1, (a[off + i] & 0xFF) >> 4);
                this.setCoeffIndex(2 * i + 0, eta - this.getCoeffIndex(2 * i + 0));
                this.setCoeffIndex(2 * i + 1, eta - this.getCoeffIndex(2 * i + 1));
            }
        }
    }

    /**
     * Bit-pack polynomial t0 with coefficients in ]-2^{D-1}, 2^{D-1}].
     */
    public byte[] polyt0Pack()
    {
        int i;
        int[] t = new int[8];
        byte[] out = new byte[DilithiumEngine.DilithiumPolyT0PackedBytes];

        for (i = 0; i < dilithiumN / 8; ++i)
        {
            t[0] = (1 << (DilithiumEngine.DilithiumD - 1)) - this.getCoeffIndex(8 * i + 0);
            t[1] = (1 << (DilithiumEngine.DilithiumD - 1)) - this.getCoeffIndex(8 * i + 1);
            t[2] = (1 << (DilithiumEngine.DilithiumD - 1)) - this.getCoeffIndex(8 * i + 2);
            t[3] = (1 << (DilithiumEngine.DilithiumD - 1)) - this.getCoeffIndex(8 * i + 3);
            t[4] = (1 << (DilithiumEngine.DilithiumD - 1)) - this.getCoeffIndex(8 * i + 4);
            t[5] = (1 << (DilithiumEngine.DilithiumD - 1)) - this.getCoeffIndex(8 * i + 5);
            t[6] = (1 << (DilithiumEngine.DilithiumD - 1)) - this.getCoeffIndex(8 * i + 6);
            t[7] = (1 << (DilithiumEngine.DilithiumD - 1)) - this.getCoeffIndex(8 * i + 7);

            out[13 * i + 0] = (byte)(t[0]);
            out[13 * i + 1] = (byte)(t[0] >> 8);
            out[13 * i + 1] = (byte)(out[13 * i + 1] | (byte)(t[1] << 5));
            out[13 * i + 2] = (byte)(t[1] >> 3);
            out[13 * i + 3] = (byte)(t[1] >> 11);
            out[13 * i + 3] = (byte)(out[13 * i + 3] | (byte)(t[2] << 2));
            out[13 * i + 4] = (byte)(t[2] >> 6);
            out[13 * i + 4] = (byte)(out[13 * i + 4] | (byte)(t[3] << 7));
            out[13 * i + 5] = (byte)(t[3] >> 1);
            out[13 * i + 6] = (byte)(t[3] >> 9);
            out[13 * i + 6] = (byte)(out[13 * i + 6] | (byte)(t[4] << 4));
            out[13 * i + 7] = (byte)(t[4] >> 4);
            out[13 * i + 8] = (byte)(t[4] >> 12);
            out[13 * i + 8] = (byte)(out[13 * i + 8] | (byte)(t[5] << 1));
            out[13 * i + 9] = (byte)(t[5] >> 7);
            out[13 * i + 9] = (byte)(out[13 * i + 9] | (byte)(t[6] << 6));
            out[13 * i + 10] = (byte)(t[6] >> 2);
            out[13 * i + 11] = (byte)(t[6] >> 10);
            out[13 * i + 11] = (byte)(out[13 * i + 11] | (byte)(t[7] << 3));
            out[13 * i + 12] = (byte)(t[7] >> 5);
        }
        return out;
    }

    /**
     * Unpack polynomial t0 with coefficients in ]-2^{D-1}, 2^{D-1}].
     * @param a
     * @param off
     */
    public void polyt0Unpack(byte[] a, int off)
    {
        int i;
        for (i = 0; i < dilithiumN / 8; ++i)
        {
            this.setCoeffIndex(8 * i + 0,
                (
                    (a[off + (13 * i + 0)] & 0xFF) |
                        ((a[off + (13 * i + 1)] & 0xFF) << 8)
                ) & 0x1FFF);
            this.setCoeffIndex(8 * i + 1,
                (
                    (((a[off + (13 * i + 1)] & 0xFF) >> 5) |
                        ((a[off + (13 * i + 2)] & 0xFF) << 3)) |
                        ((a[off + (13 * i + 3)] & 0xFF) << 11)
                ) & 0x1FFF);

            this.setCoeffIndex(8 * i + 2,
                (
                    (((a[off + (13 * i + 3)] & 0xFF) >> 2) |
                        ((a[off + (13 * i + 4)] & 0xFF) << 6))
                ) & 0x1FFF);

            this.setCoeffIndex(8 * i + 3,
                (
                    (((a[off + (13 * i + 4)] & 0xFF) >> 7) |
                        ((a[off + (13 * i + 5)] & 0xFF) << 1)) |
                        ((a[off + (13 * i + 6)] & 0xFF) << 9)
                ) & 0x1FFF);

            this.setCoeffIndex(8 * i + 4,
                (
                    (((a[off + (13 * i + 6)] & 0xFF) >> 4) |
                        ((a[off + (13 * i + 7)] & 0xFF) << 4)) |
                        ((a[off + (13 * i + 8)] & 0xFF) << 12)
                ) & 0x1FFF);

            this.setCoeffIndex(8 * i + 5,
                (
                    (((a[off + (13 * i + 8)] & 0xFF) >> 1) |
                        ((a[off + (13 * i + 9)] & 0xFF) << 7))
                ) & 0x1FFF);

            this.setCoeffIndex(8 * i + 6,
                (
                    (((a[off + (13 * i + 9)] & 0xFF) >> 6) |
                        ((a[off + (13 * i + 10)] & 0xFF) << 2)) |
                        ((a[off + (13 * i + 11)] & 0xFF) << 10)
                ) & 0x1FFF);

            this.setCoeffIndex(8 * i + 7,
                (
                    ((a[off + (13 * i + 11)] & 0xFF) >> 3 |
                        ((a[off + (13 * i + 12)] & 0xFF) << 5))
                ) & 0x1FFF);


            this.setCoeffIndex(8 * i + 0, ((1 << (DilithiumEngine.DilithiumD - 1)) - this.getCoeffIndex(8 * i + 0)));
            this.setCoeffIndex(8 * i + 1, ((1 << (DilithiumEngine.DilithiumD - 1)) - this.getCoeffIndex(8 * i + 1)));
            this.setCoeffIndex(8 * i + 2, ((1 << (DilithiumEngine.DilithiumD - 1)) - this.getCoeffIndex(8 * i + 2)));
            this.setCoeffIndex(8 * i + 3, ((1 << (DilithiumEngine.DilithiumD - 1)) - this.getCoeffIndex(8 * i + 3)));
            this.setCoeffIndex(8 * i + 4, ((1 << (DilithiumEngine.DilithiumD - 1)) - this.getCoeffIndex(8 * i + 4)));
            this.setCoeffIndex(8 * i + 5, ((1 << (DilithiumEngine.DilithiumD - 1)) - this.getCoeffIndex(8 * i + 5)));
            this.setCoeffIndex(8 * i + 6, ((1 << (DilithiumEngine.DilithiumD - 1)) - this.getCoeffIndex(8 * i + 6)));
            this.setCoeffIndex(8 * i + 7, ((1 << (DilithiumEngine.DilithiumD - 1)) - this.getCoeffIndex(8 * i + 7)));
        }
    }


    /**
     * Sample polynomial with uniformly random coefficients
     * in [-(GAMMA1 - 1), GAMMA1] by unpacking output stream
     * of SHAKE256(seed|nonce) or AES256CTR(seed,nonce).
     * @param seed
     * @param nonce
     */
    public void uniformGamma1(byte[] seed, short nonce)
    {
        byte[] buf = new byte[engine.getPolyUniformGamma1NBlocks() * Symmetric.Shake256Rate];

        SHAKEDigest shakeDigest = new SHAKEDigest(256);

        Symmetric.shakeStreamInit(shakeDigest, seed, nonce);
        shakeDigest.doFinal(buf, 0, engine.getPolyUniformGamma1NBlocks() * Symmetric.Shake256Rate);
        // System.out.println("Uniform gamma 1 buf = ");
        // Helper.printByteArray(buf);
        this.unpackZ(buf);
    }

    private void unpackZ(byte[] a)
    {
        int i;
        if (engine.getDilithiumGamma1() == (1 << 17))
        {
            for (i = 0; i < dilithiumN / 4; ++i)
            {
                this.setCoeffIndex(4 * i + 0,
                    (
                        (((a[9 * i + 0] & 0xFF)) |
                            ((a[9 * i + 1] & 0xFF) << 8)) |
                            ((a[9 * i + 2] & 0xFF) << 16)
                    ) & 0x3FFFF);
                this.setCoeffIndex(4 * i + 1,
                    (
                        (((a[9 * i + 2] & 0xFF) >> 2) |
                            ((a[9 * i + 3] & 0xFF) << 6)) |
                            ((a[9 * i + 4] & 0xFF) << 14)
                    ) & 0x3FFFF);
                this.setCoeffIndex(4 * i + 2,
                    (
                        (((a[9 * i + 4] & 0xFF) >> 4) |
                            ((a[9 * i + 5] & 0xFF) << 4)) |
                            ((a[9 * i + 6] & 0xFF) << 12)
                    ) & 0x3FFFF);
                this.setCoeffIndex(4 * i + 3,
                    (
                        (((a[9 * i + 6] & 0xFF) >> 6) |
                            ((a[9 * i + 7] & 0xFF) << 2)) |
                            ((a[9 * i + 8] & 0xFF) << 10)
                    ) & 0x3FFFF);


                this.setCoeffIndex(4 * i + 0, engine.getDilithiumGamma1() - this.getCoeffIndex(4 * i + 0));
                this.setCoeffIndex(4 * i + 1, engine.getDilithiumGamma1() - this.getCoeffIndex(4 * i + 1));
                this.setCoeffIndex(4 * i + 2, engine.getDilithiumGamma1() - this.getCoeffIndex(4 * i + 2));
                this.setCoeffIndex(4 * i + 3, engine.getDilithiumGamma1() - this.getCoeffIndex(4 * i + 3));
            }
        }
        else if (engine.getDilithiumGamma1() == (1 << 19))
        {
            for (i = 0; i < dilithiumN / 2; ++i)
            {
                this.setCoeffIndex(2 * i + 0,
                    (
                        (((a[5 * i + 0] & 0xFF)) |
                            ((a[5 * i + 1] & 0xFF) << 8)) |
                            ((a[5 * i + 2] & 0xFF) << 16)
                    ) & 0xFFFFF);
                this.setCoeffIndex(2 * i + 1,
                    (
                        (((a[5 * i + 2] & 0xFF) >> 4) |
                            ((a[5 * i + 3] & 0xFF) << 4)) |
                            ((a[5 * i + 4] & 0xFF) << 12)
                    ) & 0xFFFFF);

                this.setCoeffIndex(2 * i + 0, engine.getDilithiumGamma1() - this.getCoeffIndex(2 * i + 0));
                this.setCoeffIndex(2 * i + 1, engine.getDilithiumGamma1() - this.getCoeffIndex(2 * i + 1));
            }
        }
        else
        {
            throw new RuntimeException("Wrong Dilithiumn Gamma1!");
        }
    }

    /**
     * For all coefficients c of the input polynomial,
     * compute high and low bits c0, c1 such c mod Q = c1*ALPHA + c0
     * with -ALPHA/2 < c0 <= ALPHA/2 except c1 = (Q-1)/ALPHA where we
     * set c1 = 0 and -ALPHA/2 <= c0 = c mod Q - Q < 0.
     * Assumes coefficients to be standard representatives.
     * @param this Poly: First Output Polynomial
     * @param a Poly: Second Output Polynomial
     * @param this Poly: Input Polynomial
     */
    public void decompose(Poly a)
    {
        int i;
        for (i = 0; i < dilithiumN; ++i)
        {
            int[] decomp = Rounding.decompose(this.getCoeffIndex(i), engine.getDilithiumGamma2());
            // System.out.println(decomp[0] + ", "+decomp[1]);
            this.setCoeffIndex(i, decomp[1]);
            a.setCoeffIndex(i, decomp[0]);
        }
    }

    /**
     * Bit-pack polynomial w1 with coefficients in [0,15] or [0,43].
     * Input coefficients are assumed to be standard representatives.
     * @return
     */
    public byte[] w1Pack()
    {
        int i;

        byte[] out = new byte[engine.getDilithiumPolyW1PackedBytes()];

        if (engine.getDilithiumGamma2() == (DilithiumEngine.DilithiumQ - 1) / 88)
        {
            for (i = 0; i < dilithiumN / 4; ++i)
            {
                out[3 * i + 0] = (byte)(((byte)this.getCoeffIndex(4 * i + 0)) | (this.getCoeffIndex(4 * i + 1) << 6));
                out[3 * i + 1] = (byte)((byte)(this.getCoeffIndex(4 * i + 1) >> 2) | (this.getCoeffIndex(4 * i + 2) << 4));
                out[3 * i + 2] = (byte)((byte)(this.getCoeffIndex(4 * i + 2) >> 4) | (this.getCoeffIndex(4 * i + 3) << 2));
            }
        }
        else if (engine.getDilithiumGamma2() == (DilithiumEngine.DilithiumQ - 1) / 32)
        {
            for (i = 0; i < dilithiumN / 2; ++i)
            {
                out[i] = (byte)(this.getCoeffIndex(2 * i + 0) | (this.getCoeffIndex(2 * i + 1) << 4));
            }
        }

        return out;
    }

    /**
     * Implementation of H. Samples polynomial with TAU nonzero
     * coefficients in {-1,1} using the output stream of
     * SHAKE256(seed)
     * @param seed
     */
    public void challenge(byte[] seed)
    {
        int i, b = 0, pos;
        long signs;
        byte[] buf = new byte[Symmetric.Shake256Rate];

        SHAKEDigest shake256Digest = new SHAKEDigest(256);
        shake256Digest.update(seed, 0, DilithiumEngine.SeedBytes);
        shake256Digest.doOutput(buf, 0, Symmetric.Shake256Rate);

        signs = (long)0;
        for (i = 0; i < 8; ++i)
        {
            signs |= (long)(buf[i] & 0xFF) << 8 * i;
        }

        pos = 8;

        for (i = 0; i < dilithiumN; ++i)
        {
            this.setCoeffIndex(i, 0);
        }
        for (i = dilithiumN - engine.getDilithiumTau(); i < dilithiumN; ++i)
        {
            do
            {
                if (pos >= Symmetric.Shake256Rate)
                {
                    shake256Digest.doOutput(buf, 0, Symmetric.Shake256Rate);
                    pos = 0;
                }
                b = (buf[pos++] & 0xFF);
            }
            while (b > i);

            this.setCoeffIndex(i, this.getCoeffIndex(b));
            this.setCoeffIndex(b, (int)(1 - 2 * (signs & 1)));
            signs = (long)(signs >> 1);
        }
    }

    /**
     * Check infinity norm of polynomial against given bound.
     * Assumes input coefficients were reduced by reduce32().
     * @param B integer: norm bound
     * @return True if norm is strictly smaller than B <= (Q-1)/8 and False otherwise.
     */
    public boolean checkNorm(int B)
    {
        int i, t;

        if (B > (DilithiumEngine.DilithiumQ - 1) / 8)
        {
            return true;
        }

        for (i = 0; i < dilithiumN; ++i)
        {
            t = this.getCoeffIndex(i) >> 31;
            t = this.getCoeffIndex(i) - (t & 2 * this.getCoeffIndex(i));

            if (t >= B)
            {
                return true;
            }
        }
        return false;
    }

    /**
     * Subtract Polynomial. No modular reduction is performed.
     * @param inpPoly Poly: Current Poly - inpPoly
     */
    public void subtract(Poly inpPoly)
    {
        for (int i = 0; i < dilithiumN; ++i)
        {
            this.setCoeffIndex(i, this.getCoeffIndex(i) - inpPoly.getCoeffIndex(i));
        }
    }

    /**
     * Compute hint polynomial. The coefficients of which indicate
     * whether the low bits of the corresponding coefficient of
     * the input polynomial overflow into the high bits.
     * @param a0 Poly: Lower part of input Polynomial
     * @param a1 Poly: Higher part of input Polynomial
     * @return Int: Number of 1 bits
     */
    public int polyMakeHint(Poly a0, Poly a1)
    {
        int i, s = 0;

        for (i = 0; i < dilithiumN; ++i)
        {
            this.setCoeffIndex(i, Rounding.makeHint(a0.getCoeffIndex(i), a1.getCoeffIndex(i), engine));
            s += this.getCoeffIndex(i);
        }
        return s;
    }

    /**
     * Use hint polynomial to correct the high bits of a polynomial.
     * @param a Poly: Input Polynomial
     * @param h Poly: Input Hint Polynomial
     * @return Poly: This Polynomial with corrected high bits
     */
    public void polyUseHint(Poly a, Poly h)
    {
        for (int i = 0; i < dilithiumN; ++i)
        {
            this.setCoeffIndex(i, Rounding.useHint(a.getCoeffIndex(i), h.getCoeffIndex(i), engine.getDilithiumGamma2()));
        }
    }

    /**
     * Bit-pack polynomial with coefficients
     * in [-(GAMMA1 - 1), GAMMA1].
     * @return
     */
    public byte[] zPack()
    {
        byte[] outBytes = new byte[engine.getDilithiumPolyZPackedBytes()];
        int i;
        int[] t = new int[4];
        if (engine.getDilithiumGamma1() == (1 << 17))
        {
            for (i = 0; i < dilithiumN / 4; ++i)
            {
                t[0] = engine.getDilithiumGamma1() - this.getCoeffIndex(4 * i + 0);
                t[1] = engine.getDilithiumGamma1() - this.getCoeffIndex(4 * i + 1);
                t[2] = engine.getDilithiumGamma1() - this.getCoeffIndex(4 * i + 2);
                t[3] = engine.getDilithiumGamma1() - this.getCoeffIndex(4 * i + 3);

                outBytes[9 * i + 0] = (byte)t[0];
                outBytes[9 * i + 1] = (byte)(t[0] >> 8);
                outBytes[9 * i + 2] = (byte)((byte)(t[0] >> 16) | (t[1] << 2));
                outBytes[9 * i + 3] = (byte)(t[1] >> 6);
                outBytes[9 * i + 4] = (byte)((byte)(t[1] >> 14) | (t[2] << 4));
                outBytes[9 * i + 5] = (byte)(t[2] >> 4);
                outBytes[9 * i + 6] = (byte)((byte)(t[2] >> 12) | (t[3] << 6));
                outBytes[9 * i + 7] = (byte)(t[3] >> 2);
                outBytes[9 * i + 8] = (byte)(t[3] >> 10);
            }
        }
        else if (engine.getDilithiumGamma1() == (1 << 19))
        {
            for (i = 0; i < dilithiumN / 2; ++i)
            {
                t[0] = engine.getDilithiumGamma1() - this.getCoeffIndex(2 * i + 0);
                t[1] = engine.getDilithiumGamma1() - this.getCoeffIndex(2 * i + 1);

                outBytes[5 * i + 0] = (byte)t[0];
                outBytes[5 * i + 1] = (byte)(t[0] >> 8);
                outBytes[5 * i + 2] = (byte)((byte)(t[0] >> 16) | (t[1] << 4));
                outBytes[5 * i + 3] = (byte)(t[1] >> 4);
                outBytes[5 * i + 4] = (byte)(t[1] >> 12);

            }
        }
        else
        {
            throw new RuntimeException("Wrong Dilithium Gamma1!");
        }
        return outBytes;
    }

    /**
     * Unpack polynomial z with coefficients
     * in [-(GAMMA1 - 1), GAMMA1].
     * @param a
     */
    void zUnpack(byte[] a)
    {
        int i;
        if (engine.getDilithiumGamma1() == (1 << 17))
        {
            for (i = 0; i < dilithiumN / 4; ++i)
            {
                this.setCoeffIndex(4 * i + 0,
                    (((int)(a[9 * i + 0] & 0xFF)
                        | (int)((a[9 * i + 1] & 0xFF) << 8))
                        | (int)((a[9 * i + 2] & 0xFF) << 16))
                        & 0x3FFFF);

                this.setCoeffIndex(4 * i + 1,
                    (((int)((a[9 * i + 2] & 0xFF) >>> 2)
                        | (int)((a[9 * i + 3] & 0xFF) << 6))
                        | (int)((a[9 * i + 4] & 0xFF) << 14))
                        & 0x3FFFF);

                this.setCoeffIndex(4 * i + 2,
                    (((int)((a[9 * i + 4] & 0xFF) >>> 4)
                        | (int)((a[9 * i + 5] & 0xFF) << 4))
                        | (int)((a[9 * i + 6] & 0xFF) << 12))
                        & 0x3FFFF);

                this.setCoeffIndex(4 * i + 3,
                    (((int)((a[9 * i + 6] & 0xFF) >>> 6)
                        | (int)((a[9 * i + 7] & 0xFF) << 2))
                        | (int)((a[9 * i + 8] & 0xFF) << 10))
                        & 0x3FFFF);

                this.setCoeffIndex(4 * i + 0, engine.getDilithiumGamma1() - this.getCoeffIndex(4 * i + 0));
                this.setCoeffIndex(4 * i + 1, engine.getDilithiumGamma1() - this.getCoeffIndex(4 * i + 1));
                this.setCoeffIndex(4 * i + 2, engine.getDilithiumGamma1() - this.getCoeffIndex(4 * i + 2));
                this.setCoeffIndex(4 * i + 3, engine.getDilithiumGamma1() - this.getCoeffIndex(4 * i + 3));
            }
        }
        else if (engine.getDilithiumGamma1() == (1 << 19))
        {
            for (i = 0; i < dilithiumN / 2; ++i)
            {
                this.setCoeffIndex(2 * i + 0,
                    (int)(((((int)(a[5 * i + 0] & 0xFF))
                        | (int)((a[5 * i + 1] & 0xFF) << 8))
                        | (int)((a[5 * i + 2] & 0xFF) << 16))
                        & 0xFFFFF)
                );

                this.setCoeffIndex(2 * i + 1,
                    (int)(((((int)((a[5 * i + 2] & 0xFF) >>> 4))
                        | (int)((a[5 * i + 3] & 0xFF) << 4))
                        | (int)((a[5 * i + 4] & 0xFF) << 12))
                        & 0xFFFFF)
                );

                this.setCoeffIndex(2 * i + 0, engine.getDilithiumGamma1() - this.getCoeffIndex(2 * i + 0));
                this.setCoeffIndex(2 * i + 1, engine.getDilithiumGamma1() - this.getCoeffIndex(2 * i + 1));
            }
        }
        else
        {
            throw new RuntimeException("Wrong Dilithium Gamma1!");
        }
    }

    /**
     * Multiply polynomial by 2^D without modular reduction. Assume
     * input coefficients to be less than 2^{31-D} in absolute value.
     */
    public void shiftLeft()
    {
        for (int i = 0; i < dilithiumN; ++i)
        {
            this.setCoeffIndex(i, this.getCoeffIndex(i) << DilithiumEngine.DilithiumD);
        }
    }

    @Override
    public String toString()
    {
        return Arrays.toString(coeffs);
    }
}
