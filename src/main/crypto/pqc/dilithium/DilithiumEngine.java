package crypto.pqc.dilithium;

import java.security.SecureRandom;
import java.util.Arrays;

import org.bouncycastle.crypto.digests.SHAKEDigest;

import crypto.pqc.kyber.Helper;

class DilithiumEngine
{

    private final SecureRandom random;
    private final SHAKEDigest shake128Digest = new SHAKEDigest(128);
    private final SHAKEDigest shake256Digest = new SHAKEDigest(256);

    public final static int DilithiumN = 256;
    public final static int DilithiumQ = 8380417;
    public final static int DilithiumQinv = 58728449; // q^(-1) mod 2^32
    public final static int DilithiumD = 13;
    public final static int DilithiumRootOfUnity = 1753;
    public final static int SeedBytes = 32;
    public final static int CrhBytes = 64;
    public final boolean RandomizedSigning = false;

    public final static int DilithiumPolyT1PackedBytes = 320;
    public final static int DilithiumPolyT0PackedBytes = 416;

    private final int DilithiumPolyVecHPackedBytes;

    private final int DilithiumPolyZPackedBytes;
    private final int DilithiumPolyW1PackedBytes;
    private final int DilithiumPolyEtaPackedBytes;

    private final int DilithiumMode;

    private final int DilithiumK;
    private final int DilithiumL;
    private final int DilithiumEta;
    private final int DilithiumTau;
    private final int DilithiumBeta;
    private final int DilithiumGamma1;
    private final int DilithiumGamma2;
    private final int DilithiumOmega;

    private final int CryptoPublicKeyBytes;
    private final int CryptoSecretKeyBytes;
    private final int CryptoBytes;

    private final int PolyUniformGamma1NBlocks;
    
    public int getDilithiumPolyVecHPackedBytes()
    {
        return DilithiumPolyVecHPackedBytes;
    }

    public int getDilithiumPolyZPackedBytes()
    {
        return DilithiumPolyZPackedBytes;
    }

    public int getDilithiumPolyW1PackedBytes()
    {
        return DilithiumPolyW1PackedBytes;
    }

    public int getDilithiumPolyEtaPackedBytes()
    {
        return DilithiumPolyEtaPackedBytes;
    }

    public int getDilithiumMode()
    {
        return DilithiumMode;
    }

    public int getDilithiumK()
    {
        return DilithiumK;
    }

    public int getDilithiumL()
    {
        return DilithiumL;
    }

    public int getDilithiumEta()
    {
        return DilithiumEta;
    }

    public int getDilithiumTau()
    {
        return DilithiumTau;
    }

    public int getDilithiumBeta()
    {
        return DilithiumBeta;
    }

    public int getDilithiumGamma1()
    {
        return DilithiumGamma1;
    }

    public int getDilithiumGamma2()
    {
        return DilithiumGamma2;
    }

    public int getDilithiumOmega()
    {
        return DilithiumOmega;
    }

    public int getCryptoPublicKeyBytes()
    {
        return CryptoPublicKeyBytes;
    }

    public int getCryptoSecretKeyBytes()
    {
        return CryptoSecretKeyBytes;
    }

    public int getCryptoBytes()
    {
        return CryptoBytes;
    }

    public int getPolyUniformGamma1NBlocks()
    {
        return this.PolyUniformGamma1NBlocks;
    }

    public SHAKEDigest getShake256Digest()
    {
        return this.shake256Digest;
    }

    public SHAKEDigest getShake128Digest()
    {
        return this.shake128Digest;
    }

    public DilithiumEngine(int mode, SecureRandom random)
    {
        /*
         * Dilithium Modes
         * Mode = 2
         * 
         * Mode = 3
         * 
         * Mode = 4
         * 
         */
        this.DilithiumMode = mode;
        switch (mode)
        {
        case 2:
            this.DilithiumK = 4;
            this.DilithiumL = 4;
            this.DilithiumEta = 2;
            this.DilithiumTau = 39;
            this.DilithiumBeta = 78;
            this.DilithiumGamma1 = (1 << 17);
            this.DilithiumGamma2 = ((DilithiumQ - 1) / 88);
            this.DilithiumOmega = 80;
            this.DilithiumPolyZPackedBytes = 576;
            this.DilithiumPolyW1PackedBytes = 192;
            this.DilithiumPolyEtaPackedBytes = 96;
            break;
        case 3:
            this.DilithiumK = 6;
            this.DilithiumL = 5;
            this.DilithiumEta = 4;
            this.DilithiumTau = 49;
            this.DilithiumBeta = 196;
            this.DilithiumGamma1 = (1 << 19);
            this.DilithiumGamma2 = ((DilithiumQ - 1) / 32);
            this.DilithiumOmega = 55;
            this.DilithiumPolyZPackedBytes = 640;
            this.DilithiumPolyW1PackedBytes = 128;
            this.DilithiumPolyEtaPackedBytes = 128;
            break;
        case 5:
            this.DilithiumK = 8;
            this.DilithiumL = 7;
            this.DilithiumEta = 2;
            this.DilithiumTau = 60;
            this.DilithiumBeta = 120;
            this.DilithiumGamma1 = (1 << 19);
            this.DilithiumGamma2 = ((DilithiumQ - 1) / 32);
            this.DilithiumOmega = 75;
            this.DilithiumPolyZPackedBytes = 640;
            this.DilithiumPolyW1PackedBytes = 128;
            this.DilithiumPolyEtaPackedBytes = 96;
            break;
        default:
            throw new IllegalArgumentException("The mode " + mode + "is not supported by Crystals Dilithium!");
        }

        this.random = random;
        this.DilithiumPolyVecHPackedBytes = this.DilithiumOmega + this.DilithiumK;
        this.CryptoPublicKeyBytes = SeedBytes + this.DilithiumK * DilithiumPolyT1PackedBytes;
        this.CryptoSecretKeyBytes =
            (
                3 * SeedBytes
                    + DilithiumL * this.DilithiumPolyEtaPackedBytes
                    + DilithiumK * this.DilithiumPolyEtaPackedBytes
                    + DilithiumK * DilithiumPolyT0PackedBytes
            );
        this.CryptoBytes = SeedBytes + DilithiumL * this.DilithiumPolyZPackedBytes + this.DilithiumPolyVecHPackedBytes;

        if (this.DilithiumGamma1 == (1 << 17))
        {
            this.PolyUniformGamma1NBlocks = ((576 + Symmetric.Shake256Rate - 1) / Symmetric.Shake256Rate);
        }
        else if (this.DilithiumGamma1 == (1 << 19))
        {
            this.PolyUniformGamma1NBlocks = ((640 + Symmetric.Shake256Rate - 1) / Symmetric.Shake256Rate);
        }
        else
        {
            throw new RuntimeException("Wrong Dilithium Gamma1!");
        }
    }

    /**
     * Generates public and private key.
     * @return byte[][]: [Public Key Byte Array, Private Key Byte Array]
     */
    public byte[][] generateKeyPair()
    {
        byte[] seedBuf = new byte[SeedBytes];
        byte[] buf = new byte[2 * SeedBytes + CrhBytes];
        byte[] tr = new byte[SeedBytes];

        byte[] rho = new byte[SeedBytes],
            rhoPrime = new byte[CrhBytes],
            key = new byte[SeedBytes];

        PolyVecMatrix aMatrix = new PolyVecMatrix(this);

        PolyVecL s1 = new PolyVecL(this), s1hat;
        PolyVecK s2 = new PolyVecK(this), t1 = new PolyVecK(this), t0 = new PolyVecK(this);

        random.nextBytes(seedBuf);

        System.out.print("Seedbuf = ");
        Helper.printByteArray(seedBuf);

        shake256Digest.update(seedBuf, 0, SeedBytes);

        shake256Digest.doFinal(buf, 0, 2 * SeedBytes + CrhBytes);
        // System.out.print("buf = ");
        // Helper.printByteArray(buf);

        System.arraycopy(buf, 0, rho, 0, SeedBytes);
        System.arraycopy(buf, SeedBytes, rhoPrime, 0, CrhBytes);
        System.arraycopy(buf, SeedBytes + CrhBytes, key, 0, SeedBytes);
        // System.out.println("key = ");
        // Helper.printByteArray(key);

        aMatrix.expandMatrix(rho);
        // System.out.print(aMatrix.toString("aMatrix"));

        // System.out.println("rhoPrime = ");
        // Helper.printByteArray(rhoPrime);
        s1.uniformEta(rhoPrime, (short)0);
        // System.out.println(s1.toString("s1"));

        s2.uniformEta(rhoPrime, (short)DilithiumL);

        s1hat = new PolyVecL(this);

        s1.copyPolyVecL(s1hat);
        s1hat.polyVecNtt();

        // System.out.println(s1hat.toString("s1hat"));

        aMatrix.pointwiseMontgomery(t1, s1hat);
        // System.out.println(t1.toString("t1"));

        t1.reduce();
        t1.invNttToMont();

        t1.addPolyVecK(s2);
        // System.out.println(s2.toString("s2"));
        // System.out.println(t1.toString("t1"));
        t1.conditionalAddQ();
        t1.power2Round(t0);

        // System.out.println(t1.toString("t1"));
        // System.out.println("rho = ");
        Helper.printByteArray(rho);
        // System.out.println(t0.toString("t0"));


        byte[] pk = Packing.packPublicKey(rho, t1, this);
        // System.out.println("pk engine = ");
        // Helper.printByteArray(pk);

        shake256Digest.update(pk, 0, CryptoPublicKeyBytes);
        shake256Digest.doFinal(tr, 0, SeedBytes);

        byte[][] sk = Packing.packSecretKey(rho, tr, key, t0, s1, s2, this);
        // System.out.println("sk engine = ");
        // Helper.printByteArray(sk);

        return new byte[][]{pk, sk[0], sk[1], sk[2], sk[3], sk[4], sk[5]};
    }

    /**
     * Computes Signature
     * @param msg byte[]: Message to be signed
     * @param msglen int: Length of Message
     * @param rho byte[]: Unpacked Rho
     * @param key byte[]: Unpacked key
     * @param tr byte[]: Unpakced tr
     * @param secretKey byte[]: Unpacked Secret Key
     * @return byte[]: Signature of length Crypto Bytes
     */
    public byte[] signSignature(byte[] msg, int msglen, byte[] rho, byte[] key, byte[] tr, byte[] secretKey)
    {
        int n;
        byte[] outSig = new byte[CryptoBytes + msglen];
        byte[] mu = new byte[CrhBytes], rhoPrime = new byte[CrhBytes];
        short nonce = 0;
        PolyVecL s1 = new PolyVecL(this), y = new PolyVecL(this), z = new PolyVecL(this);
        PolyVecK t0 = new PolyVecK(this), s2 = new PolyVecK(this), w1 = new PolyVecK(this), w0 = new PolyVecK(this), h = new PolyVecK(this);
        Poly cp = new Poly(this);
        PolyVecMatrix aMatrix = new PolyVecMatrix(this);
        boolean rej = true;

        Packing.unpackSecretKey(t0, s1, s2, secretKey, this);

        // System.out.print("rho = ");
        // Helper.printByteArray(rho);

        // System.out.print("tr = ");
        // Helper.printByteArray(tr);

        // System.out.print("key = ");
        // Helper.printByteArray(key);

        this.shake256Digest.update(tr, 0, SeedBytes);
        this.shake256Digest.update(msg, 0, msglen);
        this.shake256Digest.doFinal(mu, 0, CrhBytes);

        if (RandomizedSigning)
        {
            random.nextBytes(rhoPrime);
        }
        else
        {
            byte[] keyMu = Arrays.copyOf(key, SeedBytes + CrhBytes);
            System.arraycopy(mu, 0, keyMu, SeedBytes, CrhBytes);
            shake256Digest.update(keyMu, 0, SeedBytes + CrhBytes);
            shake256Digest.doFinal(rhoPrime, 0, CrhBytes);
        }

        // System.out.print("mu = ");
        // Helper.printByteArray(mu);

        // System.out.print("rhoPrime = ");
        // Helper.printByteArray(rhoPrime);

        aMatrix.expandMatrix(rho);
        // System.out.print(aMatrix.toString("aMatrix"));

        s1.polyVecNtt();
        // System.out.println(s1.toString("s1"));

        s2.polyVecNtt();
        // System.out.println(s2.toString("s2"));

        t0.polyVecNtt();
        // System.out.println(t0.toString("t0"));
        int count = 0;
        while (rej == true && count < 1000)
        {
            count++;
            // Sample intermediate vector
            y.uniformGamma1(rhoPrime, nonce++);
            // System.out.println(y.toString("y"));

            y.copyPolyVecL(z);
            z.polyVecNtt();

            // Matrix-vector multiplication
            aMatrix.pointwiseMontgomery(w1, z);
            // System.out.println(w1.toString("w1"));

            w1.reduce();
            w1.invNttToMont();

            // Decompose w and call the random oracle
            w1.conditionalAddQ();
            w1.decompose(w0);
            // System.out.println(w1.toString("w1"));
            // System.out.println(w0.toString("w0"));

            System.arraycopy(w1.packW1(), 0, outSig, 0, DilithiumK * DilithiumPolyW1PackedBytes);
            // System.out.print("outsig = ");
            // Helper.printByteArray(outSig);


            shake256Digest.update(mu, 0, CrhBytes);
            shake256Digest.update(outSig, 0, DilithiumK * DilithiumPolyW1PackedBytes);
            shake256Digest.doFinal(outSig, 0, SeedBytes);
            // System.out.print("outsig = ");
            // Helper.printByteArray(outSig);

            cp.challenge(Arrays.copyOfRange(outSig, 0, SeedBytes));
            // System.out.println("cp = ");
            // System.out.println(cp.toString());
            cp.polyNtt();
            // System.out.println("cp = ");
            // System.out.println(cp.toString());

            // Compute z, reject if it reveals secret
            z.pointwisePolyMontgomery(cp, s1);
            z.invNttToMont();
            z.addPolyVecL(y);
            z.reduce();
            if (z.checkNorm(DilithiumGamma1 - DilithiumBeta))
            {
                continue;
            }

            h.pointwisePolyMontgomery(cp, s2);
            h.invNttToMont();
            // System.out.println(h.toString("h"));
            w0.subtract(h);
            w0.reduce();
            if (w0.checkNorm(DilithiumGamma2 - DilithiumBeta))
            {
                continue;
            }

            h.pointwisePolyMontgomery(cp, t0);
            h.invNttToMont();
            h.reduce();
            if (h.checkNorm(DilithiumGamma2))
            {
                continue;
            }

            w0.addPolyVecK(h);
            
            // System.out.println(w0.toString("w0"));
            w0.conditionalAddQ();

            // System.out.println(w0.toString("w0"));
            // System.out.println(w1.toString("w1"));
            
            n = h.makeHint(w0, w1);
            if (n > DilithiumOmega)
            {
                continue;
            }

            // System.out.println(z.toString("z"));
            // System.out.println(h.toString("h"));
            // System.out.println("Signature before pack = ");
            // Helper.printByteArray(outSig);
            outSig = Packing.packSignature(outSig, z, h, this);

            rej = false;
        }
        // System.out.println("Signature = ");
        // Helper.printByteArray(outSig);

        return outSig;

    }

    /**
     * Computes Signature
     * @param msg Byte[]: Message of length Crypto Bytes
     * @param mlen
     * @param rho
     * @param key
     * @param tr
     * @param secretKey
     * @return
     */
    public byte[] sign(byte[] msg, int mlen, byte[] rho, byte[] key, byte[] tr, byte[] secretKey)
    {
        byte[] signedMessage = new byte[CryptoBytes];

        System.arraycopy(signSignature(msg, mlen, rho, key, tr, secretKey), 0, signedMessage, 0, CryptoBytes);
        return signedMessage;
    }

    /**
     * Verifies Signature
     * @param sig
     * @param siglen
     * @param msg
     * @param msglen
     * @param publicKey
     * @return True if Verified Correctly, False if not.
     */
    public boolean signVerify(byte[] sig, int siglen, byte[] msg, int msglen, byte[] publicKey)
    {
        byte[] buf,
            rho,
            mu = new byte[CrhBytes],
            c,
            c2 = new byte[SeedBytes];
        Poly cp = new Poly(this);
        PolyVecMatrix aMatrix = new PolyVecMatrix(this);
        PolyVecL z = new PolyVecL(this);
        PolyVecK t1 = new PolyVecK(this), w1 = new PolyVecK(this), h = new PolyVecK(this);

        if (siglen != CryptoBytes)
        {
            return false;
        }

        // System.out.println("publickey = ");
        // Helper.printByteArray(publicKey);

        rho = Packing.unpackPublicKey(t1, publicKey, this);

        // System.out.println(t1.toString("t1"));

        // System.out.println("rho = ");
        // Helper.printByteArray(rho);

        if (!Packing.unpackSignature(z, h, sig, this))
        {
            return false;
        }
        c = Arrays.copyOfRange(sig, 0, SeedBytes);

        // System.out.println(z.toString("z"));
        // System.out.println(h.toString("h"));

        if (z.checkNorm(getDilithiumGamma1() - getDilithiumBeta()))
        {
            return false;
        }

        // Compute crh(crh(rho, t1), msg)
        shake256Digest.update(publicKey, 0, CryptoPublicKeyBytes);
        shake256Digest.doFinal(mu, 0, SeedBytes);
        // System.out.println("mu before = ");
        // Helper.printByteArray(mu);

        shake256Digest.update(mu, 0, SeedBytes);
        shake256Digest.update(msg, 0, msglen);
        shake256Digest.doFinal(mu, 0);

        // System.out.println("mu after = ");
        // Helper.printByteArray(mu);

        // Matrix-vector multiplication; compute Az - c2^dt1
        cp.challenge(c);
        // System.out.println("cp = ");
        // System.out.println(cp.toString());

        aMatrix.expandMatrix(rho);
        // System.out.println(aMatrix.toString("aMatrix = "));


        z.polyVecNtt();
        aMatrix.pointwiseMontgomery(w1, z);

        cp.polyNtt();
        // System.out.println("cp = ");
        // System.out.println(cp.toString());

        t1.shiftLeft();
        t1.polyVecNtt();
        t1.pointwisePolyMontgomery(cp, t1);

        // System.out.println(t1.toString("t1"));

        w1.subtract(t1);
        w1.reduce();
        w1.invNttToMont();

        // System.out.println(w1.toString("w1 before caddq"));

        // Reconstruct w1
        w1.conditionalAddQ();
        // System.out.println(w1.toString("w1 before hint"));
        w1.useHint(w1, h);
        // System.out.println(w1.toString("w1"));

        buf = w1.packW1();

        // System.out.println("buf = ");
        // Helper.printByteArray(buf);

        // System.out.println("mu = ");
        // Helper.printByteArray(mu);

        SHAKEDigest shakeDigest256 = new SHAKEDigest(256);
        shakeDigest256.update(mu, 0, CrhBytes);
        shakeDigest256.update(buf, 0, DilithiumK * DilithiumPolyW1PackedBytes);
        shakeDigest256.doFinal(c2, 0, SeedBytes);

        // System.out.println("c = ");
        // Helper.printByteArray(c);

        // System.out.println("c2 = ");
        // Helper.printByteArray(c2);


        for (int i = 0; i < SeedBytes; ++i)
        {
            if (c[i] != c2[i])
            {
                return false;
            }
        }
        return true;
    }

    /**
     * Verify Signed Message
     * @param msg
     * @param signedMsg
     * @param signedMsglen
     * @param publicKey
     * @return True if verified correctly, False otherwise. 
     */
    public boolean signOpen(byte[] msg, byte[] signedMsg, int signedMsglen, byte[] publicKey)
    {
        return signVerify(signedMsg, signedMsglen, msg, msg.length, publicKey);
    }
}
