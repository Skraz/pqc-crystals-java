package crypto.pqc.kyber;

import java.security.SecureRandom;
import java.util.Arrays;

import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.digests.SHAKEDigest;


/**
 * Engine for Kyber
 */
public class KyberEngine
{
    private SecureRandom random;
    private KyberIndCpa indCpa;
    private PolyVec polyVec;
    private byte[] seed;
    private SHA3Digest sha3Digest256 = new SHA3Digest(256);
    private SHA3Digest sha3Digest512 = new SHA3Digest(512);
    private SHAKEDigest shakeDigest = new SHAKEDigest(256);


    // constant parameters
    public final static int KyberN = 256;
    public final static int KyberQ = 3329;
    public final static int KyberQinv = 62209; // q^(-1) mod 2 ^ 16

    public final static int KyberSymBytes = 32; // Number of bytes for Hashes and Seeds
    private final static int KyberSharedSecretBytes = 32; // Number of Bytes for Shared Secret

    public final static int KyberPolyBytes = 384;

    private final static int KyberEta2 = 2;

    private final static int KyberIndCpaMsgBytes = KyberSymBytes;


    // parameters for Kyber{k}
    private final int KyberK;
    private final int KyberPolyVecBytes;
    private final int KyberPolyCompressedBytes;
    private final int KyberPolyVecCompressedBytes;
    private final int KyberEta1;
    private final int KyberIndCpaPublicKeyBytes;
    private final int KyberIndCpaSecretKeyBytes;
    private final int KyberIndCpaBytes;
    private final int KyberPublicKeyBytes;
    private final int KyberSecretKeyBytes;
    private final int KyberCipherTextBytes;

    // Crypto
    private final int CryptoBytes;
    private final int CryptoSecretKeyBytes;
    private final int CryptoPublicKeyBytes;
    private final int CryptoCipherTextBytes;

    /**
     * Getter for Eta2
     * @return int: Kyber Eta 2
     */
    public static int getKyberEta2()
    {
        return KyberEta2;
    }

    public static int getKyberIndCpaMsgBytes()
    {
        return KyberIndCpaMsgBytes;
    }

    public int getCryptoCipherTextBytes()
    {
        return CryptoCipherTextBytes;
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

    public int getKyberCipherTextBytes()
    {
        return KyberCipherTextBytes;
    }

    public int getKyberSecretKeyBytes()
    {
        return KyberSecretKeyBytes;
    }

    public int getKyberIndCpaPublicKeyBytes()
    {
        return KyberIndCpaPublicKeyBytes;
    }


    public int getKyberIndCpaSecretKeyBytes()
    {
        return KyberIndCpaSecretKeyBytes;
    }

    public int getKyberIndCpaBytes()
    {
        return KyberIndCpaBytes;
    }

    public int getKyberPublicKeyBytes()
    {
        return KyberPublicKeyBytes;
    }

    public int getKyberPolyCompressedBytes()
    {
        return KyberPolyCompressedBytes;
    }

    public int getKyberK()
    {
        return KyberK;
    }

    public int getKyberPolyVecBytes()
    {
        return KyberPolyVecBytes;
    }

    public int getKyberPolyVecCompressedBytes()
    {
        return KyberPolyVecCompressedBytes;
    }

    public int getKyberEta1()
    {
        return KyberEta1;
    }

    /**
     * Kyber Engine
     * @param k: Integer Determines the security level of Kyber
     */
    public KyberEngine(int k)
    {
        /**
         * Security Levels:
         * k = 2: Kyber 512
         * k = 3: Kyber 738
         * k = 4: Kyber 1024
         */
        this.KyberK = k;
        switch (k)
        {
        case 2:
            KyberEta1 = 3;
            KyberPolyCompressedBytes = 128;
            KyberPolyVecCompressedBytes = k * 320;
            break;
        case 3:
            KyberEta1 = 2;
            KyberPolyCompressedBytes = 128;
            KyberPolyVecCompressedBytes = k * 320;
            break;
        case 4:
            KyberEta1 = 2;
            KyberPolyCompressedBytes = 160;
            KyberPolyVecCompressedBytes = k * 352;
            break;
        default:
            throw new IllegalArgumentException("K: " + k + " is not supported for Crystals Kyber");
        }

        this.KyberPolyVecBytes = k * KyberPolyBytes;
        this.KyberIndCpaPublicKeyBytes = KyberPolyVecBytes + KyberSymBytes;
        this.KyberIndCpaSecretKeyBytes = KyberPolyVecBytes;
        this.KyberIndCpaBytes = KyberPolyVecCompressedBytes + KyberPolyCompressedBytes;
        this.KyberPublicKeyBytes = KyberIndCpaPublicKeyBytes;
        this.KyberSecretKeyBytes = KyberIndCpaSecretKeyBytes + KyberIndCpaPublicKeyBytes + 2 * KyberSymBytes;
        this.KyberCipherTextBytes = KyberIndCpaBytes;

        // Define Crypto Params
        this.CryptoBytes = KyberSharedSecretBytes;
        this.CryptoSecretKeyBytes = KyberSecretKeyBytes;
        this.CryptoPublicKeyBytes = KyberPublicKeyBytes;
        this.CryptoCipherTextBytes = KyberCipherTextBytes;

        this.indCpa = new KyberIndCpa(this);


        // Testing Random
        // byte[] b = new byte[48];

        // random.nextBytes(b);

        // Helper.printByteArray(b);
    }

    /**
     * Initialise Kyber Engine with a Secure Random
     * @param random: SecureRandom Sets a Secure Random Number Generator
     */
    public void init(SecureRandom random)
    {
        this.random = random;
    }

    /**
     * Updates the seed of the RNG
     * @param seed
     */
    public void updateSeed(byte[] seed)
    {
        this.seed = seed;
        random.setSeed(seed);
    }

    /**
     * Generates Public Key, Private Key Pair for KEM
     * @return Byte[0]: Public Key for KEM
     *         Byte[1]: Private Key for KEM
     */
    public byte[][] generateKemKeyPair()
    {
        byte[][] indCpaKeyPair = indCpa.generateKeyPair();

        byte[] secretKey = new byte[KyberSecretKeyBytes];

        System.arraycopy(indCpaKeyPair[1], 0, secretKey, 0, KyberIndCpaSecretKeyBytes);
        System.arraycopy(indCpaKeyPair[0], 0, secretKey, KyberIndCpaSecretKeyBytes, KyberIndCpaPublicKeyBytes);

        byte[] hashedPublicKey = new byte[32];

        sha3Digest256.update(indCpaKeyPair[0], 0, KyberIndCpaPublicKeyBytes);
        sha3Digest256.doFinal(hashedPublicKey, 0);

        System.arraycopy(hashedPublicKey, 0, secretKey, KyberSecretKeyBytes - 2 * KyberSymBytes, KyberSymBytes);

        byte[] z = new byte[KyberSymBytes];
        random.nextBytes(z);
        System.arraycopy(z, 0, secretKey, KyberSecretKeyBytes - KyberSymBytes, KyberSymBytes);

        byte[] outputPublicKey = new byte[KyberIndCpaPublicKeyBytes];
        System.arraycopy(indCpaKeyPair[0], 0, outputPublicKey, 0, KyberIndCpaPublicKeyBytes);
        return new byte[][]{outputPublicKey, secretKey};
    }

    /**
     * Encrypts data with the Public Key
     * @param publicKeyInput: Public Key Byte Array
     * @return Encrypted Message
     */
    public byte[][] kemEncrypt(byte[] publicKeyInput)
    {
        byte[] outputCipherText;
        byte[] outputSharedSecret = new byte[CryptoBytes];

        byte[] buf = new byte[2 * KyberSymBytes];
        byte[] kr = new byte[2 * KyberSymBytes];

        byte[] randBytes = new byte[KyberSymBytes];

        random.nextBytes(randBytes);

        // SHA3-256 Random Bytes
        sha3Digest256.update(randBytes, 0, KyberSymBytes);
        sha3Digest256.doFinal(randBytes, 0);
        System.arraycopy(randBytes, 0, buf, 0, KyberSymBytes);

        // SHA3-256 Public Key
        sha3Digest256.update(publicKeyInput, 0, KyberIndCpaPublicKeyBytes);
        sha3Digest256.doFinal(buf, KyberSymBytes);

        // SHA3-512( SHA3-256(RandBytes) || SHA3-256(PublicKey) )

        sha3Digest512.update(buf, 0, 2 * KyberSymBytes);
        sha3Digest512.doFinal(kr, 0);

        // System.out.println("buffer len = " + buf.length);

        // IndCpa Encryption
        outputCipherText = indCpa.encrypt(Arrays.copyOfRange(buf, 0, KyberSymBytes), publicKeyInput, Arrays.copyOfRange(kr, 32, kr.length));

        // System.out.printf("cipher text = %d [", outputCipherText.length);
        // Helper.printByteArray(outputCipherText);
        // System.out.print("]\n");

        sha3Digest256.update(outputCipherText, 0, CryptoCipherTextBytes);
        sha3Digest256.doFinal(kr, KyberSymBytes);

        Helper.printByteArray(kr);

        shakeDigest.update(kr, 0, 2 * KyberSymBytes);
        shakeDigest.doFinal(outputSharedSecret, 0, KyberSymBytes);

        byte[][] outBuf = new byte[2][];
        outBuf[0] = outputSharedSecret;
        outBuf[1] = outputCipherText;

        return outBuf;
    }

    /**
     * Decrypt the CipherText
     * @param cipherText: Encrypted Message
     * @param secretKey: Secret Key
     * @return Decrypted Message
     */
    public byte[] kemDecrypt(byte[] cipherText, byte[] secretKey)
    {
        byte[] outputSharedSecret = new byte[KyberSharedSecretBytes];
        byte[] buf = new byte[2 * KyberSymBytes],
            kr = new byte[2 * KyberSymBytes],
            cmp = new byte[KyberCipherTextBytes];

        int i;
        byte[] publicKey = Arrays.copyOfRange(secretKey, KyberIndCpaSecretKeyBytes, secretKey.length);

        System.arraycopy(indCpa.decrypt(cipherText, secretKey), 0, buf, 0, KyberSymBytes);

        // System.out.print("ct = ");
        // Helper.printByteArray(Arrays.copyOfRange(cipherText, 0, KyberSymBytes));

        System.arraycopy(secretKey, KyberSecretKeyBytes - 2 * KyberSymBytes, buf, KyberSymBytes, KyberSymBytes);

        sha3Digest512.update(buf, 0, 2 * KyberSymBytes);
        sha3Digest512.doFinal(kr, 0);

        cmp = indCpa.encrypt(Arrays.copyOfRange(buf, 0, KyberSymBytes), publicKey, Arrays.copyOfRange(kr, KyberSymBytes, kr.length));

        boolean fail = !(Arrays.equals(cipherText, cmp));

        // System.out.println("fail = " + fail);

        sha3Digest256.update(cipherText, 0, KyberCipherTextBytes);
        sha3Digest256.doFinal(kr, KyberSymBytes);

        cmov(kr, Arrays.copyOfRange(secretKey, KyberSecretKeyBytes - KyberSymBytes, KyberSecretKeyBytes), KyberSymBytes, fail);

        shakeDigest.update(kr, 0, 2 * KyberSymBytes);
        shakeDigest.doFinal(outputSharedSecret, 0, KyberSymBytes);

        return outputSharedSecret;
    }

    /**
     * If b is True, then copy the contents of x to r, otherwise, return r.
     * @param r: Byte to return
     * @param x: Byte to check
     * @param xlen: length of byte to check
     * @param b: Boolean value to verify that it's correct
     */
    private void cmov(byte[] r, byte[] x, int xlen, boolean b)
    {
        if (b)
        {
            System.arraycopy(x, 0, r, 0, xlen);
        }
        else
        {
            System.arraycopy(r, 0, r, 0, xlen);
        }
    }

    /**
     * Generates Random Byte Array
     * @param buf: Byte array to generate random bytes into
     */
    public void getRandomBytes(byte[] buf)
    {
        this.random.nextBytes(buf);
    }

}
