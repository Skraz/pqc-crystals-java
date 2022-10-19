package crypto.pqc.test;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.HashMap;
import junit.framework.TestCase;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

import crypto.pqc.kyber.*;

import static org.junit.Assert.assertTrue;

public class CrystalsMain {
    public static void main(String[] args) throws Exception {
        runTests();
    }

    public static void runTests() throws Exception {
        KyberParameters[] params = new KyberParameters[]{
            KyberParameters.kyber512,
            KyberParameters.kyber768,
            KyberParameters.kyber1024,
        };
        String[] files = new String[]{
            "kyber512.rsp",
            "kyber768.rsp",
            "kyber1024.rsp",
        };

        for (int fileIndex = 0; fileIndex != files.length; fileIndex++)
        {
            String name = files[fileIndex];
            System.out.println("testing: " + name);
            InputStream src = CrystalsKyberTest.class.getResourceAsStream("/resources/crypto/pqc/test/kyber/" + name);
            BufferedReader bin = new BufferedReader(new InputStreamReader(src));

            String line = null;
            HashMap<String, String> buf = new HashMap<String, String>();
            while ((line = bin.readLine()) != null)
            {
                line = line.trim();

                if (line.startsWith("#"))
                {
                    continue;
                }
                if (line.length() == 0)
                {
                    if (buf.size() > 0)
                    {
                        String count = buf.get("count");
                        System.out.println("test case: " + count);

                        byte[] seed = Hex.decode(buf.get("seed")); // seed for Kyber secure random
                        byte[] pk = Hex.decode(buf.get("pk"));     // public key
                        byte[] sk = Hex.decode(buf.get("sk"));     // private key
                        byte[] ct = Hex.decode(buf.get("ct"));     // ciphertext
                        byte[] ss = Hex.decode(buf.get("ss"));     // session key

                        NISTSecureRandom random = new NISTSecureRandom(seed, null);
                        KyberParameters parameters = params[fileIndex];

                        KyberKeyPairGenerator kpGen = new KyberKeyPairGenerator();
                        KyberKeyGenerationParameters genParam = new KyberKeyGenerationParameters(random, parameters);
                        //
                        // Generate keys and test.
                        //
                        kpGen.init(genParam);
                        AsymmetricCipherKeyPair kp = kpGen.generateKeyPair();

                        KyberPublicKeyParameters pubParams = (KyberPublicKeyParameters)(KyberPublicKeyParameters)kp.getPublic();
                        KyberPrivateKeyParameters privParams = (KyberPrivateKeyParameters)(KyberPrivateKeyParameters)kp.getPrivate();

                        assertTrue(name + " " + count + ": public key", Arrays.areEqual(pk, pubParams.getPublicKey()));
                        assertTrue(name + " " + count + ": secret key", Arrays.areEqual(sk, privParams.getPrivateKey()));
                        
                        // assertFalse(name + " " + count + ": secret key", Arrays.areEqual(sk, privParams.getPrivateKey()));
                        // Helper.printByteArray(privParams.getPrivateKey());

                        // KEM Enc
                        KyberKEMGenerator KyberEncCipher = new KyberKEMGenerator(random);
                        SecretWithEncapsulation secWenc = KyberEncCipher.generateEncapsulated(pubParams);
                        byte[] generated_cipher_text = secWenc.getEncapsulation();
                        assertTrue(name + " " + count + ": kem_enc cipher text", Arrays.areEqual(ct, generated_cipher_text));
                        byte[] secret = secWenc.getSecret();
                        assertTrue(name + " " + count + ": kem_enc key", Arrays.areEqual(ss, secret));

                        // KEM Dec
                        KyberKEMExtractor KyberDecCipher = new KyberKEMExtractor(privParams);

                        byte[] dec_key = KyberDecCipher.extractSecret(generated_cipher_text);

                        assertTrue(name + " " + count + ": kem_dec ss", Arrays.areEqual(dec_key, ss));
                        assertTrue(name + " " + count + ": kem_dec key", Arrays.areEqual(dec_key, secret));


                        // } 
                        // catch (AssertionError e) {
                        //     System.out.println("Failed assertion error.");
                        //     System.out.println();

                        //     System.out.println();
                        //     continue;
                        // }
                    }
                    buf.clear();

                    continue;
                }

                int a = line.indexOf("=");
                if (a > -1)
                {
                    buf.put(line.substring(0, a).trim(), line.substring(a + 1).trim());
                }
            }
            System.out.println("testing successful!");
        }
    }
}
