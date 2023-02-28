package crypto.pqc.test;

import java.io.BufferedReader;
import java.io.Console;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import junit.framework.TestCase;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

import crypto.pqc.dilithium.*;
import crypto.pqc.kyber.*;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertFalse;

public class CrystalsMain {
    public static void main(String[] args) throws Exception {
        // checkKyber();
        checkDilithium();
    }

    public static void checkKyber() throws Exception {
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

        String[] filesOutput = new String[] {
            "kyber512-concurrency.csv",
            "kyber768-concurrency.csv",
            "kyber1024-concurrency.csv",
        };


        for (int fileIndex = 0; fileIndex != files.length; fileIndex++)
        {
            String name = files[fileIndex];
            File file = new File(filesOutput[fileIndex]);
            file.createNewFile();
            PrintWriter pw = new PrintWriter(file);

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

                        List<String> dataLines = new ArrayList<String>();

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

                        Runtime rt = Runtime.getRuntime();
                        long startTime = System.nanoTime();
                        rt.gc();
                        long start_memory = rt.totalMemory() - rt.freeMemory();

                        AsymmetricCipherKeyPair kp = kpGen.generateKeyPair();

                        long endTime = System.nanoTime();
                        rt.gc();
                        long end_memory = rt.totalMemory() - rt.freeMemory();
                        String keyPairTime = Long.toString(endTime - startTime);
                        String keyPairMemory = Long.toString(end_memory);

                        dataLines.add(count);
                        dataLines.add(keyPairTime);
                        dataLines.add(keyPairMemory);

                        KyberPublicKeyParameters pubParams = (KyberPublicKeyParameters)(KyberPublicKeyParameters)kp.getPublic();
                        KyberPrivateKeyParameters privParams = (KyberPrivateKeyParameters)(KyberPrivateKeyParameters)kp.getPrivate();

                        assertTrue(name + " " + count + ": public key", Arrays.areEqual(pk, pubParams.getPublicKey()));
                        assertTrue(name + " " + count + ": secret key", Arrays.areEqual(sk, privParams.getPrivateKey()));
                        
                        // assertFalse(name + " " + count + ": secret key", Arrays.areEqual(sk, privParams.getPrivateKey()));
                        // Helper.printByteArray(privParams.getPrivateKey());

                        // KEM Enc
                        KyberKEMGenerator KyberEncCipher = new KyberKEMGenerator(random);

                        startTime = System.nanoTime();
                        rt.gc();
                        start_memory = rt.totalMemory() - rt.freeMemory();

                        SecretWithEncapsulation secWenc = KyberEncCipher.generateEncapsulated(pubParams);

                        endTime = System.nanoTime();
                        rt.gc();
                        end_memory = rt.totalMemory() - rt.freeMemory();
                        String encryptTime = Long.toString(endTime - startTime);
                        String encryptMemory = Long.toString(end_memory);
                        
                        dataLines.add(encryptTime);
                        dataLines.add(encryptMemory);


                        byte[] generated_cipher_text = secWenc.getEncapsulation();
                        assertTrue(name + " " + count + ": kem_enc cipher text", Arrays.areEqual(ct, generated_cipher_text));
                        byte[] secret = secWenc.getSecret();
                        assertTrue(name + " " + count + ": kem_enc key", Arrays.areEqual(ss, secret));

                        // KEM Dec
                        KyberKEMExtractor KyberDecCipher = new KyberKEMExtractor(privParams);

                        // Decryption
                        startTime = System.nanoTime();
                        rt.gc();
                        start_memory = rt.totalMemory() - rt.freeMemory();

                        byte[] dec_key = KyberDecCipher.extractSecret(generated_cipher_text);

                        endTime = System.nanoTime();
                        rt.gc();
                        end_memory = rt.totalMemory() - rt.freeMemory();
                        String decryptTime = Long.toString(endTime - startTime);
                        String decryptMemory = Long.toString(end_memory);

                        dataLines.add(decryptTime);
                        dataLines.add(decryptMemory);

                        assertTrue(name + " " + count + ": kem_dec ss", Arrays.areEqual(dec_key, ss));
                        assertTrue(name + " " + count + ": kem_dec key", Arrays.areEqual(dec_key, secret));


                        // } 
                        // catch (AssertionError e) {
                        //     System.out.println("Failed assertion error.");
                        //     System.out.println();

                        //     System.out.println();
                        //     continue;
                        // }

                        System.out.println(convertToCSV(new String[]{count, keyPairTime, keyPairMemory, encryptTime, encryptMemory, decryptTime, decryptMemory}));

                        pw.write(convertToCSV(new String[]{count, keyPairTime, keyPairMemory, encryptTime, encryptMemory, decryptTime, decryptMemory}) + "\n");
                        
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
            pw.close();

            System.out.println("testing successful!");
        }
    }
    public static void checkDilithium() throws Exception {
        String[] files = new String[]{
            "PQCsignKAT_Dilithium2.rsp",
            "PQCsignKAT_Dilithium3.rsp",
            "PQCsignKAT_Dilithium5.rsp"
        };
        DilithiumParameters[] parameters = new DilithiumParameters[]{
            DilithiumParameters.dilithium2,
            DilithiumParameters.dilithium3,
            DilithiumParameters.dilithium5
        };
        String[] filesOutput = new String[] {
            "dilithium2-concurrency.csv",
            "dilithium3-concurrency.csv",
            "dilithium5-concurrency.csv",
        };


        for (int fileindex = 0; fileindex < files.length; fileindex++)
        {
            String name = files[fileindex];        
            File file = new File(filesOutput[fileindex]);
            file.createNewFile();
            PrintWriter pw = new PrintWriter(file);

            System.out.println("testing: " + name);
            InputStream src = CrystalsDilithiumTest.class.getResourceAsStream("/resources/crypto/pqc/test/dilithium/" + name);
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

                        List<String> dataLines = new ArrayList<String>();

                        byte[] seed = Hex.decode(buf.get("seed")); // seed for Dilithium secure random
                        byte[] pk = Hex.decode(buf.get("pk"));     // public key
                        byte[] sk = Hex.decode(buf.get("sk"));     // private key
                        byte[] sm = Hex.decode(buf.get("sm"));     // signed message
                        int sm_len = Integer.parseInt(buf.get("smlen"));
                        byte[] msg = Hex.decode(buf.get("msg")); // message
                        int m_len = Integer.parseInt(buf.get("mlen"));

                        NISTSecureRandom random = new NISTSecureRandom(seed, null);

                        // keygen
                        DilithiumKeyGenerationParameters kparam = new DilithiumKeyGenerationParameters(random, parameters[fileindex]);
                        DilithiumKeyPairGenerator kpg = new DilithiumKeyPairGenerator();
                        kpg.init(kparam);

                        Runtime rt = Runtime.getRuntime();
                        long startTime = System.nanoTime();
                        rt.gc();
                        long start_memory = rt.totalMemory() - rt.freeMemory();

                        AsymmetricCipherKeyPair ackp = kpg.generateKeyPair();

                        long endTime = System.nanoTime();
                        rt.gc();
                        long end_memory = rt.totalMemory() - rt.freeMemory();
                        String keyPairTime = Long.toString(endTime - startTime);
                        String keyPairMemory = Long.toString(end_memory);

                        dataLines.add(count);
                        dataLines.add(keyPairTime);
                        dataLines.add(keyPairMemory);


                        byte[] respk = ((DilithiumPublicKeyParameters)ackp.getPublic()).getEncoded();
                        // System.out.println("pk = ");
                        // Helper.printByteArray(pk);
                        byte[] ressk = ((DilithiumPrivateKeyParameters)ackp.getPrivate()).getEncoded();

                        // //keygen
                        // assertTrue(name + " " + count + " public key", Arrays.areEqual(respk, pk));
                        // assertTrue(name + " " + count + " secret key", Arrays.areEqual(ressk, sk));

                        // sign
                        DilithiumSigner signer = new DilithiumSigner();
                        DilithiumPrivateKeyParameters skparam = (DilithiumPrivateKeyParameters)ackp.getPrivate();
                        ParametersWithRandom skwrand = new ParametersWithRandom(skparam, random);
                        signer.init(true, skwrand);
                        
                        startTime = System.nanoTime();
                        rt.gc();
                        start_memory = rt.totalMemory() - rt.freeMemory();

                        byte[] sigGenerated = signer.generateSignature(msg);

                        endTime = System.nanoTime();
                        rt.gc();
                        end_memory = rt.totalMemory() - rt.freeMemory();
                        String sigGenTime = Long.toString(endTime - startTime);
                        String sigGenMemory = Long.toString(end_memory);
                        
                        dataLines.add(sigGenTime);
                        dataLines.add(sigGenMemory);

                        byte[] attachedSig = Arrays.concatenate(sigGenerated, msg);

                        // verify
                        DilithiumSigner verifier = new DilithiumSigner();
                        DilithiumPublicKeyParameters pkparam = new DilithiumPublicKeyParameters(parameters[fileindex], pk);
                        verifier.init(false, pkparam);

                        startTime = System.nanoTime();
                        rt.gc();
                        start_memory = rt.totalMemory() - rt.freeMemory();

                        boolean vrfyrespass = verifier.verifySignature(msg, sigGenerated);

                        endTime = System.nanoTime();
                        rt.gc();
                        end_memory = rt.totalMemory() - rt.freeMemory();
                        String sigVerifyTime = Long.toString(endTime - startTime);
                        String sigVerifyMemory = Long.toString(end_memory);

                        dataLines.add(sigVerifyTime);
                        dataLines.add(sigVerifyMemory);
                        sigGenerated[3]++; // changing the signature by 1 byte should cause it to fail
                        boolean vrfyresfail = verifier.verifySignature(msg, sigGenerated);

                        // print results
                            /*
                            System.out.println("--Keygen");
                            boolean kgenpass = true;
                            if (!Arrays.areEqual(respk, pk)) {
                                System.out.println("  == Keygen: pk do not match");
                                kgenpass = false;
                            }
                            if (!Arrays.areEqual(ressk, sk)) {
                                System.out.println("  == Keygen: sk do not match");
                                kgenpass = false;
                            }
                            if (kgenpass) {
                                System.out.println("  ++ Keygen pass");
                            } else {
                                System.out.println("  == Keygen failed");
                                return;
                            }

                            System.out.println("--Sign");
                            boolean spass = true;
                            if (!Arrays.areEqual(ressm, sm)) {
                                System.out.println("  == Sign: signature do not match");
                                spass = false;
                            }
                            if (spass) {
                                System.out.println("  ++ Sign pass");
                            } else {
                                System.out.println("  == Sign failed");
                                return;
                            }

                            System.out.println("--Verify");
                            if (vrfyrespass && !vrfyresfail) {
                                System.out.println("  ++ Verify pass");
                            } else {
                                System.out.println("  == Verify failed");
                                return;
                            }
                             */
                        // AssertTrue

                        //sign
                        // System.out.println("attached Sig = ");
                        // Helper.printByteArray(attachedSig);
                        // System.out.println("sm = ");
                        // Helper.printByteArray(sm);
                        assertTrue(name + " " + count + " signature", Arrays.areEqual(attachedSig, sm));
                        //verify
                        assertTrue(name + " " + count + " verify failed when should pass", vrfyrespass);
                        assertFalse(name + " " + count + " verify passed when should fail", vrfyresfail);
                        // System.out.println(convertToCSV(new String[]{count, keyPairTime, keyPairMemory, sigGenTime, sigGenMemory, sigVerifyTime, sigVerifyMemory}));

                        pw.write(convertToCSV(new String[]{count, keyPairTime, keyPairMemory, sigGenTime, sigGenMemory, sigVerifyTime, sigVerifyMemory}) + "\n");
                        

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
            pw.close();
            System.out.println("testing successful!");
        }
    }
    
    public static String convertToCSV(String[] data) {
    return Stream.of(data)
      .collect(Collectors.joining(","));
    }


}
