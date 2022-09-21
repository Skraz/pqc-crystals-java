package crypto.pqc.kyber;

import org.bouncycastle.crypto.EncapsulatedSecretExtractor;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

public class KyberKEMExtractor
    implements EncapsulatedSecretExtractor
{
    private KyberEngine engine;

    private KyberPrivateKeyParameters key;

    public KyberKEMExtractor(KyberPrivateKeyParameters privParams)
    {
        this.key = privParams;
        initCipher(privParams);
    }

    private void initCipher(AsymmetricKeyParameter recipientKey)
    {
        KyberPrivateKeyParameters key = (KyberPrivateKeyParameters)recipientKey;
        engine = key.getParameters().getEngine();
    }

    @Override
    public byte[] extractSecret(byte[] encapsulation)
    {
        // Decryption
        byte[] sharedSecret = engine.kemDecrypt(encapsulation, ((KyberPrivateKeyParameters)key).getPrivateKey());
        return sharedSecret;
    }

    public int getInputSize()
    {
        return engine.getCryptoCipherTextBytes();
    }
}
