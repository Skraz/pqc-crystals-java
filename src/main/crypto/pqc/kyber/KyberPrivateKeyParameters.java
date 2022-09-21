package crypto.pqc.kyber;

import org.bouncycastle.util.Arrays;

public class KyberPrivateKeyParameters
    extends KyberKeyParameters
{
    private byte[] privateKey;

    public byte[] getPrivateKey()
    {
        return Arrays.clone(privateKey);
    }

    public KyberPrivateKeyParameters(KyberParameters params, byte[] privateKey)
    {
        super(true, params);
        this.privateKey = Arrays.clone(privateKey);
    }

    public byte[] getEncoded()
    {
        return Arrays.clone(privateKey);
    }

}
