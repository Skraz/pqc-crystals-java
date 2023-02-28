package crypto.pqc.kyber;

import org.bouncycastle.util.Arrays;

public class KyberPublicKeyParameters
    extends KyberKeyParameters
{

    private byte[] publicKey;

    public byte[] getPublicKey()
    {
        return Arrays.clone(publicKey);
    }

    public byte[] getEncoded()
    {
        return getPublicKey();
    }

    public KyberPublicKeyParameters(KyberParameters params, byte[] publicKey)
    {
        super(false, params);
        this.publicKey = Arrays.clone(publicKey);
    }
}
