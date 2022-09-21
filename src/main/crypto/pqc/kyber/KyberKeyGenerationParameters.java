package crypto.pqc.kyber;

import java.security.SecureRandom;

import org.bouncycastle.crypto.KeyGenerationParameters;

public class KyberKeyGenerationParameters
    extends KeyGenerationParameters
{
    private KyberParameters params;

    public KyberKeyGenerationParameters(
        SecureRandom random,
        KyberParameters kyberParameters)
    {
        super(random, 256);
        this.params = kyberParameters;
    }

    public KyberParameters getParameters()
    {
        return params;
    }
}
