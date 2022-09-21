package crypto.pqc.dilithium;

import java.security.SecureRandom;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.pqc.crypto.MessageSigner;

public class DilithiumSigner
    implements MessageSigner
{
    private DilithiumPrivateKeyParameters privKey;
    private DilithiumPublicKeyParameters pubKey;

    private SecureRandom random;

    public DilithiumSigner()
    {
    }

    public void init(boolean forSigning, CipherParameters param)
    {
        if (forSigning)
        {
            if (param instanceof ParametersWithRandom)
            {
                privKey = (DilithiumPrivateKeyParameters)((ParametersWithRandom)param).getParameters();
                random = ((ParametersWithRandom)param).getRandom();
            }
            else
            {
                privKey = (DilithiumPrivateKeyParameters)param;
                random = CryptoServicesRegistrar.getSecureRandom();
            }
        }
        else
        {
            pubKey = (DilithiumPublicKeyParameters)param;
        }
    }

    public byte[] generateSignature(byte[] message)
    {
        DilithiumEngine engine = privKey.getParameters().getEngine(random);

        return engine.sign(message, message.length, privKey.rho, privKey.k, privKey.tr, privKey.getPrivateKey());
    }

    public boolean verifySignature(byte[] message, byte[] signature)
    {
        DilithiumEngine engine = pubKey.getParameters().getEngine(random);

        return engine.signOpen(message, signature, signature.length, pubKey.getPublicKey());
    }
}
