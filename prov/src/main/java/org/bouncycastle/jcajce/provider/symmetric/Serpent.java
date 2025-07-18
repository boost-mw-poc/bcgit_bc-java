package org.bouncycastle.jcajce.provider.symmetric;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherKeyGenerator;
import org.bouncycastle.crypto.engines.SerpentEngine;
import org.bouncycastle.crypto.engines.TnepresEngine;
import org.bouncycastle.crypto.generators.Poly1305KeyGenerator;
import org.bouncycastle.crypto.macs.GMac;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.modes.CFBBlockCipher;
import org.bouncycastle.crypto.modes.GCMBlockCipher;
import org.bouncycastle.crypto.modes.OFBBlockCipher;
import org.bouncycastle.internal.asn1.gnu.GNUObjectIdentifiers;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.symmetric.util.BaseBlockCipher;
import org.bouncycastle.jcajce.provider.symmetric.util.BaseKeyGenerator;
import org.bouncycastle.jcajce.provider.symmetric.util.BaseMac;
import org.bouncycastle.jcajce.provider.symmetric.util.BlockCipherProvider;
import org.bouncycastle.jcajce.provider.symmetric.util.IvAlgorithmParameters;

public final class Serpent
{
    private Serpent()
    {
    }
    
    public static class ECB
        extends BaseBlockCipher
    {
        public ECB()
        {
            super(new BlockCipherProvider()
            {
                public BlockCipher get()
                {
                    return new SerpentEngine();
                }
            });
        }
    }

    public static class ECB128
        extends BaseBlockCipher
    {
        public ECB128()
        {
            super(128, new BlockCipherProvider()
            {
                public BlockCipher get()
                {
                    return new SerpentEngine();
                }
            });
        }
    }

    public static class ECB192
        extends BaseBlockCipher
    {
        public ECB192()
        {
            super(192, new BlockCipherProvider()
            {
                public BlockCipher get()
                {
                    return new SerpentEngine();
                }
            });
        }
    }

    public static class ECB256
        extends BaseBlockCipher
    {
        public ECB256()
        {
            super(256, new BlockCipherProvider()
            {
                public BlockCipher get()
                {
                    return new SerpentEngine();
                }
            });
        }
    }

    public static class TECB
        extends BaseBlockCipher
    {
        public TECB()
        {
            super(new BlockCipherProvider()
            {
                public BlockCipher get()
                {
                    return new TnepresEngine();
                }
            });
        }
    }

    public static class CBC
        extends BaseBlockCipher
    {
        public CBC()
        {
            super(new CBCBlockCipher(new SerpentEngine()), 128);
        }
    }

    public static class CBC128
        extends BaseBlockCipher
    {
        public CBC128()
        {
            super(128, new CBCBlockCipher(new SerpentEngine()), 128);
        }
    }

    public static class CBC192
        extends BaseBlockCipher
    {
        public CBC192()
        {
            super(192, new CBCBlockCipher(new SerpentEngine()), 128);
        }
    }

    public static class CBC256
        extends BaseBlockCipher
    {
        public CBC256()
        {
            super(256, new CBCBlockCipher(new SerpentEngine()), 128);
        }
    }

    public static class CFB
        extends BaseBlockCipher
    {
        public CFB()
        {
            super(new BufferedBlockCipher(new CFBBlockCipher(new SerpentEngine(), 128)), 128);
        }
    }

    public static class CFB128
        extends BaseBlockCipher
    {
        public CFB128()
        {
            super(128, new BufferedBlockCipher(new CFBBlockCipher(new SerpentEngine(), 128)), 128);
        }
    }

    public static class CFB192
        extends BaseBlockCipher
    {
        public CFB192()
        {
            super(192, new BufferedBlockCipher(new CFBBlockCipher(new SerpentEngine(), 128)), 128);
        }
    }

    public static class CFB256
        extends BaseBlockCipher
    {
        public CFB256()
        {
            super(256, new BufferedBlockCipher(new CFBBlockCipher(new SerpentEngine(), 128)), 128);
        }
    }

    public static class OFB
        extends BaseBlockCipher
    {
        public OFB()
        {
            super(new BufferedBlockCipher(new OFBBlockCipher(new SerpentEngine(), 128)), 128);
        }
    }

    public static class OFB128
        extends BaseBlockCipher
    {
        public OFB128()
        {
            super(128, new BufferedBlockCipher(new OFBBlockCipher(new SerpentEngine(), 128)), 128);
        }
    }

    public static class OFB192
        extends BaseBlockCipher
    {
        public OFB192()
        {
            super(192, new BufferedBlockCipher(new OFBBlockCipher(new SerpentEngine(), 128)), 128);
        }
    }

    public static class OFB256
        extends BaseBlockCipher
    {
        public OFB256()
        {
            super(256, new BufferedBlockCipher(new OFBBlockCipher(new SerpentEngine(), 128)), 128);
        }
    }

    public static class KeyGen
        extends BaseKeyGenerator
    {
        public KeyGen()
        {
            super("Serpent", 192, new CipherKeyGenerator());
        }
    }

    public static class TKeyGen
        extends BaseKeyGenerator
    {
        public TKeyGen()
        {
            super("Tnepres", 192, new CipherKeyGenerator());
        }
    }

    public static class SerpentGMAC
        extends BaseMac
    {
        public SerpentGMAC()
        {
            super(new GMac(GCMBlockCipher.newInstance(new SerpentEngine())));
        }
    }

    public static class TSerpentGMAC
        extends BaseMac
    {
        public TSerpentGMAC()
        {
            super(new GMac(GCMBlockCipher.newInstance(new TnepresEngine())));
        }
    }

    public static class Poly1305
        extends BaseMac
    {
        public Poly1305()
        {
            super(new org.bouncycastle.crypto.macs.Poly1305(new SerpentEngine()));
        }
    }

    public static class Poly1305KeyGen
        extends BaseKeyGenerator
    {
        public Poly1305KeyGen()
        {
            super("Poly1305-Serpent", 256, new Poly1305KeyGenerator());
        }
    }

    public static class AlgParams
        extends IvAlgorithmParameters
    {
        protected String engineToString()
        {
            return "Serpent IV";
        }
    }

    public static class TAlgParams
        extends IvAlgorithmParameters
    {
        protected String engineToString()
        {
            return "Tnepres IV";
        }
    }

    public static class Mappings
        extends SymmetricAlgorithmProvider
    {
        private static final String PREFIX = Serpent.class.getName();

        public Mappings()
        {
        }

        public void configure(ConfigurableProvider provider)
        {

            provider.addAlgorithm("Cipher.Serpent", PREFIX + "$ECB");
            provider.addAlgorithm("KeyGenerator.Serpent", PREFIX + "$KeyGen");
            provider.addAlgorithm("AlgorithmParameters.Serpent", PREFIX + "$AlgParams");

            provider.addAlgorithm("Cipher.Tnepres", PREFIX + "$TECB");
            provider.addAlgorithm("KeyGenerator.Tnepres", PREFIX + "$TKeyGen");
            provider.addAlgorithm("AlgorithmParameters.Tnepres", PREFIX + "$TAlgParams");

            provider.addAlgorithm("Cipher", GNUObjectIdentifiers.Serpent_128_ECB, PREFIX + "$ECB128");
            provider.addAlgorithm("Cipher", GNUObjectIdentifiers.Serpent_192_ECB, PREFIX + "$ECB192");
            provider.addAlgorithm("Cipher", GNUObjectIdentifiers.Serpent_256_ECB, PREFIX + "$ECB256");

            provider.addAlgorithm("Cipher", GNUObjectIdentifiers.Serpent_128_CBC, PREFIX + "$CBC128");
            provider.addAlgorithm("Cipher", GNUObjectIdentifiers.Serpent_192_CBC, PREFIX + "$CBC192");
            provider.addAlgorithm("Cipher", GNUObjectIdentifiers.Serpent_256_CBC, PREFIX + "$CBC256");

            provider.addAlgorithm("Cipher", GNUObjectIdentifiers.Serpent_128_CFB, PREFIX + "$CFB128");
            provider.addAlgorithm("Cipher", GNUObjectIdentifiers.Serpent_192_CFB, PREFIX + "$CFB192");
            provider.addAlgorithm("Cipher", GNUObjectIdentifiers.Serpent_256_CFB, PREFIX + "$CFB256");

            provider.addAlgorithm("Cipher", GNUObjectIdentifiers.Serpent_128_OFB, PREFIX + "$OFB128");
            provider.addAlgorithm("Cipher", GNUObjectIdentifiers.Serpent_192_OFB, PREFIX + "$OFB192");
            provider.addAlgorithm("Cipher", GNUObjectIdentifiers.Serpent_256_OFB, PREFIX + "$OFB256");

            addGMacAlgorithm(provider, "SERPENT", PREFIX + "$SerpentGMAC", PREFIX + "$KeyGen");
            addGMacAlgorithm(provider, "TNEPRES", PREFIX + "$TSerpentGMAC", PREFIX + "$TKeyGen");
            addPoly1305Algorithm(provider, "SERPENT", PREFIX + "$Poly1305", PREFIX + "$Poly1305KeyGen");
        }
    }
}
